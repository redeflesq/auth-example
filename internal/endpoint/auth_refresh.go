package endpoint

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/redeflesq/auth-example/internal/model"
	"github.com/redeflesq/auth-example/internal/server"
	"github.com/redeflesq/auth-example/internal/storage"
	"github.com/redeflesq/auth-example/internal/token"
)

// AuthRefresh godoc
// @Summary Refresh authentication tokens
// @Description Generates new access and refresh tokens pair using valid refresh token and valid JWT from Authorization header.
// @Tags Authentication
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body model.TokenRequest true "Refresh token"
// @Success 200 {object} model.TokenResponse "New tokens pair"
// @Failure 400 {object} model.ErrorResponse "Invalid request format"
// @Failure 401 {object} model.ErrorResponse "Unauthorized - invalid or revoked tokens"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /auth/refresh [post]
// @Example request
//
//	{
//	  "refresh_token": "dGhpcyBpcyBhIHNhbXBsZSByZWZyZXNoIHRva2Vu"
//	}
//
// @Example response 200
//
//	{
//	  "access_token": "eyJhbGciOiJIUzUxMiIs...",
//	  "refresh_token": "bmV3IHJlZnJlc2ggdG9rZW4gdmFsdWU"
//	}
//
// @Example response 401
//
//	{
//	  "error": "Invalid token"
//	}
func AuthRefresh(writer http.ResponseWriter, req *http.Request) {

	var freq model.TokenRequest
	if err := json.NewDecoder(req.Body).Decode(&freq); err != nil {
		server.SetResponse(writer, http.StatusBadRequest, model.ErrorResponse{Error: "Invalid request"})
		return
	}

	// Находим токен доступа из запроса

	access_token_str := server.GetTokenString(req)
	if access_token_str == "" {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Authorization required"})
		return
	}

	// Парсим JWT без валидации времени истечения и т. д.

	access_claims := &model.Claims{}
	access_token, err := token.ParseJWTWithoutValidation(access_token_str, access_claims)
	if err != nil || !access_token.Valid {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Invalid token"})
		return
	}

	// Сверяем что токены доступа и обновления парные

	refresh_pair_id, refresh_token_data, _ := token.DecodeRefreshToken(freq.RefreshToken)
	if access_claims.PairID != refresh_pair_id {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Incorrect tokens pair"})
		return
	}

	user_id := access_claims.UserID
	pair_id := access_claims.PairID

	// Проверяем отозван ли токен доступа

	revoked, err := storage.AccessTokenIsRevoked(pair_id)
	if err != nil || revoked {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Token revoked"})
		return
	}

	// Ищем токен обновления в базе по данным из токена доступа
	// В данный момент токен доступа: парный и не отозван

	var token_hash, ip_address, user_agent string
	err = storage.DB.QueryRow(
		`SELECT token_hash, ip_address, user_agent FROM refresh_tokens 
         WHERE user_id = $1 AND pair_id = $2 AND is_revoked = false AND expires_at > NOW()`,
		user_id, pair_id,
	).Scan(&token_hash, &ip_address, &user_agent)

	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Refresh token not found"})
		return
	}

	// Верифицируем токен обновления который был получен из запроса

	refresh_token_verification := token.VerifyRefreshToken(refresh_token_data, token_hash, user_id)
	if !refresh_token_verification {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Incorrect refresh token"})
		return
	}

	// Отправляем вебхук об изменении IP (Если изменился)

	current_ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	if current_ip != ip_address {
		go server.SendWebhook(user_id, ip_address, current_ip)
	}

	// Проверяем User-Agent

	current_useragent := req.UserAgent()
	if current_useragent != user_agent {

		err = storage.RevokeAccessToken(pair_id, access_claims.ExpiresAt.Time)
		if err != nil {
			log.Printf("Failed to revoke token: %v", err)
		}

		err = storage.RevokeRefreshTokens(pair_id)
		if err != nil {
			log.Printf("Failed to revoke token: %v", err)
		}

		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "User-Agent changed"})
		return
	}

	// Генерируем новые токены

	new_tokens_pair, err := token.GenerateTokensPair(user_id)
	if err != nil {
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to generate tokens"})
		return
	}

	// Удаляем старые токены

	err = storage.RevokeAccessToken(pair_id, access_claims.ExpiresAt.Time)
	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to revoke old access token"})
		return
	}

	_, err = storage.DB.Exec("UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = $1", token_hash)
	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to revoke old refresh token"})
		return
	}

	// Сохраняем новый refresh токен

	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	err = storage.SaveRefreshToken(user_id, new_tokens_pair.PairID, new_tokens_pair.RefreshToken.Hash, current_useragent, ip)
	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to save refresh token"})
		return
	}

	// Возвращаем новые токены

	server.SetResponse(writer, http.StatusOK, model.TokenResponse{
		AccessToken:  new_tokens_pair.AccessToken,
		RefreshToken: new_tokens_pair.RefreshToken.Token,
	})
}
