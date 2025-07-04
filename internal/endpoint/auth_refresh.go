package endpoint

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redeflesq/auth-example/internal/model"
	"github.com/redeflesq/auth-example/internal/server"
	"github.com/redeflesq/auth-example/internal/storage"
	"github.com/redeflesq/auth-example/internal/token"
)

// AuthRefresh godoc
// @Summary Refresh authentication tokens
// @Description Generates new access and refresh tokens pair using valid refresh token
// @Tags Authentication
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body model.TokenRequest true "Refresh token"
// @Success 200 {object} model.TokenResponse "New tokens pair"
// @Failure 400 {object} model.ErrorResponse "Invalid request format"
// @Failure 401 {object} model.ErrorResponse "Unauthorized - invalid, expired or revoked tokens"
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

	// Находим Access Token

	access_token_str := server.GetTokenString(req)
	if access_token_str == "" {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Authorization required"})
		return
	}

	access_claims := &model.Claims{}
	access_token, err := jwt.ParseWithClaims(access_token_str, access_claims, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !access_token.Valid {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Invalid token"})
		return
	}

	refresh_pair_id, refresh_token_data, _ := token.DecodeRefreshToken(freq.RefreshToken)
	if access_claims.PairID != refresh_pair_id {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Incorrect tokens pair"})
		return
	}

	// Проверяем отозван ли access token

	revoked, err := storage.AccessTokenIsRevoked(access_claims.PairID)
	if err != nil || revoked {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Token revoked"})
		return
	}

	// Ищем токен в базе

	var token_hash, ip_address, user_agent string
	err = storage.DB.QueryRow(
		`SELECT token_hash, ip_address, user_agent FROM refresh_tokens 
         WHERE user_id = $1 AND pair_id = $2 AND is_revoked = false AND expires_at > NOW()`,
		access_claims.UserID, access_claims.PairID,
	).Scan(&token_hash, &ip_address, &user_agent)

	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Refresh token not found"})
		return
	}

	// Верифицируем Refresh Token

	refresh_token_verification := token.VerifyRefreshToken(refresh_token_data, token_hash, access_claims.UserID)
	if !refresh_token_verification {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Incorrect refresh token"})
		return
	}

	user_id := access_claims.UserID

	// Отправляем вебхук об изменении IP (Если изменился)

	current_ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	if current_ip != ip_address {
		go server.SendWebhook(user_id, ip_address, current_ip)
	}

	// Проверяем User-Agent

	current_useragent := req.UserAgent()
	if current_useragent != user_agent {

		err = storage.RevokeAccessToken(access_claims.PairID, access_claims.ExpiresAt.Time)
		if err != nil {
			log.Printf("Failed to revoke token: %v", err)
		}

		err = storage.RevokeRefreshTokens(access_claims.PairID)
		if err != nil {
			log.Printf("Failed to revoke token: %v", err)
		}

		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "User-Agent changed"})
		return
	}

	// Генерируем новые токены

	tokens_pair, err := token.GenerateTokensPair(user_id)
	if err != nil {
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to generate tokens"})
		return
	}

	// Удаляем старые токены

	err = storage.RevokeAccessToken(access_claims.PairID, access_claims.ExpiresAt.Time)
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
	err = storage.SaveRefreshToken(user_id, tokens_pair.PairID, tokens_pair.RefreshToken.Hash, current_useragent, ip)
	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to save refresh token"})
		return
	}

	// Возвращаем новые токены

	server.SetResponse(writer, http.StatusOK, model.TokenResponse{
		AccessToken:  tokens_pair.AccessToken,
		RefreshToken: tokens_pair.RefreshToken.Token,
	})
}
