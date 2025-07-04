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

// AuthToken godoc
// @Summary Generate new authentication tokens
// @Description Creates new access and refresh tokens pair for specified user ID
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.UserIdRequest true "User ID"
// @Success 200 {object} model.TokenResponse "Successfully generated tokens"
// @Failure 400 {object} model.ErrorResponse "Invalid request or empty user ID"
// @Failure 500 {object} model.ErrorResponse "Failed to generate or save tokens"
// @Router /auth/token [post]
// @Example request
//
//	{
//	  "user_id": "1337-abcd-0228"
//	}
//
// @Example response 200
//
//	{
//	  "access_token": "eyJhbGciOiJIUzUxMiIs...",
//	  "refresh_token": "dGhpcyBpcyBhIHNhbXBsZSByZWZyZXNoIHRva2Vu"
//	}
//
// @Example response 400
//
//	{
//	  "error": "Empty user id"
//	}
func AuthToken(writer http.ResponseWriter, req *http.Request) {

	var freq model.UserIdRequest
	if err := json.NewDecoder(req.Body).Decode(&freq); err != nil {
		server.SetResponse(writer, http.StatusBadRequest, model.ErrorResponse{Error: "Invalid request"})
		return
	}

	if freq.UserID == "" {
		server.SetResponse(writer, http.StatusBadRequest, model.ErrorResponse{Error: "Empty user id"})
		return
	}

	tokens_pair, err := token.GenerateTokensPair(freq.UserID)
	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to generate tokens"})
		return
	}

	ua := req.UserAgent()
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	err = storage.SaveRefreshToken(freq.UserID, tokens_pair.PairID, tokens_pair.RefreshToken.Hash, ua, ip)

	if err != nil {
		log.Println(err)
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to save refresh token"})
		return
	}

	server.SetResponse(writer, http.StatusOK, model.TokenResponse{
		AccessToken:  tokens_pair.AccessToken,
		RefreshToken: tokens_pair.RefreshToken.Token,
	})
}
