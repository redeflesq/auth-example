package endpoint

import (
	"net/http"

	"github.com/redeflesq/auth-example/internal/model"
	"github.com/redeflesq/auth-example/internal/server"
	"github.com/redeflesq/auth-example/internal/storage"
)

// AuthLogout godoc
// @Summary Logout user
// @Description Revokes current access token and all associated refresh tokens. Requires valid JWT in Authorization header.
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} model.SuccessResponse "Successfully logged out"
// @Failure 401 {object} model.ErrorResponse "Unauthorized - invalid or revoked tokens"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /auth/logout [post]
// @Example response 200
//
//	{
//	  "success": "Successfully logged out"
//	}
//
// @Example response 401
//
//	{
//	  "error": "Invalid token"
//	}
//
// @Example response 500
//
//	{
//	  "error": "Failed to revoke access token"
//	}
func AuthLogout(writer http.ResponseWriter, req *http.Request) {

	claims, ok := req.Context().Value("claims").(*model.Claims)

	if !ok {
		server.SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Authorization required"})
		return
	}

	var err error

	err = storage.RevokeAccessToken(claims.PairID, claims.ExpiresAt.Time)
	if err != nil {
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to revoke access token"})
		return
	}

	err = storage.RevokeRefreshTokens(claims.PairID)
	if err != nil {
		server.SetResponse(writer, http.StatusInternalServerError, model.ErrorResponse{Error: "Failed to revoke refresh token"})
		return
	}

	server.SetResponse(writer, http.StatusOK, model.SuccessResponse{Success: "Successfully logged out"})
}
