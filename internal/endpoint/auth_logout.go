package endpoint

import (
	"log"
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
// @Router /auth/logout [post]
// @Example response 200
//
//	{
//	  "success": "Logged out"
//	}
//
// @Example response 401
//
//	{
//	  "error": "Invalid token"
//	}
func AuthLogout(writer http.ResponseWriter, req *http.Request) {

	claims, ok := req.Context().Value("claims").(*model.Claims)

	if !ok {
		return
	}

	var err error

	err = storage.RevokeAccessToken(claims.PairID, claims.ExpiresAt.Time)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
	}

	err = storage.RevokeRefreshTokens(claims.PairID)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
	}

	server.SetResponse(writer, http.StatusOK, model.SuccessResponse{Success: "Successfully logged out"})
}
