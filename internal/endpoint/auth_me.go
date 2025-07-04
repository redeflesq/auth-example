package endpoint

import (
	"net/http"

	"github.com/redeflesq/auth-example/internal/model"
	"github.com/redeflesq/auth-example/internal/server"
)

// AuthMe godoc
// @Summary Get current user ID
// @Description Returns the user ID from valid JWT token
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} model.UserIdResponse "Successfully retrieved user ID"
// @Router /auth/me [get]
// @Example response 200
//
//	{
//	  "user_id": "123e4567-e89b-12d3-a456-426614174000"
//	}
//
// @Example response 401
//
//	{
//	  "error": "Authorization required"
//	}
func AuthMe(writer http.ResponseWriter, req *http.Request) {

	claims, ok := req.Context().Value("claims").(*model.Claims)

	if !ok {
		return
	}

	server.SetResponse(writer, http.StatusOK, model.UserIdResponse{UserID: claims.UserID})
}
