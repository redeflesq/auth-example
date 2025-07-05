package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/redeflesq/auth-example/internal/model"
	"github.com/redeflesq/auth-example/internal/storage"
	"github.com/redeflesq/auth-example/internal/token"
)

func SetResponse(writer http.ResponseWriter, status_code int, response any) {

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status_code)

	json.NewEncoder(writer).Encode(response)
}

func GetTokenString(req *http.Request) string {

	auth_header := req.Header.Get("Authorization")

	if auth_header == "" {
		return ""
	}

	return strings.TrimPrefix(auth_header, "Bearer ")
}

func CleanRevokedTokens() {
	for {
		_, err := storage.DB.Exec("DELETE FROM revoked_tokens WHERE expires_at < NOW()")
		if err != nil {
			log.Printf("Token cleanup error: %v", err)
		}
		time.Sleep(24 * time.Hour)
	}
}

func AuthMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {

		token_str := GetTokenString(req)

		if token_str == "" {
			SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Authorization required"})
			return
		}

		claims := &model.Claims{}

		token, err := token.ParseJWT(token_str, claims)

		if err != nil || !token.Valid {
			SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Invalid token"})
			return
		}

		revoked, err := storage.AccessTokenIsRevoked(claims.PairID)

		if err != nil || revoked {
			SetResponse(writer, http.StatusUnauthorized, model.ErrorResponse{Error: "Token revoked"})
			return
		}

		ctx := context.WithValue(req.Context(), "claims", claims)

		next.ServeHTTP(writer, req.WithContext(ctx))
	})
}
