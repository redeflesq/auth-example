package main

import (
	_ "github.com/redeflesq/auth-example/docs"
	"github.com/redeflesq/auth-example/internal/app"
)

// @title Auth Example API
// @version 1.0
// @description API for auth with JWT
// @host localhost:8080
// @BasePath /
// @schemes http

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token. Example: "Bearer eyJhbGciOi..."

func main() {
	app.Run()
}
