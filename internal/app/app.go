package app

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"github.com/redeflesq/auth-example/internal/endpoint"
	"github.com/redeflesq/auth-example/internal/server"
	"github.com/redeflesq/auth-example/internal/storage"

	_ "github.com/redeflesq/auth-example/docs"
	httpSwagger "github.com/swaggo/http-swagger"
)

func Run() {

	_ = godotenv.Load(".env")

	if err := storage.Init(); err != nil {
		log.Fatal("Failed to connect to DB:", err)
	}
	
	go server.CleanRevokedTokens()

	router := mux.NewRouter()

	router.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
		httpSwagger.DocExpansion("none"),
		httpSwagger.UIConfig(map[string]string{
			"showExtensions": "true",
		}),
	))

	router.HandleFunc("/auth/token", endpoint.AuthToken).Methods("POST")
	router.HandleFunc("/auth/refresh", endpoint.AuthRefresh).Methods("POST")
	router.Handle("/auth/me", server.AuthMiddleware(http.HandlerFunc(endpoint.AuthMe))).Methods("GET")
	router.Handle("/auth/logout", server.AuthMiddleware(http.HandlerFunc(endpoint.AuthLogout))).Methods("POST")

	app_port := os.Getenv("APP_PORT")

	log.Printf("Server running on port :%s", app_port)

	log.Fatal(http.ListenAndServe(":"+app_port, router))
}
