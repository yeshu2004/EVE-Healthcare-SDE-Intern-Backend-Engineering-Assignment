package main

import (
	"github/yeshu2004/eve-health/middleware"
	"github/yeshu2004/eve-health/router"
	"github/yeshu2004/eve-health/database"
	"log"
	"net/http"
)

const PORT = ":4000"

func main() {
	pgClient, err := database.ConnectPostgresSQL()
	if err != nil {
		log.Fatal(err)
	}

	mux := router.Router(pgClient)
	srv := http.Server{
		Addr:    PORT,
		Handler: middleware.SrvMiddleware(mux),
	}

	log.Printf("server running on port%v\n", PORT)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server running error: %v\n", err)
	}
}
