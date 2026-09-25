package router

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github/yeshu2004/eve-health/database"
	"github/yeshu2004/eve-health/middleware"
	m "github/yeshu2004/eve-health/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type RouterSrv struct {
	pg database.PostgresClient
}

func Router(pg *database.PostgresClient) http.Handler {
	mux := http.NewServeMux()
	srv := RouterSrv{
		pg: *pg,
	}

	mux.HandleFunc("/", defaultHandler)
	mux.HandleFunc("/login", srv.loginHandler)
	mux.HandleFunc("/register", srv.registerHandler)

	// protected route
	mux.Handle("/profile", middleware.AuthMiddleware(http.HandlerFunc(srv.profileHandler)))

	return mux
}

func (s *RouterSrv) profileHandler(w http.ResponseWriter, r *http.Request) {

}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	// do nothing
}

func (s *RouterSrv) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req m.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "name, email and password are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, err := s.pg.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}

		log.Println(err)
		writeError(w, http.StatusInternalServerError, "server error, try again")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":     user.ID,
		"expiry_time": time.Now().Add(2 * time.Hour).Unix(),
	})

	secret := os.Getenv("JWT_SECRET")
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Println(err)
		writeError(w, http.StatusBadRequest, "failed to generate token")
		return
	}
	log.Printf("[user-%d] login token: %s\n", user.ID, tokenString)

	writeResponse(w, http.StatusOK, map[string]any{
		"token": tokenString,
		"user": map[string]any{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
	})
}

func (s *RouterSrv) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req m.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "name, email and password are required")
		return
	}

	hashPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		writeError(w, http.StatusInternalServerError, "server error, try again")
		return
	}

	req.Password = string(hashPass)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	userID, err := s.pg.RegisterNewUser(ctx, req)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}

		writeError(w, http.StatusInternalServerError, "failed to register user")
		return
	}

	writeResponse(w, http.StatusCreated, map[string]any{
		"id":      userID,
		"message": "user registered successfully",
	})
}

func writeResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := m.Response{
		Data: data,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, status int, errorMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	log.Printf("[ERROR]: %v", errorMessage)

	err := m.ErrorResponse{Error: errorMessage}
	_ = json.NewEncoder(w).Encode(err)
}
