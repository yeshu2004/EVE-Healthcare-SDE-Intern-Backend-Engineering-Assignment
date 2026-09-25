package database

import (
	"context"
	"database/sql"
	"fmt"
	"github/yeshu2004/eve-health/models"
	"log"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

type PostgresClient struct {
	db *sql.DB
}

func ConnectPostgresSQL() (*PostgresClient, error) {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env")
	}
	
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s sslmode=disable", dbUser, dbPassword, dbName)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Minute * 5)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	log.Println("PostgreSQL DB connected!")

	return &PostgresClient{
		db: db,
	}, nil
}

func (pg *PostgresClient) RegisterNewUser(ctx context.Context, data models.RegisterRequest) (int, error) {
	var userID int
	query := `INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING RETURNING id`

	err := pg.db.QueryRowContext(ctx, query, data.Name, data.Email, data.Password).Scan(&userID); 
	if err != nil {
		return -1, err
	}

	return userID, nil;
}

func (pg *PostgresClient) GetUserByEmail(ctx context.Context, email string) (models.User, error){
	var user models.User
	query := `SELECT id, name, email, password_hash FROM users WHERE email = $1`
	if err := pg.db.QueryRowContext(ctx, query, email).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash); err != nil {
		return user, err
	}

	return user, nil
}
