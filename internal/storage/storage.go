package storage

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func Init() error {

	db_auth := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	var err error

	attemps, err := strconv.Atoi(os.Getenv("DB_CONNECT_ATTEMPS"))

	if err != nil || attemps < 1 {
		attemps = 10
	}

	for i := 0; i < attemps; i++ {

		DB, err = sql.Open("postgres", db_auth)

		if err != nil {
			log.Printf("Failed to open DB: %v (attempt %d/10)", err, i+1)
			time.Sleep(2 * time.Second)
			continue
		}

		if err = DB.Ping(); err == nil {
			log.Println("DB connected")
			return nil
		}

		log.Printf("DB ping failed: %v", err)

		DB.Close()

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("failed to connect to DB after 10 attempts")
}

func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

func SaveRefreshToken(user_id, pair_id, resfresh_hash, useragent, ip_address string) error {

	expirationMinutes, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRATION_MINUTES"))

	if err != nil || expirationMinutes < 1440 {
		expirationMinutes = 43200
	}

	_, err = DB.Exec(
		"INSERT INTO refresh_tokens (user_id, pair_id, token_hash, user_agent, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
		user_id,
		pair_id,
		resfresh_hash,
		useragent,
		ip_address,
		time.Now().Add(time.Minute*1*time.Duration(expirationMinutes)),
	)

	return err
}

func AccessTokenIsRevoked(pair_id string) (bool, error) {

	var revoked bool
	err := DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE pair_id = $1)",
		pair_id,
	).Scan(&revoked)

	return revoked, err
}

func RevokeAccessToken(pair_id string, expires_time time.Time) error {

	_, err := DB.Exec(
		"INSERT INTO revoked_tokens (pair_id, expires_at) VALUES ($1, $2)",
		pair_id,
		expires_time,
	)

	return err
}

func RevokeRefreshTokens(pair_id string) error {

	_, err := DB.Exec("UPDATE refresh_tokens SET is_revoked = true WHERE pair_id = $1", pair_id)

	return err
}
