package token

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redeflesq/auth-example/internal/model"
)

func MakeRandomBytes(length int) []byte {

	bytes := make([]byte, length)

	rand.Read(bytes)

	return bytes
}

func HashRefreshToken(token_data, expected_user_id string) ([]byte, error) {

	to_hash := expected_user_id + ":" + token_data

	hash, err := bcrypt.GenerateFromPassword([]byte(to_hash), bcrypt.DefaultCost)

	return hash, err
}

func GenerateRefreshToken(user_id, pair_id string) (string, string, error) {

	token_data := uuid.NewString()

	token_plain := pair_id + ":" + token_data

	token_base64 := base64.StdEncoding.EncodeToString([]byte(token_plain))

	hash, err := HashRefreshToken(token_data, user_id)

	if err != nil {
		return "", "", err
	}

	return token_base64, string(hash), nil
}

func DecodeRefreshToken(token string) (string, string, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(rawBytes), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid token format")
	}
	return parts[0], parts[1], nil
}

func VerifyRefreshToken(token_data string, hash string, expected_user_id string) bool {

	to_check := expected_user_id + ":" + token_data

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(to_check))

	return err == nil
}

func GenerateJWT(user_id string, pair_id string) (string, error) {

	secret := []byte(os.Getenv("JWT_SECRET"))
	expiration, _ := strconv.Atoi(os.Getenv("JWT_EXPIRATION_MINUTES"))

	claims := model.Claims{
		UserID: user_id,
		PairID: pair_id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * time.Duration(expiration))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-example",
		},
	}

	// Или ES512? Не особо понятно..
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(secret)
}

func GenerateTokensPair(user_id string) (model.TokenPair, error) {

	var token_pair model.TokenPair

	pair_id := uuid.NewString()

	refresh_token, refresh_hash, err := GenerateRefreshToken(user_id, pair_id)

	if err != nil {
		return token_pair, err
	}

	jwt, err := GenerateJWT(user_id, pair_id)

	if err != nil {
		return token_pair, err
	}

	token_pair.AccessToken = jwt
	token_pair.RefreshToken.Hash = refresh_hash
	token_pair.RefreshToken.Token = refresh_token
	token_pair.PairID = pair_id

	return token_pair, nil
}
