package model

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	UserID string `json:"user_id"`
	PairID string `json:"pair_id"`
	jwt.RegisteredClaims
}

type RefreshToken_ struct {
	Token string `json:"token"`
	Hash  string `json:"hash"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken RefreshToken_
	PairID       string `json:"pair_id"`
}

// Responses

type SuccessResponse struct {
	Success string `json:"success"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserIdResponse struct {
	UserID string `json:"user_id"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Requests

type TokenRequest struct {
	RefreshToken string `json:"refresh_token"` // It's not hash
}

type UserIdRequest struct {
	UserID string `json:"user_id"`
}
