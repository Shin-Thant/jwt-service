package jwtservice

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type authClaim struct {
	UserID string `json:"id"`
	jwt.RegisteredClaims
}

func NewAuthClaim(userId string, registeredClaim *jwt.RegisteredClaims) *authClaim {
	return &authClaim{
		UserID:           userId,
		RegisteredClaims: *registeredClaim,
	}
}

func NewEmptyAuthClaim() *authClaim {
	return &authClaim{}
}

type RegisteredClaimInput struct {
	Issuer    string
	Subject   string
	ExpiresAt time.Time
}

func NewRegisteredClaim(claimInput *RegisteredClaimInput) *jwt.RegisteredClaims {
	return &jwt.RegisteredClaims{
		ID:        time.Now().String(),
		Issuer:    "Server",
		Subject:   claimInput.Subject,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(claimInput.ExpiresAt),
	}
}
