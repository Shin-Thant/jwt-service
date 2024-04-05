package jwtservice

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

func NewAuthJwtToken(claim *authClaim) *jwt.Token {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
}

func ParseJwtWithClaims(token string, claim *authClaim, secret string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(
		token,
		claim,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("invalid signing method")
			}
			return []byte(secret), nil
		},
		jwt.WithExpirationRequired(),
	)
}
