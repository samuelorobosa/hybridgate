package auth

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = time.Hour
	tokenTypeAccess = "access"
	tokenTypeRefresh = "refresh"
)

type tokenClaims struct {
	TokenType   string   `json:"typ"`
	Email       string   `json:"email,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

func jwtSecret() ([]byte, error) {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is not set")
	}
	return []byte(secret), nil
}

func signAccessToken(userCUID, email, jti string, permissions []string, ttl time.Duration) (string, error) {
	secret, err := jwtSecret()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := tokenClaims{
		TokenType:   tokenTypeAccess,
		Email:       email,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userCUID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func signRefreshToken(userCUID, jti string, ttl time.Duration) (string, error) {
	secret, err := jwtSecret()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := tokenClaims{
		TokenType: tokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userCUID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

type ParsedToken struct {
	TokenType   string
	UserCUID    string
	Email       string
	Permissions []string
	JTI         string
	ExpiresAt   time.Time
}

func parseToken(tokenString string, expectedType string) (*ParsedToken, error) {
	secret, err := jwtSecret()
	if err != nil {
		return nil, err
	}

	claims := &tokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.TokenType != expectedType {
		return nil, fmt.Errorf("unexpected token type %q", claims.TokenType)
	}
	if claims.Subject == "" || claims.ID == "" {
		return nil, fmt.Errorf("token missing subject or jti")
	}

	expiresAt := time.Time{}
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	return &ParsedToken{
		TokenType:   claims.TokenType,
		UserCUID:    claims.Subject,
		Email:       claims.Email,
		Permissions: claims.Permissions,
		JTI:         claims.ID,
		ExpiresAt:   expiresAt,
	}, nil
}

func ParseAccessToken(tokenString string) (*ParsedToken, error) {
	return parseToken(tokenString, tokenTypeAccess)
}

func ParseRefreshToken(tokenString string) (*ParsedToken, error) {
	return parseToken(tokenString, tokenTypeRefresh)
}
