package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/lucsky/cuid"
)

// ErrInvalidCredentials is returned when email/password do not match a user.
var ErrInvalidCredentials = errors.New("invalid credentials")

// LoginInput is transport-agnostic credentials passed from the HTTP layer (or tests).
type LoginInput struct {
	Email    string
	Password string
}

// LoginResult holds issued tokens and authorization metadata for the client.
type LoginResult struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	Permissions  []string `json:"permissions"`
}

// LoginUser authenticates the user, loads permissions, and issues access + refresh JWTs.
func LoginUser(in LoginInput) (*LoginResult, error) {
	user, err := getUserByEmail(in.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}

	match, err := argon2id.ComparePasswordAndHash(in.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return nil, ErrInvalidCredentials
	}

	permissions, err := getUserPermissions(user.CUID)
	if err != nil {
		return nil, err
	}

	accessJTI := cuid.New()
	refreshJTI := cuid.New()

	accessToken, err := signAccessToken(user.CUID, user.Email, accessJTI, permissions, accessTokenTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := signRefreshToken(user.CUID, refreshJTI, refreshTokenTTL)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(refreshTokenTTL).UTC().Format(time.RFC3339)
	if err := storeRefreshToken(cuid.New(), user.CUID, refreshJTI, expiresAt); err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		Permissions:  permissions,
	}, nil
}
