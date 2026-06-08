package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/lucsky/cuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrUserNotFound       = errors.New("user not found")
)

type LoginInput struct {
	Email    string
	Password string
}

type LoginResult struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	Permissions  []string `json:"permissions"`
}

type RevokeInput struct {
	Email string
}

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

	return issueSession(user.CUID, user.Email)
}

func RefreshSession(refreshToken string) (*LoginResult, error) {
	parsed, err := ParseRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	reqCtx := context.Background()
	revoked, err := IsUserRevoked(reqCtx, parsed.UserCUID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrInvalidToken
	}

	record, err := getRefreshTokenByJTI(parsed.JTI)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Revoked {
		return nil, ErrInvalidToken
	}

	expiresAt, err := time.Parse(time.RFC3339, record.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse refresh expiry: %w", err)
	}
	if time.Now().After(expiresAt) {
		return nil, ErrInvalidToken
	}

	user, err := getUserByCUID(parsed.UserCUID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidToken
	}

	if err := revokeRefreshTokenByJTI(parsed.JTI); err != nil {
		return nil, err
	}

	return issueSession(user.CUID, user.Email)
}

func RevokeUser(ctx context.Context, in RevokeInput) error {
	user, err := getUserByEmail(in.Email)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	if err := removeAllUserRoles(user.CUID); err != nil {
		return err
	}
	if err := revokeAllRefreshTokensForUser(user.CUID); err != nil {
		return err
	}
	if err := MarkUserRevoked(ctx, user.CUID, accessTokenTTL); err != nil {
		return err
	}

	return nil
}

func LogoutUser(ctx context.Context, accessJTI, refreshToken string) error {
	if accessJTI != "" {
		if err := BlacklistJTI(ctx, accessJTI, accessTokenTTL); err != nil {
			return err
		}
	}

	if refreshToken != "" {
		if parsed, err := ParseRefreshToken(refreshToken); err == nil {
			_ = revokeRefreshTokenByJTI(parsed.JTI)
		}
	}

	return nil
}

func issueSession(userCUID, email string) (*LoginResult, error) {
	permissions, err := getUserPermissions(userCUID)
	if err != nil {
		return nil, err
	}

	accessJTI := cuid.New()
	refreshJTI := cuid.New()

	accessToken, err := signAccessToken(userCUID, email, accessJTI, permissions, accessTokenTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := signRefreshToken(userCUID, refreshJTI, refreshTokenTTL)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(refreshTokenTTL).UTC().Format(time.RFC3339)
	if err := storeRefreshToken(cuid.New(), userCUID, refreshJTI, expiresAt); err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		Permissions:  permissions,
	}, nil
}
