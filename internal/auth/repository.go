package auth

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/samuelorobosa/hybridgate/internal/platform/database"
)

type userRecord struct {
	CUID         string
	Email        string
	PasswordHash string
}

func getUserByEmail(email string) (*userRecord, error) {
	var u userRecord
	err := database.DB.QueryRow(
		`SELECT cuid, email, password_hash FROM users WHERE email = ?`,
		email,
	).Scan(&u.CUID, &u.Email, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &u, nil
}

func getUserPermissions(userCUID string) ([]string, error) {
	rows, err := database.DB.Query(
		`SELECT DISTINCT p.slug
		 FROM permissions p
		 INNER JOIN role_permissions rp ON rp.permission_id = p.cuid
		 INNER JOIN user_roles ur ON ur.role_id = rp.role_id
		 WHERE ur.user_id = ?
		 ORDER BY p.slug`,
		userCUID,
	)
	if err != nil {
		return nil, fmt.Errorf("get user permissions: %w", err)
	}
	defer rows.Close()

	var slugs []string
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, fmt.Errorf("scan permission slug: %w", err)
		}
		slugs = append(slugs, slug)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions: %w", err)
	}
	return slugs, nil
}

func getUserByCUID(userCUID string) (*userRecord, error) {
	var u userRecord
	err := database.DB.QueryRow(
		`SELECT cuid, email, password_hash FROM users WHERE cuid = ?`,
		userCUID,
	).Scan(&u.CUID, &u.Email, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by cuid: %w", err)
	}
	return &u, nil
}

type refreshTokenRecord struct {
	CUID      string
	UserID    string
	JTI       string
	ExpiresAt string
	Revoked   bool
}

func getRefreshTokenByJTI(jti string) (*refreshTokenRecord, error) {
	var r refreshTokenRecord
	var revoked int
	err := database.DB.QueryRow(
		`SELECT cuid, user_id, jti, expires_at, revoked FROM refresh_tokens WHERE jti = ?`,
		jti,
	).Scan(&r.CUID, &r.UserID, &r.JTI, &r.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	r.Revoked = revoked == 1
	return &r, nil
}

func storeRefreshToken(recordCUID, userCUID, jti string, expiresAt string) error {
	_, err := database.DB.Exec(
		`INSERT INTO refresh_tokens (cuid, user_id, jti, expires_at, revoked) VALUES (?, ?, ?, ?, 0)`,
		recordCUID,
		userCUID,
		jti,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

func revokeRefreshTokenByJTI(jti string) error {
	_, err := database.DB.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?`, jti)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func revokeAllRefreshTokensForUser(userCUID string) error {
	_, err := database.DB.Exec(
		`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0`,
		userCUID,
	)
	if err != nil {
		return fmt.Errorf("revoke user refresh tokens: %w", err)
	}
	return nil
}

func removeAllUserRoles(userCUID string) error {
	_, err := database.DB.Exec(`DELETE FROM user_roles WHERE user_id = ?`, userCUID)
	if err != nil {
		return fmt.Errorf("remove user roles: %w", err)
	}
	return nil
}
