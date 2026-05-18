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
