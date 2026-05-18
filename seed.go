package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/alexedwards/argon2id"
	"github.com/lucsky/cuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/samuelorobosa/hybridgate/internal/platform/database"
)

const defaultPassword = "password123"

var (
	dbPath = flag.String("db", "hybridgate.db", "path to the SQLite database file")

	userSeeds = []struct {
		email    string
		roleName string
	}{
		{email: "admin@test.com", roleName: "Admin"},
		{email: "manager@test.com", roleName: "Manager"},
		{email: "guest@test.com", roleName: "Viewer"},
	}
)

func main() {
	flag.Parse()

	log.Printf("opening database: %s", *dbPath)

	db, err := sql.Open("sqlite3", *dbPath+"?_foreign_keys=on")
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	if err := database.CreateTables(db); err != nil {
		log.Fatalf("create schema: %v", err)
	}
	log.Println("tables created")

	if err := seedData(db); err != nil {
		log.Fatalf("seed data: %v", err)
	}

	log.Println("seed completed successfully")
}

func seedData(db *sql.DB) error {
	passwordHash, err := argon2id.CreateHash(defaultPassword, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				log.Printf("rollback failed: %v", rbErr)
			}
			return
		}
		if err = tx.Commit(); err != nil {
			err = fmt.Errorf("commit transaction: %w", err)
		}
	}()

	permRead, err := ensurePermission(tx, "file:read")
	if err != nil {
		return err
	}
	permWrite, err := ensurePermission(tx, "file:write")
	if err != nil {
		return err
	}
	permRevoke, err := ensurePermission(tx, "admin:revoke")
	if err != nil {
		return err
	}
	log.Println("permissions ready: file:read, file:write, admin:revoke")

	roleAdmin, err := ensureRole(tx, "Admin")
	if err != nil {
		return err
	}
	roleManager, err := ensureRole(tx, "Manager")
	if err != nil {
		return err
	}
	roleViewer, err := ensureRole(tx, "Viewer")
	if err != nil {
		return err
	}
	log.Println("roles ready: Admin, Manager, Viewer")

	if err := linkRolePermission(tx, roleAdmin, permRead); err != nil {
		return err
	}
	if err := linkRolePermission(tx, roleAdmin, permWrite); err != nil {
		return err
	}
	if err := linkRolePermission(tx, roleAdmin, permRevoke); err != nil {
		return err
	}

	if err := linkRolePermission(tx, roleManager, permRead); err != nil {
		return err
	}
	if err := linkRolePermission(tx, roleManager, permWrite); err != nil {
		return err
	}

	if err := linkRolePermission(tx, roleViewer, permRead); err != nil {
		return err
	}
	log.Println("role_permissions linked")

	rolesByName := map[string]string{
		"Admin":   roleAdmin,
		"Manager": roleManager,
		"Viewer":  roleViewer,
	}
	if err := seedUsers(tx, passwordHash, rolesByName); err != nil {
		return err
	}

	return nil
}

func seedUsers(tx *sql.Tx, passwordHash string, rolesByName map[string]string) error {
	for _, u := range userSeeds {
		userCUID, err := ensureUser(tx, u.email, passwordHash)
		if err != nil {
			return err
		}

		roleCUID, ok := rolesByName[u.roleName]
		if !ok {
			return fmt.Errorf("unknown role %q for user %q", u.roleName, u.email)
		}

		if err := linkUserRole(tx, userCUID, roleCUID); err != nil {
			return err
		}

		log.Printf("user seeded: %s -> %s (%s)", u.email, u.roleName, userCUID)
	}

	log.Println("users and user_roles ready")
	return nil
}

func ensurePermission(tx *sql.Tx, slug string) (string, error) {
	var permCUID string
	err := tx.QueryRow(`SELECT cuid FROM permissions WHERE slug = ?`, slug).Scan(&permCUID)
	if err == nil {
		return permCUID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("lookup permission %q: %w", slug, err)
	}

	permCUID = cuid.New()
	_, err = tx.Exec(
		`INSERT OR IGNORE INTO permissions (cuid, slug) VALUES (?, ?)`,
		permCUID,
		slug,
	)
	if err != nil {
		return "", fmt.Errorf("insert permission %q: %w", slug, err)
	}

	err = tx.QueryRow(`SELECT cuid FROM permissions WHERE slug = ?`, slug).Scan(&permCUID)
	if err != nil {
		return "", fmt.Errorf("reload permission %q: %w", slug, err)
	}

	log.Printf("permission inserted: %s (%s)", slug, permCUID)
	return permCUID, nil
}

func ensureRole(tx *sql.Tx, name string) (string, error) {
	var roleCUID string
	err := tx.QueryRow(`SELECT cuid FROM roles WHERE name = ?`, name).Scan(&roleCUID)
	if err == nil {
		return roleCUID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("lookup role %q: %w", name, err)
	}

	roleCUID = cuid.New()
	_, err = tx.Exec(
		`INSERT OR IGNORE INTO roles (cuid, name) VALUES (?, ?)`,
		roleCUID,
		name,
	)
	if err != nil {
		return "", fmt.Errorf("insert role %q: %w", name, err)
	}

	err = tx.QueryRow(`SELECT cuid FROM roles WHERE name = ?`, name).Scan(&roleCUID)
	if err != nil {
		return "", fmt.Errorf("reload role %q: %w", name, err)
	}

	log.Printf("role inserted: %s (%s)", name, roleCUID)
	return roleCUID, nil
}

func ensureUser(tx *sql.Tx, email, passwordHash string) (string, error) {
	var userCUID string
	err := tx.QueryRow(`SELECT cuid FROM users WHERE email = ?`, email).Scan(&userCUID)
	if err == nil {
		log.Printf("user already exists: %s (%s)", email, userCUID)
		return userCUID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("lookup user %q: %w", email, err)
	}

	userCUID = cuid.New()
	_, err = tx.Exec(
		`INSERT OR IGNORE INTO users (cuid, email, password_hash) VALUES (?, ?, ?)`,
		userCUID,
		email,
		passwordHash,
	)
	if err != nil {
		return "", fmt.Errorf("insert user %q: %w", email, err)
	}

	err = tx.QueryRow(`SELECT cuid FROM users WHERE email = ?`, email).Scan(&userCUID)
	if err != nil {
		return "", fmt.Errorf("reload user %q: %w", email, err)
	}

	log.Printf("user inserted: %s (%s)", email, userCUID)
	return userCUID, nil
}

func linkRolePermission(tx *sql.Tx, roleCUID, permissionCUID string) error {
	_, err := tx.Exec(
		`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`,
		roleCUID,
		permissionCUID,
	)
	if err != nil {
		return fmt.Errorf("link role %s to permission %s: %w", roleCUID, permissionCUID, err)
	}
	return nil
}

func linkUserRole(tx *sql.Tx, userCUID, roleCUID string) error {
	_, err := tx.Exec(
		`INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)`,
		userCUID,
		roleCUID,
	)
	if err != nil {
		return fmt.Errorf("link user %s to role %s: %w", userCUID, roleCUID, err)
	}
	return nil
}
