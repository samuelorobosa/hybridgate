package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

type ddlEntry struct {
	name string
	sql  string
}

var DB *sql.DB

func InitDB() {
	var err error

	DB, err = sql.Open("sqlite3", "hybridgate.db?_foreign_keys=on")

	if err != nil {
		log.Panicf("failed to open database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Panicf("failed to ping database: %v", err)
	}

	log.Println("database connected successfully")

	// Set max connections and idle connections
	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(5)

	if err := CreateTables(DB); err != nil {
		log.Panicf("failed to create tables: %v", err)
	}
}

func CreateTables(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	schema := []ddlEntry{
		{
			name: "users",
			sql: `
				CREATE TABLE IF NOT EXISTS users (
					cuid TEXT PRIMARY KEY,
					email TEXT NOT NULL UNIQUE,
					password_hash TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)`,
		},
		{
			name: "roles",
			sql: `
				CREATE TABLE IF NOT EXISTS roles (
					cuid TEXT PRIMARY KEY,
					name TEXT NOT NULL UNIQUE,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)`,
		},
		{
			name: "permissions",
			sql: `
				CREATE TABLE IF NOT EXISTS permissions (
					cuid TEXT PRIMARY KEY,
					slug TEXT NOT NULL UNIQUE,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)`,
		},
		{
			name: "user_roles",
			sql: `
				CREATE TABLE IF NOT EXISTS user_roles (
					user_id TEXT NOT NULL,
					role_id TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					PRIMARY KEY (user_id, role_id),
					FOREIGN KEY (user_id) REFERENCES users(cuid) ON DELETE CASCADE,
					FOREIGN KEY (role_id) REFERENCES roles(cuid) ON DELETE CASCADE
				)`,
		},
		{
			name: "role_permissions",
			sql: `
				CREATE TABLE IF NOT EXISTS role_permissions (
					role_id TEXT NOT NULL,
					permission_id TEXT NOT NULL,
					PRIMARY KEY (role_id, permission_id),
					FOREIGN KEY (role_id) REFERENCES roles(cuid) ON DELETE CASCADE,
					FOREIGN KEY (permission_id) REFERENCES permissions(cuid) ON DELETE CASCADE
				)`,
		},
		{
			name: "refresh_tokens",
			sql: `
				CREATE TABLE IF NOT EXISTS refresh_tokens (
					cuid TEXT PRIMARY KEY,
					user_id TEXT NOT NULL,
					jti TEXT NOT NULL UNIQUE,
					expires_at TIMESTAMP NOT NULL,
					revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (user_id) REFERENCES users(cuid) ON DELETE CASCADE
				)`,
		},
	}

	for _, table := range schema {
		if _, err := db.Exec(table.sql); err != nil {
			return fmt.Errorf("create %s table: %w", table.name, err)
		}
	}

	indexes := []ddlEntry{
		{
			name: "idx_refresh_tokens_user_id",
			sql:  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)`,
		},
		{
			name: "idx_refresh_tokens_jti",
			sql:  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_jti ON refresh_tokens(jti)`,
		},
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx.sql); err != nil {
			return fmt.Errorf("create %s: %w", idx.name, err)
		}
	}

	return nil
}
