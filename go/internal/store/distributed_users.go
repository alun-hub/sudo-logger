package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// GetUser implements SessionStore.
func (d *DistributedStore) GetUser(ctx context.Context, username string) (*User, error) {
	var u User
	var lastLogin *time.Time
	err := d.db.QueryRow(ctx, `
SELECT username, password_hash, role, source, full_name, email, created_at, last_login
FROM sudo_users
WHERE username = $1`, username).Scan(
		&u.Username, &u.PasswordHash, &u.Role, &u.Source, &u.FullName, &u.Email, &u.CreatedAt, &lastLogin,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if lastLogin != nil {
		u.LastLogin = *lastLogin
	}
	return &u, nil
}

// UpsertUser implements SessionStore.
func (d *DistributedStore) UpsertUser(ctx context.Context, u User) error {
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_users
  (username, password_hash, role, source, full_name, email, created_at, last_login)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE(NULLIF($7, '0001-01-01 00:00:00+00'::timestamptz), NOW()), $8)
ON CONFLICT (username) DO UPDATE SET
  password_hash = EXCLUDED.password_hash, -- pragma: allowlist secret
  role          = EXCLUDED.role,
  source        = EXCLUDED.source,
  full_name     = EXCLUDED.full_name,
  email         = EXCLUDED.email,
  last_login    = COALESCE(EXCLUDED.last_login, sudo_users.last_login)`,
		u.Username, u.PasswordHash, u.Role, u.Source, u.FullName, u.Email, u.CreatedAt,
		func() *time.Time {
			if u.LastLogin.IsZero() {
				return nil
			}
			return &u.LastLogin
		}(),
	)
	if err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}
	return nil
}

// ListUsers implements SessionStore.
func (d *DistributedStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.db.Query(ctx, `
SELECT username, password_hash, role, source, full_name, email, created_at, last_login
FROM sudo_users
ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users = []User{}
	for rows.Next() {
		var u User
		var lastLogin *time.Time
		if err := rows.Scan(
			&u.Username, &u.PasswordHash, &u.Role, &u.Source, &u.FullName, &u.Email, &u.CreatedAt, &lastLogin,
		); err != nil {
			return nil, fmt.Errorf("scan user row: %w", err)
		}
		if lastLogin != nil {
			u.LastLogin = *lastLogin
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeleteUser implements SessionStore.
func (d *DistributedStore) DeleteUser(ctx context.Context, username string) error {
	if _, err := d.db.Exec(ctx, `DELETE FROM sudo_users WHERE username = $1`, username); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// ── Auth Configuration ───────────────────────────────────────────────────

// GetAuthConfig implements SessionStore.
func (d *DistributedStore) GetAuthConfig(ctx context.Context) (AuthConfig, error) {
	var cfg AuthConfig
	var raw []byte
	err := d.db.QueryRow(ctx, `SELECT config_json FROM sudo_auth_config WHERE id = 1`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("get auth config: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse auth config: %w", err)
	}
	return cfg, nil
}

// SetAuthConfig implements SessionStore.
func (d *DistributedStore) SetAuthConfig(ctx context.Context, cfg AuthConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal auth config: %w", err)
	}
	_, err = d.db.Exec(ctx, `
		INSERT INTO sudo_auth_config (id, config_json) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET config_json = EXCLUDED.config_json
	`, raw)
	if err != nil {
		return fmt.Errorf("set auth config: %w", err)
	}
	return nil
}

// ── Role Management ──────────────────────────────────────────────────────────

// GetRoles implements SessionStore.
func (d *DistributedStore) GetRoles(ctx context.Context) ([]RoleDefinition, error) {
	rows, err := d.db.Query(ctx, `SELECT name, description, permissions FROM sudo_roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	// Always prepend the locked built-in admin role synthesised in-memory.
	out := []RoleDefinition{{
		Name:        "admin",
		Description: "Built-in administrator: all permissions",
		Permissions: AllPermissions,
		BuiltIn:     true,
	}}
	for rows.Next() {
		var name, desc string
		var permsJSON []byte
		if err := rows.Scan(&name, &desc, &permsJSON); err != nil {
			return nil, err
		}
		var perms []Permission
		if err := json.Unmarshal(permsJSON, &perms); err != nil {
			return nil, fmt.Errorf("decode permissions for role %q: %w", name, err)
		}
		out = append(out, RoleDefinition{Name: name, Description: desc, Permissions: perms})
	}
	return out, rows.Err()
}

// GetRole implements SessionStore.
func (d *DistributedStore) GetRole(ctx context.Context, name string) (RoleDefinition, error) {
	if name == "admin" {
		return RoleDefinition{
			Name:        "admin",
			Description: "Built-in administrator: all permissions",
			Permissions: AllPermissions,
			BuiltIn:     true,
		}, nil
	}
	var desc string
	var permsJSON []byte
	err := d.db.QueryRow(ctx,
		`SELECT description, permissions FROM sudo_roles WHERE name = $1`, name,
	).Scan(&desc, &permsJSON)
	if err != nil {
		return RoleDefinition{}, nil // not found → empty
	}
	var perms []Permission
	if err := json.Unmarshal(permsJSON, &perms); err != nil {
		return RoleDefinition{}, fmt.Errorf("decode permissions for role %q: %w", name, err)
	}
	return RoleDefinition{Name: name, Description: desc, Permissions: perms}, nil
}

// UpsertRole implements SessionStore.
func (d *DistributedStore) UpsertRole(ctx context.Context, def RoleDefinition) error {
	if def.Name == "admin" {
		return fmt.Errorf("role %q is built-in and cannot be modified", def.Name)
	}
	raw, err := json.Marshal(def.Permissions)
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}
	_, err = d.db.Exec(ctx, `
		INSERT INTO sudo_roles (name, description, permissions)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, permissions = EXCLUDED.permissions
	`, def.Name, def.Description, raw)
	return err
}

// DeleteRole implements SessionStore.
func (d *DistributedStore) DeleteRole(ctx context.Context, name string) error {
	if name == "admin" {
		return fmt.Errorf("role %q is built-in and cannot be deleted", name)
	}
	_, err := d.db.Exec(ctx, `DELETE FROM sudo_roles WHERE name = $1`, name)
	return err
}
