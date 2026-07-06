package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// IsBlocked implements SessionStore.
func (d *DistributedStore) IsBlocked(ctx context.Context, user, host string) (bool, string, error) {
	var reason string
	err := d.db.QueryRow(ctx, `
SELECT COALESCE((SELECT value FROM sudo_config WHERE key='block_message'),'')
FROM sudo_blocked_users
WHERE username=$1 AND (host=$2 OR host IS NULL)
LIMIT 1`,
		user, host,
	).Scan(&reason)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil // no match
		}
		return false, "", err
	}
	return true, reason, nil
}


// GetBlockedPolicy reads all blocked-user rows and returns them as a BlockedPolicy.
// Multiple rows with the same username (different hosts) are merged into one entry.
func (d *DistributedStore) GetBlockedPolicy(ctx context.Context) (BlockedPolicy, error) {
	// Block message is stored separately in sudo_config.
	var blockMsg string
	rows, err := d.db.Query(ctx, `SELECT value FROM sudo_config WHERE key = 'block_message'`)
	if err == nil {
		if rows.Next() {
			_ = rows.Scan(&blockMsg)
		}
		rows.Close()
	}

	// Read all blocked users.
	urows, err := d.db.Query(ctx, `
SELECT username, host, reason, blocked_at
FROM sudo_blocked_users
ORDER BY username, host NULLS FIRST`)
	if err != nil {
		return BlockedPolicy{}, err
	}
	defer urows.Close()

	type row struct {
		username  string
		host      *string
		reason    *string
		blockedAt *int64
	}
	userMap := make(map[string]*BlockedUserEntry)
	var order []string
	for urows.Next() {
		var r row
		if err := urows.Scan(&r.username, &r.host, &r.reason, &r.blockedAt); err != nil {
			return BlockedPolicy{}, err
		}
		if _, exists := userMap[r.username]; !exists {
			reason := ""
			if r.reason != nil {
				reason = *r.reason
			}
			var at int64
			if r.blockedAt != nil {
				at = *r.blockedAt
			}
			userMap[r.username] = &BlockedUserEntry{
				Username:  r.username,
				Reason:    reason,
				BlockedAt: at,
			}
			order = append(order, r.username)
		}
		if r.host != nil && *r.host != "" {
			userMap[r.username].Hosts = append(userMap[r.username].Hosts, *r.host)
		}
	}
	if err := urows.Err(); err != nil {
		return BlockedPolicy{}, err
	}

	p := BlockedPolicy{BlockMessage: blockMsg}
	for _, u := range order {
		e := *userMap[u]
		if e.Hosts == nil {
			e.Hosts = []string{}
		}
		p.Users = append(p.Users, e)
	}
	if p.Users == nil {
		p.Users = []BlockedUserEntry{}
	}
	return p, nil
}

// SaveBlockedPolicy replaces the full blocked-users list in a single transaction.
func (d *DistributedStore) SaveBlockedPolicy(ctx context.Context, policy BlockedPolicy) error {
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM sudo_blocked_users`); err != nil {
		return err
	}

	for _, u := range policy.Users {
		if len(u.Hosts) == 0 {
			// NULL host = blocked on all hosts.
			if _, err := tx.Exec(ctx,
				`INSERT INTO sudo_blocked_users (username, host, reason, blocked_at) VALUES ($1, NULL, $2, $3)`,
				u.Username, u.Reason, u.BlockedAt); err != nil {
				return err
			}
		} else {
			for _, h := range u.Hosts {
				if _, err := tx.Exec(ctx,
					`INSERT INTO sudo_blocked_users (username, host, reason, blocked_at) VALUES ($1, $2, $3, $4)`,
					u.Username, h, u.Reason, u.BlockedAt); err != nil {
					return err
				}
			}
		}
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO sudo_config (key, value) VALUES ('block_message', $1)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		policy.BlockMessage); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// IsWhitelisted implements SessionStore.
func (d *DistributedStore) IsWhitelisted(ctx context.Context, user, host string) (bool, error) {
	var dummy int
	err := d.db.QueryRow(ctx, `
SELECT 1 FROM sudo_whitelisted_users
WHERE username=$1 AND (host=$2 OR host IS NULL)
LIMIT 1`, user, host).Scan(&dummy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil // no match
		}
		return false, err
	}
	return true, nil
}

// GetWhitelistPolicy reads all whitelisted-user rows and returns them as a WhitelistPolicy.
func (d *DistributedStore) GetWhitelistPolicy(ctx context.Context) (WhitelistPolicy, error) {
	rows, err := d.db.Query(ctx, `
SELECT username, host, reason
FROM sudo_whitelisted_users
ORDER BY username, host NULLS FIRST`)
	if err != nil {
		return WhitelistPolicy{}, err
	}
	defer rows.Close()

	type row struct {
		username string
		host     *string
		reason   *string
	}
	userMap := make(map[string]*WhitelistedUserEntry)
	var order []string
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.username, &r.host, &r.reason); err != nil {
			return WhitelistPolicy{}, err
		}
		if _, exists := userMap[r.username]; !exists {
			reason := ""
			if r.reason != nil {
				reason = *r.reason
			}
			userMap[r.username] = &WhitelistedUserEntry{
				Username: r.username,
				Reason:   reason,
			}
			order = append(order, r.username)
		}
		if r.host != nil && *r.host != "" {
			userMap[r.username].Hosts = append(userMap[r.username].Hosts, *r.host)
		}
	}
	if err := rows.Err(); err != nil {
		return WhitelistPolicy{}, err
	}

	var p WhitelistPolicy
	for _, u := range order {
		e := *userMap[u]
		if e.Hosts == nil {
			e.Hosts = []string{}
		}
		p.Users = append(p.Users, e)
	}
	if p.Users == nil {
		p.Users = []WhitelistedUserEntry{}
	}
	return p, nil
}

// SaveWhitelistPolicy replaces the full whitelisted-users list in a single transaction.
func (d *DistributedStore) SaveWhitelistPolicy(ctx context.Context, policy WhitelistPolicy) error {
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM sudo_whitelisted_users`); err != nil {
		return err
	}

	for _, u := range policy.Users {
		if len(u.Hosts) == 0 {
			if _, err := tx.Exec(ctx,
				`INSERT INTO sudo_whitelisted_users (username, host, reason) VALUES ($1, NULL, $2)`,
				u.Username, u.Reason); err != nil {
				return err
			}
		} else {
			for _, h := range u.Hosts {
				if _, err := tx.Exec(ctx,
					`INSERT INTO sudo_whitelisted_users (username, host, reason) VALUES ($1, $2, $3)`,
					u.Username, h, u.Reason); err != nil {
					return err
				}
			}
		}
	}

	return tx.Commit(ctx)
}

// ── ApprovalStore implementation (DistributedStore) ───────────────────────────
