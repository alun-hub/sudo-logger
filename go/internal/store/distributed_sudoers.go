package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sudo-logger/internal/protocol"

	"github.com/jackc/pgx/v5"
)

// SaveSudoersSnapshot implements SessionStore.
func (d *DistributedStore) SaveSudoersSnapshot(ctx context.Context, snap *protocol.SudoersSnapshot) error {
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_sudoers_snapshots (host, content, sha256, uploaded_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (host, sha256) DO UPDATE SET uploaded_at = excluded.uploaded_at`,
		snap.Host, snap.Content, snap.SHA256, time.Now().Unix())
	return err
}

// ListSudoersSnapshots implements SessionStore.
func (d *DistributedStore) ListSudoersSnapshots(ctx context.Context, host string, limit int) ([]SudoersSnapshotRecord, error) {
	rows, err := d.db.Query(ctx, `
SELECT host, sha256, uploaded_at, content
FROM sudo_sudoers_snapshots
WHERE host = $1
ORDER BY uploaded_at DESC
LIMIT $2`, host, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SudoersSnapshotRecord
	for rows.Next() {
		var r SudoersSnapshotRecord
		if err := rows.Scan(&r.Host, &r.SHA256, &r.UploadedAt, &r.Content); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListSudoersHosts implements SessionStore.
func (d *DistributedStore) ListSudoersHosts(ctx context.Context) ([]string, error) {
	rows, err := d.db.Query(ctx, `SELECT DISTINCT host FROM sudo_sudoers_snapshots ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// ListSudoersConfigs implements SessionStore.
func (d *DistributedStore) ListSudoersConfigs(ctx context.Context) (map[string]bool, error) {
	rows, err := d.db.Query(ctx, `SELECT key FROM sudo_config WHERE key LIKE 'sudoers/%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(key, "sudoers/")] = true
	}
	return out, rows.Err()
}

// SaveSudoersError implements SessionStore.
func (d *DistributedStore) SaveSudoersError(ctx context.Context, serr protocol.SudoersError) error {
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_config (key, value)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		"sudoers_err/"+serr.Host, string(toJSON(serr)))
	return err
}

// GetSudoersError implements SessionStore.
func (d *DistributedStore) GetSudoersError(ctx context.Context, host string) (*protocol.SudoersError, error) {
	var val string
	err := d.db.QueryRow(ctx, `SELECT value FROM sudo_config WHERE key = $1`, "sudoers_err/"+host).Scan(&val)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var serr protocol.SudoersError
	if err := json.Unmarshal([]byte(val), &serr); err != nil {
		return nil, err
	}
	return &serr, nil
}

// SaveHeartbeat implements SessionStore.
func (d *DistributedStore) SaveHeartbeat(ctx context.Context, host string) error {
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_config (key, value)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		"sudoers_seen/"+host, fmt.Sprintf("%d", time.Now().Unix()))
	return err
}

// GetLastSeen implements SessionStore.
func (d *DistributedStore) GetLastSeen(ctx context.Context, host string) (int64, error) {
	var val string
	err := d.db.QueryRow(ctx, `SELECT value FROM sudo_config WHERE key = $1`, "sudoers_seen/"+host).Scan(&val)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var ts int64
	_, err = fmt.Sscanf(val, "%d", &ts)
	return ts, err
}
