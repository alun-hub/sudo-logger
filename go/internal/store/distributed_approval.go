package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (d *DistributedStore) ListApprovalRequests(ctx context.Context) ([]ApprovalRequest, error) {
	rows, err := d.db.Query(ctx, `
SELECT id, username, host, command, justification, notify_via, submitted_at, expires_at
FROM sudo_approval_requests
WHERE expires_at > $1
ORDER BY submitted_at ASC`,
		time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApprovalRequest
	for rows.Next() {
		var r ApprovalRequest
		var submittedAt, expiresAt int64
		if err := rows.Scan(&r.ID, &r.User, &r.Host, &r.Command,
			&r.Justification, &r.NotifyVia, &submittedAt, &expiresAt); err != nil {
			return nil, err
		}
		r.SubmittedAt = time.Unix(submittedAt, 0)
		r.ExpiresAt = time.Unix(expiresAt, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DistributedStore) CreateApprovalRequest(ctx context.Context, req ApprovalRequest) error {
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_approval_requests
    (id, username, host, command, justification, notify_via, submitted_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING`,
		req.ID, req.User, req.Host, req.Command,
		req.Justification, req.NotifyVia,
		req.SubmittedAt.Unix(), req.ExpiresAt.Unix())
	return err
}

func (d *DistributedStore) DeleteApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error) {
	var r ApprovalRequest
	var submittedAt, expiresAt int64
	err := d.db.QueryRow(ctx, `
DELETE FROM sudo_approval_requests
WHERE id = $1
RETURNING id, username, host, command, justification, notify_via, submitted_at, expires_at`,
		id).Scan(&r.ID, &r.User, &r.Host, &r.Command,
		&r.Justification, &r.NotifyVia, &submittedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.SubmittedAt = time.Unix(submittedAt, 0)
	r.ExpiresAt = time.Unix(expiresAt, 0)
	return &r, nil
}

func (d *DistributedStore) HasApprovalWindow(ctx context.Context, user, host string) (time.Time, bool, error) {
	var expiresAtUnix int64
	err := d.db.QueryRow(ctx, `
SELECT expires_at FROM sudo_approval_windows
WHERE username = $1 AND host = $2`,
		user, host).Scan(&expiresAtUnix)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	exp := time.Unix(expiresAtUnix, 0)
	if !exp.After(time.Now()) {
		return time.Time{}, false, nil
	}
	return exp, true, nil
}

func (d *DistributedStore) CreateApprovalWindow(ctx context.Context, user, host, grantedBy string, expiresAt time.Time) error {
	_, err := d.db.Exec(ctx, `
INSERT INTO sudo_approval_windows (username, host, granted_by, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (username, host) DO UPDATE
    SET granted_by = EXCLUDED.granted_by,
        expires_at = EXCLUDED.expires_at`,
		user, host, grantedBy, expiresAt.Unix())
	return err
}

// ── distributedWriter ─────────────────────────────────────────────────────────
