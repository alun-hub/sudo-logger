package store

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// localApprovalWindow is the LocalStore's in-memory representation of an
// active approval window. Unexported — not part of the public store API.
type localApprovalWindow struct {
	User      string    `yaml:"user"`
	Host      string    `yaml:"host"`
	GrantedBy string    `yaml:"granted_by"`
	ExpiresAt time.Time `yaml:"expires_at"`
}

type localApprovalStoreFile struct {
	Pending []ApprovalRequest     `yaml:"pending"`
	Windows []localApprovalWindow `yaml:"windows"`
}

var localApprovalSaveMu sync.Mutex // serialise writes to approval-store.yaml

func (ls *LocalStore) loadApprovalStore() error {
	data, err := os.ReadFile(ls.cfg.ApprovalStorePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var f localApprovalStoreFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return err
	}
	now := time.Now()
	ls.approvalMu.Lock()
	defer ls.approvalMu.Unlock()
	for _, r := range f.Pending {
		r := r
		if r.ExpiresAt.After(now) {
			ls.approvalPending[r.ID] = &r
		}
	}
	for _, w := range f.Windows {
		if w.ExpiresAt.After(now) {
			ls.approvalWindows = append(ls.approvalWindows, w)
		}
	}
	log.Printf("store/local: approval-store: loaded %d pending, %d windows from %s",
		len(ls.approvalPending), len(ls.approvalWindows), ls.cfg.ApprovalStorePath)
	return nil
}

func (ls *LocalStore) saveApprovalStore() {
	ls.approvalMu.RLock()
	f := localApprovalStoreFile{}
	for _, r := range ls.approvalPending {
		f.Pending = append(f.Pending, *r)
	}
	f.Windows = append(f.Windows, ls.approvalWindows...)
	ls.approvalMu.RUnlock()

	data, err := yaml.Marshal(f)
	if err != nil {
		log.Printf("store/local: approval-store marshal: %v", err)
		return
	}
	localApprovalSaveMu.Lock()
	defer localApprovalSaveMu.Unlock()
	tmp := ls.cfg.ApprovalStorePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("store/local: approval-store write: %v", err)
		return
	}
	if err := os.Rename(tmp, ls.cfg.ApprovalStorePath); err != nil {
		log.Printf("store/local: approval-store rename: %v", err)
	}
}

// ── ApprovalStore interface ───────────────────────────────────────────────────

func (ls *LocalStore) ListApprovalRequests(_ context.Context) ([]ApprovalRequest, error) {
	now := time.Now()
	ls.approvalMu.RLock()
	defer ls.approvalMu.RUnlock()
	out := make([]ApprovalRequest, 0, len(ls.approvalPending))
	for _, r := range ls.approvalPending {
		if r.ExpiresAt.After(now) {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (ls *LocalStore) CreateApprovalRequest(_ context.Context, req ApprovalRequest) error {
	ls.approvalMu.Lock()
	ls.approvalPending[req.ID] = &req
	ls.approvalMu.Unlock()
	go ls.saveApprovalStore()
	return nil
}

func (ls *LocalStore) DeleteApprovalRequest(_ context.Context, id string) (*ApprovalRequest, error) {
	ls.approvalMu.Lock()
	req, ok := ls.approvalPending[id]
	if !ok {
		ls.approvalMu.Unlock()
		return nil, nil
	}
	copy := *req
	delete(ls.approvalPending, id)
	ls.approvalMu.Unlock()
	go ls.saveApprovalStore()
	return &copy, nil
}

func (ls *LocalStore) HasApprovalWindow(_ context.Context, user, host string) (bool, error) {
	now := time.Now()
	ls.approvalMu.RLock()
	defer ls.approvalMu.RUnlock()
	for _, w := range ls.approvalWindows {
		if w.User == user && w.Host == host && w.ExpiresAt.After(now) {
			return true, nil
		}
	}
	return false, nil
}

func (ls *LocalStore) CreateApprovalWindow(_ context.Context, user, host, grantedBy string, expiresAt time.Time) error {
	ls.approvalMu.Lock()
	// Replace any existing window for the same user@host.
	replaced := false
	for i, w := range ls.approvalWindows {
		if w.User == user && w.Host == host {
			ls.approvalWindows[i] = localApprovalWindow{User: user, Host: host,
				GrantedBy: grantedBy, ExpiresAt: expiresAt}
			replaced = true
			break
		}
	}
	if !replaced {
		ls.approvalWindows = append(ls.approvalWindows, localApprovalWindow{
			User: user, Host: host, GrantedBy: grantedBy, ExpiresAt: expiresAt,
		})
	}
	ls.approvalMu.Unlock()
	go ls.saveApprovalStore()
	return nil
}
