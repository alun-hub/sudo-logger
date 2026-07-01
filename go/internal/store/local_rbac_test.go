package store_test

// Tests for the LocalStore RBAC surface: GetUser/UpsertUser/ListUsers/
// DeleteUser, GetAuthConfig/SetAuthConfig, GetRoles/GetRole/UpsertRole/
// DeleteRole/seedViewerRole.

import (
	"testing"

	"sudo-logger/internal/store"
)

// ── Users ─────────────────────────────────────────────────────────────────────

func TestLocalStoreUpsertAndGetUser(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	u := store.User{Username: "alice", PasswordHash: "hash1", Role: "admin", Source: "local"}
	if err := s.UpsertUser(ctx, u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	got, err := s.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got == nil {
		t.Fatal("GetUser returned nil for a user that was just upserted")
		return
	}
	if got.Username != "alice" || got.Role != "admin" || got.PasswordHash != "hash1" { // pragma: allowlist secret
		t.Errorf("GetUser = %+v, want username=alice role=admin hash=hash1", got)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set on first insert")
	}
}

func TestLocalStoreGetUser_Unknown(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	got, err := s.GetUser(t.Context(), "nobody")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got != nil {
		t.Errorf("GetUser for unknown user = %+v, want nil", got)
	}
}

func TestLocalStoreUpsertUser_UpdatePreservesCreatedAt(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	original := store.User{Username: "alice", PasswordHash: "hash1", Role: "viewer", Source: "local"}
	if err := s.UpsertUser(ctx, original); err != nil {
		t.Fatalf("UpsertUser (create): %v", err)
	}
	created, err := s.GetUser(ctx, "alice")
	if err != nil || created == nil {
		t.Fatalf("GetUser after create: %v", err)
	}

	// Update without an explicit CreatedAt — the store should preserve the
	// original timestamp rather than overwriting it with the zero value.
	update := store.User{Username: "alice", PasswordHash: "hash2", Role: "admin", Source: "local"}
	if err := s.UpsertUser(ctx, update); err != nil {
		t.Fatalf("UpsertUser (update): %v", err)
	}
	updated, err := s.GetUser(ctx, "alice")
	if err != nil || updated == nil {
		t.Fatalf("GetUser after update: %v", err)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("CreatedAt changed on update: got %v, want %v", updated.CreatedAt, created.CreatedAt)
	}
	if updated.PasswordHash != "hash2" || updated.Role != "admin" { // pragma: allowlist secret
		t.Errorf("update did not apply: got %+v", updated)
	}
}

func TestLocalStoreListUsers_SortedByUsername(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	for _, name := range []string{"carol", "alice", "bob"} {
		if err := s.UpsertUser(ctx, store.User{Username: name, Source: "local"}); err != nil {
			t.Fatalf("UpsertUser(%s): %v", name, err)
		}
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("ListUsers count = %d, want 3", len(users))
	}
	want := []string{"alice", "bob", "carol"}
	for i, u := range users {
		if u.Username != want[i] {
			t.Errorf("ListUsers[%d] = %q, want %q", i, u.Username, want[i])
		}
	}
}

func TestLocalStoreDeleteUser(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	if err := s.UpsertUser(ctx, store.User{Username: "alice", Source: "local"}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	got, err := s.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser after delete: %v", err)
	}
	if got != nil {
		t.Errorf("user still present after DeleteUser: %+v", got)
	}
}

func TestLocalStoreDeleteUser_Nonexistent(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	// Deleting a user that was never created must not error.
	if err := s.DeleteUser(t.Context(), "nobody"); err != nil {
		t.Errorf("DeleteUser of unknown user returned an error: %v", err)
	}
}

func TestLocalStoreUsers_PersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1, err := store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.UpsertUser(t.Context(), store.User{Username: "alice", PasswordHash: "h", Source: "local"}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	s1.Close()

	s2, err := store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("New (reopen): %v", err)
	}
	defer s2.Close()
	got, err := s2.GetUser(t.Context(), "alice")
	if err != nil {
		t.Fatalf("GetUser after reopen: %v", err)
	}
	if got == nil {
		t.Fatal("user did not persist across store reopen")
	}
}

// ── Auth config ───────────────────────────────────────────────────────────────

func TestLocalStoreAuthConfig_DefaultsToLocal(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	cfg, err := s.GetAuthConfig(t.Context())
	if err != nil {
		t.Fatalf("GetAuthConfig: %v", err)
	}
	if cfg.Source != "local" {
		t.Errorf("default AuthConfig.Source = %q, want %q", cfg.Source, "local")
	}
}

func TestLocalStoreSetAndGetAuthConfig(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	cfg := store.AuthConfig{Source: "proxy", AdminGroups: []string{"admins"}}
	if err := s.SetAuthConfig(ctx, cfg); err != nil {
		t.Fatalf("SetAuthConfig: %v", err)
	}
	got, err := s.GetAuthConfig(ctx)
	if err != nil {
		t.Fatalf("GetAuthConfig: %v", err)
	}
	if got.Source != "proxy" || len(got.AdminGroups) != 1 || got.AdminGroups[0] != "admins" {
		t.Errorf("GetAuthConfig after set = %+v, want source=proxy admin_groups=[admins]", got)
	}
}

// ── Roles ─────────────────────────────────────────────────────────────────────

func TestLocalStoreGetRoles_IncludesBuiltinAdmin(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	roles, err := s.GetRoles(t.Context())
	if err != nil {
		t.Fatalf("GetRoles: %v", err)
	}
	var foundAdmin, foundViewer bool
	for _, r := range roles {
		if r.Name == "admin" {
			foundAdmin = true
			if !r.BuiltIn {
				t.Error("admin role should be marked BuiltIn")
			}
			if len(r.Permissions) != len(store.AllPermissions) {
				t.Errorf("admin role permissions = %d, want %d (all permissions)", len(r.Permissions), len(store.AllPermissions))
			}
		}
		if r.Name == "viewer" {
			foundViewer = true
		}
	}
	if !foundAdmin {
		t.Error("GetRoles did not include the built-in admin role")
	}
	if !foundViewer {
		t.Error("GetRoles did not include the seeded viewer role")
	}
}

func TestLocalStoreGetRole_Admin(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	role, err := s.GetRole(t.Context(), "admin")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if role.Name != "admin" || !role.BuiltIn {
		t.Errorf("GetRole(admin) = %+v, want built-in admin", role)
	}
}

func TestLocalStoreGetRole_Unknown(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	role, err := s.GetRole(t.Context(), "does-not-exist")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if role.Name != "" {
		t.Errorf("GetRole for unknown role = %+v, want zero value", role)
	}
}

func TestLocalStoreUpsertRole_CustomRole(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	def := store.RoleDefinition{
		Name:        "operator",
		Description: "Can list and replay all sessions",
		Permissions: []store.Permission{store.PermSessionsListOwn, store.PermSessionsReplayOwn},
	}
	if err := s.UpsertRole(ctx, def); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	got, err := s.GetRole(ctx, "operator")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.Name != "operator" || len(got.Permissions) != 2 {
		t.Errorf("GetRole(operator) = %+v, want the upserted definition", got)
	}
	if got.BuiltIn {
		t.Error("a custom role must not be marked BuiltIn even if the caller sets it")
	}
}

func TestLocalStoreUpsertRole_CannotModifyAdmin(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	err := s.UpsertRole(t.Context(), store.RoleDefinition{Name: "admin", Permissions: nil})
	if err == nil {
		t.Error("UpsertRole should refuse to modify the built-in admin role")
	}
	// The built-in admin role's real permission set must be unaffected.
	role, getErr := s.GetRole(t.Context(), "admin")
	if getErr != nil {
		t.Fatalf("GetRole: %v", getErr)
	}
	if len(role.Permissions) != len(store.AllPermissions) {
		t.Errorf("admin role was mutated despite UpsertRole rejecting the write: got %d perms, want %d",
			len(role.Permissions), len(store.AllPermissions))
	}
}

func TestLocalStoreDeleteRole_CannotDeleteAdmin(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()

	if err := s.DeleteRole(t.Context(), "admin"); err == nil {
		t.Error("DeleteRole should refuse to delete the built-in admin role")
	}
}

func TestLocalStoreDeleteRole_CustomRole(t *testing.T) {
	s, _ := newLocalStore(t)
	defer s.Close()
	ctx := t.Context()

	def := store.RoleDefinition{Name: "operator", Permissions: []store.Permission{store.PermSessionsListOwn}}
	if err := s.UpsertRole(ctx, def); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	if err := s.DeleteRole(ctx, "operator"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	got, err := s.GetRole(ctx, "operator")
	if err != nil {
		t.Fatalf("GetRole after delete: %v", err)
	}
	if got.Name != "" {
		t.Errorf("role still present after DeleteRole: %+v", got)
	}
}

func TestLocalStoreRoles_PersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1, err := store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	def := store.RoleDefinition{Name: "operator", Permissions: []store.Permission{store.PermSessionsListOwn}}
	if err := s1.UpsertRole(t.Context(), def); err != nil {
		t.Fatalf("UpsertRole: %v", err)
	}
	s1.Close()

	s2, err := store.New(testStoreConfig(dir))
	if err != nil {
		t.Fatalf("New (reopen): %v", err)
	}
	defer s2.Close()
	got, err := s2.GetRole(t.Context(), "operator")
	if err != nil {
		t.Fatalf("GetRole after reopen: %v", err)
	}
	if got.Name != "operator" {
		t.Error("custom role did not persist across store reopen")
	}
}
