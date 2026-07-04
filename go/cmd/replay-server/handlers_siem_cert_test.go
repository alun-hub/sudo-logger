package main

// Tests for the SIEM cert upload endpoint: containsPEMBlock and
// handleUploadSiemCert.

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── containsPEMBlock ──────────────────────────────────────────────────────────

func TestContainsPEMBlock_Valid(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	if !containsPEMBlock([]byte(pem)) {
		t.Error("valid-looking PEM block should be detected")
	}
}

func TestContainsPEMBlock_NoMarker(t *testing.T) {
	if containsPEMBlock([]byte("just some random bytes, not a cert")) {
		t.Error("data without a BEGIN marker should not be detected as PEM")
	}
}

// TestContainsPEMBlock_WeakValidationAcceptsGarbage documents a known gap:
// containsPEMBlock only checks for the literal "-----BEGIN " substring — it
// never checks for a matching END marker or calls pem.Decode, so a blob that
// merely contains the prefix (with garbage, or no END block at all) still
// passes. This is intentional documentation of current behavior, not a fix.
func TestContainsPEMBlock_WeakValidationAcceptsGarbage(t *testing.T) {
	garbage := "-----BEGIN CERTIFICATE-----\nthis is not valid base64/DER at all, no END marker"
	if !containsPEMBlock([]byte(garbage)) {
		t.Error("containsPEMBlock unexpectedly rejected a BEGIN-prefixed garbage blob (behavior changed)")
	}
}

// ── handleUploadSiemCert ──────────────────────────────────────────────────────

func multipartCertRequest(t *testing.T, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/siem-config/cert", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// withSiemConfigDir points flagSiemConfig at a file inside a fresh temp dir
// (handleUploadSiemCert writes certs next to it) and restores the original
// value on test cleanup.
func withSiemConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := *flagSiemConfig
	*flagSiemConfig = filepath.Join(dir, "siem.yaml")
	t.Cleanup(func() { *flagSiemConfig = orig })
	return dir
}

func withLocalStorage(t *testing.T) {
	t.Helper()
	orig := *flagStorage
	*flagStorage = "local"
	t.Cleanup(func() { *flagStorage = orig })
}

func TestHandleUploadSiemCert_DistributedModeNotImplemented(t *testing.T) {
	initTestStore(t)
	orig := *flagStorage
	*flagStorage = "distributed"
	t.Cleanup(func() { *flagStorage = orig })

	req := multipartCertRequest(t, "ca.pem", []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"))
	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("distributed mode: got %d, want 501", rr.Code)
	}
}

func TestHandleUploadSiemCert_Valid(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	dir := withSiemConfigDir(t)

	content := []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
	req := multipartCertRequest(t, "ca.pem", content)
	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("valid upload: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := filepath.Join(dir, "ca.pem")
	if resp["path"] != want {
		t.Errorf("response path = %q, want %q", resp["path"], want)
	}
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("uploaded cert not written to disk: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Error("written cert content does not match uploaded content")
	}
}

func TestHandleUploadSiemCert_InvalidFilename(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	withSiemConfigDir(t)

	// Path traversal filenames are covered separately below — filepath.Base
	// reduces them to a valid basename rather than rejecting them here.
	tests := []string{
		"cert.txt",       // wrong extension
		"has spaces.pem", // disallowed character
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			req := multipartCertRequest(t, name, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"))
			rr := httptest.NewRecorder()
			handleUploadSiemCert(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("filename %q: got %d, want 400", name, rr.Code)
			}
		})
	}
}

// TestHandleUploadSiemCert_PathTraversalFilenameIsBasenamed documents that a
// filename containing path separators is reduced to its base name before
// the regex check and the destDir containment check, so it cannot escape
// destDir — it just lands under a different (but still safe) plain name.
func TestHandleUploadSiemCert_PathTraversalFilenameIsBasenamed(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	dir := withSiemConfigDir(t)

	req := multipartCertRequest(t, "../../etc/passwd.pem", []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"))
	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (traversal filename should be basenamed, not rejected); body: %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "passwd.pem")); err != nil {
		t.Errorf("expected cert written as basenamed passwd.pem inside destDir: %v", err)
	}
}

func TestHandleUploadSiemCert_MissingPEMBlock(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	withSiemConfigDir(t)

	req := multipartCertRequest(t, "ca.pem", []byte("this is not a certificate at all"))
	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("non-PEM content: got %d, want 400", rr.Code)
	}
}

func TestHandleUploadSiemCert_MissingFileField(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	withSiemConfigDir(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("not_file", "irrelevant")
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/siem-config/cert", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing file field: got %d, want 400", rr.Code)
	}
}

func TestHandleUploadSiemCert_TooLarge(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	withSiemConfigDir(t)

	// One byte over the 64 KB limit; well under the outer MaxBytesReader
	// cap (maxSize+1024) once multipart framing overhead is added.
	huge := bytes.Repeat([]byte("a"), 64*1024+1)
	req := multipartCertRequest(t, "ca.pem", huge)
	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge && rr.Code != http.StatusBadRequest {
		t.Errorf("oversized file: got %d, want 413 or 400; body: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "-----BEGIN") {
		t.Error("oversized-file rejection response should not echo file content")
	}
}
func TestHandleUploadSiemCert_ForbiddenForNonAdmin(t *testing.T) {
	initTestStore(t)
	withLocalStorage(t)
	withSiemConfigDir(t)

	u := newUserWithPassword(t, "viewer-user", "Correct-Horse1!", RoleViewer)
	if err := sessionStore.UpsertUser(t.Context(), u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	content := []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
	req := multipartCertRequest(t, "ca.pem", content)

	perms := resolveRolePerms(req, RoleViewer)
	ctx := context.WithValue(req.Context(), ctxRole, RoleViewer)
	ctx = context.WithValue(ctx, ctxPermissions, perms)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("viewer without PermConfigWrite: got %d, want 403; body: %s", rr.Code, rr.Body.String())
	}
}
