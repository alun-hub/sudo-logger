package main

// Size-boundary tests for the SIEM certificate upload. The handler must write
// what it received, byte for byte, or refuse the upload outright — a silently
// truncated certificate or key in /etc/sudo-logger would break SIEM delivery
// with no indication of why.

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func uploadCert(t *testing.T, dir string, payload []byte) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "probe.crt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}

	req := adminReq(http.MethodPost, "/api/siem-cert", "")
	req.Body = httptest.NewRequest(http.MethodPost, "/", &body).Body
	req.Header.Set("Content-Type", mw.FormDataContentType())

	rr := httptest.NewRecorder()
	handleUploadSiemCert(rr, req)
	return rr, filepath.Join(dir, "probe.crt")
}

func certPayload(bodyLen int) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" +
		string(bytes.Repeat([]byte("A"), bodyLen)) + "\n-----END CERTIFICATE-----\n")
}

func TestUploadSiemCert_WritesExactlyWhatWasSent(t *testing.T) {
	initTestStore(t)
	dir := t.TempDir()
	restoreSiemCertFlags(t, dir)

	for _, bodyLen := range []int{1024, 32 * 1024, 60 * 1024} {
		payload := certPayload(bodyLen)
		rr, dest := uploadCert(t, dir, payload)
		if rr.Code != http.StatusOK {
			t.Fatalf("body %d: status %d, want 200 (%s)", bodyLen, rr.Code, rr.Body.String())
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("body %d: reading written cert: %v", bodyLen, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("body %d: wrote %d bytes, sent %d — certificate was truncated",
				bodyLen, len(got), len(payload))
		}
		if err := os.Remove(dest); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
	}
}

func TestUploadSiemCert_RefusesOversizeInsteadOfTruncating(t *testing.T) {
	initTestStore(t)
	dir := t.TempDir()
	restoreSiemCertFlags(t, dir)

	rr, dest := uploadCert(t, dir, certPayload(70*1024))
	if rr.Code == http.StatusOK {
		t.Errorf("oversize upload accepted with status 200")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("a rejected upload still wrote %s", dest)
	}
}

func restoreSiemCertFlags(t *testing.T, dir string) {
	t.Helper()
	oldCfg := *flagSiemConfig
	*flagSiemConfig = filepath.Join(dir, "siem.yaml")
	oldStorage := *flagStorage
	*flagStorage = "local"
	t.Cleanup(func() {
		*flagSiemConfig = oldCfg
		*flagStorage = oldStorage
	})
}
