package store

// Test infrastructure for DistributedStore: a real ephemeral Postgres via
// testcontainers-go (skips cleanly if no container runtime is reachable),
// and a minimal in-process fake S3 server (PutObject, GetObject,
// ListObjectsV2, DeleteObjects) built on httptest — buildS3Client already
// supports MinIO-style custom endpoints via BaseEndpoint+UsePathStyle, so no
// S3-mock dependency is needed.

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// ── Postgres testcontainer ────────────────────────────────────────────────────

// podmanDockerHost points testcontainers-go's Docker client at the local
// rootless podman API socket (started out-of-band via
// `systemctl --user start podman.socket`), matching how this project's own
// container images are built (podman, per scripts/rebuild-*.sh).
func podmanDockerHost() string {
	return fmt.Sprintf("unix:///run/user/%d/podman/podman.sock", os.Getuid())
}

// dockerHostOverride returns the DOCKER_HOST value to use, or "" to leave
// testcontainers-go's own auto-detection alone. Dev machines here only run
// rootless podman (no standard docker daemon), so we point at its socket —
// but CI runners (and most normal dev setups) have a real Docker daemon at
// the standard location, which testcontainers-go finds on its own and which
// this override must not shadow.
func dockerHostOverride() string {
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return ""
	}
	if _, err := os.Stat(fmt.Sprintf("/run/user/%d/podman/podman.sock", os.Getuid())); err == nil {
		return podmanDockerHost()
	}
	return ""
}

// newTestPostgresDSN starts an ephemeral Postgres container and returns a
// connection string. Skips the test (not fails) when no container runtime
// is reachable, so `go test ./...` stays green on machines without Docker
// or Podman.
func newTestPostgresDSN(t *testing.T) string {
	t.Helper()
	if host := dockerHostOverride(); host != "" {
		t.Setenv("DOCKER_HOST", host)
	}
	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ctr, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("sudologger_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"), // pragma: allowlist secret
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("container runtime not available (start it with `systemctl --user start podman.socket`): %v", err)
	}
	t.Cleanup(func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tcancel()
		if err := ctr.Terminate(tctx); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}
	return dsn
}

// ── Fake S3 server ────────────────────────────────────────────────────────────

type fakeS3Object struct {
	data []byte
}

// fakeS3Server is a minimal path-style S3 implementation covering exactly
// the operations distributed.go uses: PutObject, GetObject, ListObjectsV2,
// and DeleteObjects (batch delete via POST ?delete).
type fakeS3Server struct {
	mu      sync.Mutex
	objects map[string]fakeS3Object // key: "bucket/key"
	srv     *httptest.Server
}

func newFakeS3Server(t *testing.T) *fakeS3Server {
	t.Helper()
	f := &fakeS3Server{objects: make(map[string]fakeS3Object)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3Server) url() string { return f.srv.URL }

func (f *fakeS3Server) handle(w http.ResponseWriter, r *http.Request) {
	// Path-style: /<bucket>/<key...>
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]

	// DeleteObjects: POST /<bucket>?delete
	if r.Method == http.MethodPost && r.URL.Query().Has("delete") {
		f.handleDeleteObjects(w, r, bucket)
		return
	}
	// ListObjectsV2: GET /<bucket>?list-type=2&prefix=...
	if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
		f.handleListObjectsV2(w, r, bucket)
		return
	}
	if len(parts) < 2 || parts[1] == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	key := parts[1]
	objKey := bucket + "/" + key

	switch r.Method {
	case http.MethodPut:
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.objects[objKey] = fakeS3Object{data: data}
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		f.mu.Lock()
		obj, ok := f.objects[objKey]
		f.mu.Unlock()
		if !ok {
			f.writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(obj.data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(obj.data)

	case http.MethodDelete:
		f.mu.Lock()
		delete(f.objects, objKey)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case http.MethodHead:
		f.mu.Lock()
		obj, ok := f.objects[objKey]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(obj.data)))
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not supported by fake S3", http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3Server) writeS3Error(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, message)
}

type listBucketResult struct {
	XMLName  xml.Name           `xml:"ListBucketResult"`
	Name     string             `xml:"Name"`
	Prefix   string             `xml:"Prefix"`
	KeyCount int                `xml:"KeyCount"`
	MaxKeys  int                `xml:"MaxKeys"`
	Contents []listBucketObject `xml:"Contents"`
}

type listBucketObject struct {
	Key  string `xml:"Key"`
	Size int    `xml:"Size"`
}

func (f *fakeS3Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	f.mu.Lock()
	var contents []listBucketObject
	for objKey, obj := range f.objects {
		b, key, ok := strings.Cut(objKey, "/")
		if !ok || b != bucket || !strings.HasPrefix(key, prefix) {
			continue
		}
		contents = append(contents, listBucketObject{Key: key, Size: len(obj.data)})
	}
	f.mu.Unlock()

	result := listBucketResult{
		Name:     bucket,
		Prefix:   prefix,
		KeyCount: len(contents),
		MaxKeys:  1000,
		Contents: contents,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(result)
}

type deleteObjectsRequest struct {
	XMLName xml.Name             `xml:"Delete"`
	Objects []deleteObjectsEntry `xml:"Object"`
}

type deleteObjectsEntry struct {
	Key string `xml:"Key"`
}

func (f *fakeS3Server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var req deleteObjectsRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	for _, obj := range req.Objects {
		delete(f.objects, bucket+"/"+obj.Key)
	}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>`)
}

func (f *fakeS3Server) has(bucket, key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[bucket+"/"+key]
	return ok
}

// ── Combined DistributedStore fixture ─────────────────────────────────────────

// newDistributedTestStore builds a real *DistributedStore against an
// ephemeral Postgres container and the fake S3 server. Skips cleanly if no
// container runtime is reachable.
func newDistributedTestStore(t *testing.T) (*DistributedStore, *fakeS3Server) {
	t.Helper()
	dsn := newTestPostgresDSN(t)
	fakeS3 := newFakeS3Server(t)

	cfg := Config{
		Backend:     "distributed",
		DBURL:       dsn,
		S3Bucket:    "test-bucket",
		S3Endpoint:  fakeS3.url(),
		S3PathStyle: true,
		S3AccessKey: "test-access-key",
		S3SecretKey: "test-secret-key", // pragma: allowlist secret
		S3Prefix:    "sessions/",
		BufferDir:   t.TempDir(),
	}
	d, err := newDistributedStore(cfg)
	if err != nil {
		t.Fatalf("newDistributedStore: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d, fakeS3
}
