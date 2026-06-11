# Task 06: Go Integration, Cleanup & RPM Build

## Context
The React/TS SPA is complete (Tasks 01–05). This task:
1. Adds an SPA fallback in the Go server so client-side routes work
2. Updates the Makefile to build the UI before compiling Go
3. Removes the old vanilla JS files (index.html + vendor/)
4. Verifies the full build produces a working binary with embedded assets
5. Rebuilds the RPM

## Working directory
`/home/alun/sudo-logger`

---

## Step 1: Build the UI

```bash
cd go/cmd/replay-server/ui
npm ci
npm run build
```

This writes files to `go/cmd/replay-server/static/`. Verify:

```bash
ls go/cmd/replay-server/static/
# → index.html  assets/
```

---

## Step 2: Add SPA fallback to main.go

**File:** `go/cmd/replay-server/main.go`

The current code at ~line 1446–1450 is:

```go
staticFS, err := fs.Sub(staticFiles, "static")
if err != nil {
    log.Fatalf("embed static: %v", err)
}
mux.Handle("/", http.FileServer(http.FS(staticFS)))
```

Replace those last two lines with:

```go
staticFS, err := fs.Sub(staticFiles, "static")
if err != nil {
    log.Fatalf("embed static: %v", err)
}
fileServer := http.FileServer(http.FS(staticFS))
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // Let the file server handle real static assets (JS, CSS, images).
    // For all other non-API paths, serve index.html so React Router works.
    if _, statErr := fs.Stat(staticFS, strings.TrimPrefix(r.URL.Path, "/")); statErr == nil {
        fileServer.ServeHTTP(w, r)
        return
    }
    idx, _ := staticFS.Open("index.html")
    defer idx.Close()
    http.ServeContent(w, r, "index.html", time.Time{}, idx.(io.ReadSeeker))
})
```

Add these imports if not already present (check the existing import block):
- `"io"`
- `"io/fs"`
- `"time"`

These are almost certainly already imported. Verify with:

```bash
grep -n '"io"' go/cmd/replay-server/main.go
grep -n '"io/fs"' go/cmd/replay-server/main.go
grep -n '"time"' go/cmd/replay-server/main.go
```

---

## Step 3: Update Makefile

**File:** `go/Makefile`

Find the `replay-server` build target (search for `replay-server` or
`cmd/replay-server`). Add a `ui-build` target and make `replay-server`
depend on it.

Add this block **before** the existing `replay-server` target:

```makefile
.PHONY: ui-build
ui-build:
	cd cmd/replay-server/ui && npm ci --prefer-offline && npm run build
```

Then change the existing `replay-server` target to depend on `ui-build`.
Example — if it currently looks like:

```makefile
replay-server:
	go build -o cmd/replay-server/replay-server ./cmd/replay-server/
```

Change to:

```makefile
replay-server: ui-build
	go build -o cmd/replay-server/replay-server ./cmd/replay-server/
```

---

## Step 4: Remove old static files

**Only run this after `npm run build` has succeeded and `static/index.html`
contains the Vite-built output (check for `<div id="root">`).**

```bash
# Confirm new build is in place
grep -c 'id="root"' go/cmd/replay-server/static/index.html
# → should print 1

# Remove old vendor directory
rm -rf go/cmd/replay-server/static/vendor/

# The old index.html was replaced by the Vite build, nothing more to delete.
```

---

## Step 5: Verify Go build

```bash
cd go
make replay-server

# Binary should exist
ls -lh cmd/replay-server/replay-server
```

Start the server and smoke-test:

```bash
# Requires a running log-server or use --db-dsn pointing to an existing DB
./cmd/replay-server/replay-server --listen :8080 --db-dsn <your-dsn>

# In another terminal:
curl -s http://localhost:8080/healthz     # → ok
curl -s http://localhost:8080/            # → HTML with id="root"
curl -s http://localhost:8080/reports     # → HTML with id="root" (SPA fallback)
curl -s http://localhost:8080/api/sessions | head -c 100  # → JSON
```

---

## Step 6: Run pre-commit

```bash
cd /home/alun/sudo-logger
pre-commit run --all-files
```

Fix any HIGH/CRITICAL findings before proceeding.

---

## Step 7: Commit

Stage the UI source and the modified Go files (not the built static/ assets —
they are generated):

```bash
git add go/cmd/replay-server/ui/
git add go/cmd/replay-server/main.go
git add go/Makefile
# Do NOT git add go/cmd/replay-server/static/ (generated)
git status
git commit -m "feat(ui): migrate replay-server SPA to React + TypeScript"
```

Add `go/cmd/replay-server/static/` to `.gitignore` if it isn't already:

```bash
grep 'replay-server/static' .gitignore || echo 'go/cmd/replay-server/static/' >> .gitignore
```

---

## Step 8: Build RPM

```bash
/rpm-builder replay
```

Then on the target host (gnarg):

```bash
sudo dnf install <rpm-path>
sudo systemctl restart sudo-logger-replay
```

---

## Verification checklist

- [ ] `npm run build` succeeds, writes `static/index.html`
- [ ] `go build ./cmd/replay-server/` succeeds
- [ ] `GET /` returns HTML with `id="root"`
- [ ] `GET /reports` returns same HTML (SPA fallback)
- [ ] `GET /api/sessions` returns JSON
- [ ] `GET /assets/index-*.js` returns 200 (static asset)
- [ ] Terminal replay works in browser (session with `has_io=true`)
- [ ] `pre-commit run --all-files` passes
- [ ] RPM built and deployed to gnarg
