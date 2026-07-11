# ---- UI Build stage ----
FROM node:22-alpine AS ui-builder
WORKDIR /src/ui
# Copy UI package files and install dependencies
COPY go/cmd/replay-server/ui/package*.json ./
RUN npm ci --prefer-offline
# Copy UI source and build
COPY go/cmd/replay-server/ui/ ./
RUN npm run build

# ---- Go Build stage ----
# Go 1.25+ required by go.mod.
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Copy the Go source tree (includes go/vendor — no network access needed).
COPY go/ .

# Copy the built UI assets from the ui-builder stage
COPY --from=ui-builder /src/static ./cmd/replay-server/static

# GOPROXY=off ensures the build fails immediately if anything tries to fetch
# a module from the internet. -mod=vendor uses the vendored dependencies.
ENV GOPROXY=off
RUN CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o /usr/local/bin/sudo-logserver ./cmd/server && \
    CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o /usr/local/bin/sudo-replay-server ./cmd/replay-server

# ---- Runtime stage ----
# Use debian:12-slim to provide a shell and package manager (needed for sudo/visudo).
FROM debian:12-slim

# Install sudo (for visudo validation), ca-certificates (for S3 TLS), and
# wget (used by the HEALTHCHECK commands in docker-compose.yaml).
RUN apt-get update && \
    apt-get install -y --no-install-recommends sudo ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

# Create a nonroot user (UID 65532) to match distroless behavior.
RUN groupadd -g 65532 nonroot && \
    useradd -u 65532 -g nonroot -s /sbin/nologin nonroot

USER nonroot:nonroot

# Copy both server binaries to the runtime image.
COPY --from=builder /usr/local/bin/sudo-logserver /usr/local/bin/sudo-logserver
COPY --from=builder /usr/local/bin/sudo-replay-server /usr/local/bin/sudo-replay-server

# Bundle the default risk-scoring rules so the replay-server starts
# without requiring an external mount.  Override by mounting a volume
# at /etc/sudo-logger or by passing a different -rules path.
# Note: the file is owned by root inside the image.  To allow the
# Settings UI to save rule changes, mount a writable volume at
# /etc/sudo-logger (see docker-compose.yaml).
COPY go/cmd/replay-server/risk-rules.yaml /etc/sudo-logger/risk-rules.yaml

# Expose both the logserver (9876) and replay-server (8080) ports.
EXPOSE 9876 8080

# Default entrypoint remains the logserver.
ENTRYPOINT ["/usr/local/bin/sudo-logserver"]
CMD ["-listen=:9876", \
     "-logdir=/var/log/sudoreplay", \
     "-cert=/etc/sudo-logger/server.crt", \
     "-key=/etc/sudo-logger/server.key", \
     "-ca=/etc/sudo-logger/ca.crt", \
     "-signkey=/etc/sudo-logger/ack-sign.key"]
