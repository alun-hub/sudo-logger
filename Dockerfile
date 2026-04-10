# ---- Build stage ----
# Go 1.25+ required by go.mod.
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Copy the Go source tree (includes go/vendor — no network access needed).
COPY go/ .

# GOPROXY=off ensures the build fails immediately if anything tries to fetch
# a module from the internet. -mod=vendor uses the vendored dependencies.
ENV GOPROXY=off
RUN CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o /usr/local/bin/sudo-logserver ./cmd/server && \
    CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o /usr/local/bin/sudo-replay-server ./cmd/replay-server

# ---- Runtime stage ----
# distroless/static-debian12:nonroot contains only minimal binaries,
# certs, and a non-privileged user (UID 65532).
FROM gcr.io/distroless/static-debian12:nonroot

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
