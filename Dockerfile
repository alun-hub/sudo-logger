# ---- Build stage ----
# Updated to Go 1.24 for latest performance and security fixes.
FROM golang:1.24-alpine AS builder
WORKDIR /src

# Copy only the Go source tree.
COPY go/ .

# Build all binaries with CGO_ENABLED=0 to ensure they are fully static
# and compatible with the distroless runtime (no musl/glibc dependencies).
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/sudo-logserver ./cmd/server && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/sudo-replay-server ./cmd/replay-server

# ---- Runtime stage ----
# distroless/static-debian12:nonroot contains only minimal binaries, 
# certs, and a non-privileged user (UID 65532).
FROM gcr.io/distroless/static-debian12:nonroot

# Copy both server binaries to the runtime image.
COPY --from=builder /usr/local/bin/sudo-logserver /usr/local/bin/sudo-logserver
COPY --from=builder /usr/local/bin/sudo-replay-server /usr/local/bin/sudo-replay-server

# Expose both the logserver (9876) and replay-server (8080) ports.
EXPOSE 9876 8080

# Default entrypoint remains the logserver.
ENTRYPOINT ["/usr/local/bin/sudo-logserver"]
CMD ["-listen=:9876", \
     "-logdir=/var/log/sudoreplay", \
     "-cert=/etc/sudo-logger/server.crt", \
     "-key=/etc/sudo-logger/server.key", \
     "-ca=/etc/sudo-logger/ca.crt", \
     "-hmackey=/etc/sudo-logger/hmac.key"]
