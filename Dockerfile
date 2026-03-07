# ---- Build stage ----
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go/ .
RUN go build -ldflags="-s -w" -o /sudo-logserver ./cmd/server

# ---- Runtime stage ----
# distroless/nonroot: no shell, no package manager, UID=65532
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /sudo-logserver /usr/local/bin/sudo-logserver

EXPOSE 9876

ENTRYPOINT ["/usr/local/bin/sudo-logserver"]
CMD ["-listen=:9876", \
     "-logdir=/var/log/sudoreplay", \
     "-cert=/etc/sudo-logger/server.crt", \
     "-key=/etc/sudo-logger/server.key", \
     "-ca=/etc/sudo-logger/ca.crt", \
     "-hmackey=/etc/sudo-logger/hmac.key"]
