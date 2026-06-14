.PHONY: all replay-server ui-build server

all: replay-server server

ui-build:
	cd cmd/replay-server/ui && npm ci --prefer-offline && npm run build

replay-server: ui-build
	go build -o cmd/replay-server/replay-server ./cmd/replay-server/

server:
	go build -o cmd/server/server ./cmd/server/
