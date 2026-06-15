# sudo-logger build targets
#
# Typical first-time setup on Fedora:
#   sudo dnf install clang llvm libbpf-devel bpftool linux-headers-$(uname -r)
#   make vmlinux-agent
#   make generate-agent
#   make agent

GOPATH  ?= $(shell go env GOPATH)
KERNEL  ?= $(shell uname -r)
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/')

.PHONY: all agent vmlinux-agent generate-agent tidy test clean docs-site docs-manual

all: agent

# ── sudo-logger-agent (plugin handler + eBPF recorder) ──────────────────────

vmlinux-agent: go/cmd/agent/bpf/vmlinux.h

go/cmd/agent/bpf/vmlinux.h: /sys/kernel/btf/vmlinux
	bpftool btf dump file $< format c > $@
	@echo "vmlinux.h generated for kernel $(KERNEL)"

generate-agent: go/cmd/agent/bpf/vmlinux.h
	cd go && go generate ./cmd/agent/

agent: generate-agent
	cd go && go build -o ../bin/sudo-logger-agent ./cmd/agent/

# ── Common ────────────────────────────────────────────────────────────────────

tidy:
	cd go && go mod tidy

test:
	cd go && go test ./...

clean:
	rm -f go/cmd/agent/recorder_bpf*.go
	rm -f go/cmd/agent/recorder_bpf*.o
	rm -f go/cmd/agent/bpf/vmlinux.h
	rm -f bin/sudo-logger-agent

# ── Documentation ─────────────────────────────────────────────────────────────

# Full MkDocs site → docs/site/
docs-site:
	mkdocs build

# Single-page manual for replay-server UI → docs/manual.html
# Also copies to the embedded static path so it is included in the next build.
CHAPTERS := $(wildcard docs/chapters/*.md)

docs-manual:
	pandoc $(CHAPTERS) \
	  --from markdown \
	  --to html5 \
	  --standalone \
	  --toc \
	  --toc-depth=3 \
	  --metadata title="sudo-logger Documentation" \
	  --css=manual.css \
	  -o docs/manual.html
	cp docs/manual.html go/cmd/replay-server/ui/public/docs/manual.html
	cp docs/manual.html go/cmd/replay-server/static/docs/manual.html
	@echo "Built docs/manual.html and copied to replay-server"
