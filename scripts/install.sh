#!/bin/bash
# scripts/install.sh — One-liner installer for sudo-logger client/server/replay.
set -euo pipefail

COMPONENT=${1:-client}

if [ "$COMPONENT" != "client" ] && [ "$COMPONENT" != "server" ] && [ "$COMPONENT" != "replay" ]; then
    echo "Usage: $0 [client|server|replay]"
    exit 1
fi

echo "==> Detecting system configuration..."
OS=""
if [ -f /etc/debian_version ]; then
    OS="deb"
elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
    OS="rpm"
else
    echo "❌ Unsupported OS. Only Debian/Ubuntu and RHEL/Fedora/Rocky Linux are supported."
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        # goreleaser names every package format (.deb and .rpm alike) after
        # the Go GOARCH value, not the traditional RPM x86_64/aarch64 arch
        # suffix — both must be "amd64"/"arm64" or the download 404s.
        ARCH_DEB="amd64"
        ARCH_RPM="amd64"
        ;;
    aarch64|arm64)
        ARCH_DEB="arm64"
        ARCH_RPM="arm64"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "==> Fetching latest release information from GitHub..."
REPO="alun-hub/sudo-logger"
RELEASE_JSON=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest")
TAG=$(echo "$RELEASE_JSON" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")

if [ -z "$TAG" ]; then
    # Fallback if API rate-limited or unavailable: extract tag via redirect header
    TAG=$(curl -sSLI -o /dev/null -w "%{url_effective}" "https://github.com/${REPO}/releases/latest" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo "")
fi

if [ -z "$TAG" ]; then
    echo "❌ Failed to fetch latest release version from GitHub."
    exit 1
fi

echo "Latest release: $TAG"

PKG_PART=""
case "$COMPONENT" in
    client) PKG_PART="client" ;;
    server) PKG_PART="server" ;;
    replay) PKG_PART="replay" ;;
esac

VERSION=${TAG#v} # strip leading 'v'
FILENAME=""
if [ "$OS" = "deb" ]; then
    FILENAME="sudo-logger-${PKG_PART}_${VERSION}_linux_${ARCH_DEB}.deb"
else
    FILENAME="sudo-logger-${PKG_PART}_${VERSION}_linux_${ARCH_RPM}.rpm"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${FILENAME}"
SIG_URL="${DOWNLOAD_URL}.sig"
CERT_URL="${DOWNLOAD_URL}.pem"

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "==> Downloading package..."
curl -sSL -o "${TEMP_DIR}/${FILENAME}" "$DOWNLOAD_URL"

echo "==> Verifying signature..."
if command -v cosign >/dev/null 2>&1; then
    curl -sSL -o "${TEMP_DIR}/${FILENAME}.sig" "$SIG_URL"
    curl -sSL -o "${TEMP_DIR}/${FILENAME}.pem" "$CERT_URL"
    if cosign verify-blob \
        --signature "${TEMP_DIR}/${FILENAME}.sig" \
        --certificate "${TEMP_DIR}/${FILENAME}.pem" \
        --certificate-identity-regexp "https://github.com/alun-hub/sudo-logger/.*" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${TEMP_DIR}/${FILENAME}" >/dev/null 2>&1; then
        echo "✅ Signature verified successfully via Sigstore/cosign!"
    else
        echo "❌ Cosign signature verification failed!"
        exit 1
    fi
else
    echo "⚠️ cosign is not installed. Skipping signature verification."
    echo "   To verify releases, install cosign (https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign) and re-run."
fi

echo "==> Installing package..."
if [ "$OS" = "deb" ]; then
    sudo dpkg -i "${TEMP_DIR}/${FILENAME}" || sudo apt-get install -f -y
else
    if command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y "${TEMP_DIR}/${FILENAME}"
    else
        sudo yum install -y "${TEMP_DIR}/${FILENAME}"
    fi
fi

echo "🎉 Installation of sudo-logger-${PKG_PART} completed successfully!"
if [ "$COMPONENT" = "client" ]; then
    echo "Next steps:"
    echo "  1. Configure /etc/sudo-logger/agent.conf with your server address."
    echo "  2. Restart the agent: sudo systemctl restart sudo-logger-agent"
elif [ "$COMPONENT" = "server" ]; then
    echo "Next steps:"
    echo "  1. Configure /etc/sudo-logger/server.conf."
    echo "  2. Copy /etc/sudo-logger/ack-verify.key to all client machines."
    echo "  3. Start the server: sudo systemctl enable --now sudo-logserver"
elif [ "$COMPONENT" = "replay" ]; then
    echo "Next steps:"
    echo "  1. Access the web interface on http://localhost:8080."
    echo "  2. Start the replay server: sudo systemctl enable --now sudo-replay"
fi
