#!/bin/bash
set -e

PACKAGE_TYPE=$1

if [[ -z "$PACKAGE_TYPE" ]]; then
    echo "Usage: $0 <client|server|replay>"
    exit 1
fi

SPEC_FILE=""
case $PACKAGE_TYPE in
    client) SPEC_FILE="rpm/sudo-logger-client.spec" ;;
    server) SPEC_FILE="rpm/sudo-logger-server.spec" ;;
    replay) SPEC_FILE="rpm/sudo-logger-replay.spec" ;;
    *) echo "Invalid package type. Use client, server, or replay."; exit 1 ;;
esac

if [[ ! -f "$SPEC_FILE" ]]; then
    echo "Error: Spec file $SPEC_FILE not found."
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "WARNING: You have uncommitted changes. These will NOT be included in the RPM."
    echo "Continue anyway? (y/n)"
    read -r response
    if [[ "$response" != "y" ]]; then
        exit 1
    fi
fi

# Extract version from spec file
VERSION=$(grep "^Version:" "$SPEC_FILE" | awk '{print $2}')
echo "Building $PACKAGE_TYPE version $VERSION..."

# Create rpmbuild tree if missing
rpmdev-setuptree || mkdir -p ~/rpmbuild/{SOURCES,SPECS,RPMS,SRPMS,BUILD}

# Create archive
OUT_TAR=~/rpmbuild/SOURCES/sudo-logger-${VERSION}.tar.gz
echo "Creating archive: $OUT_TAR"
git archive --format=tar.gz --prefix=sudo-logger-${VERSION}/ HEAD > "$OUT_TAR"

# Build RPM
echo "Running rpmbuild..."
rpmbuild -ba "$SPEC_FILE"

echo "Success! RPMs generated in ~/rpmbuild/RPMS/x86_64/"
ls -lh ~/rpmbuild/RPMS/x86_64/sudo-logger-${PACKAGE_TYPE}-*.rpm
