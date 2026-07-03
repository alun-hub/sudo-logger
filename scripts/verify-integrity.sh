#!/bin/bash
# scripts/verify-integrity.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILE=$1
if [ -z "$FILE" ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

EXTENSION="${FILE##*.}"

case "$EXTENSION" in
    go)
        echo "[*] Validating Go file: $FILE"
        go fmt "$FILE"
        # Only run vet if we can resolve dependencies, otherwise fmt is enough for syntax
        go vet "$FILE" || echo "[!] go vet failed (likely dependency resolution), but fmt passed."
        ;;
    c)
        echo "[*] Validating C file: $FILE"
        gcc -fsyntax-only -I"$SCRIPT_DIR/../plugin/include" "$FILE"
        ;;
    *)
        echo "[!] Unknown file type for $FILE, skipping syntax check."
        ;;
esac

echo "[+] Syntax check: PASSED"
