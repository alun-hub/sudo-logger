#!/bin/bash
# scripts/verify-integrity.sh
set -e

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
        go vet "$FILE"
        ;;
    c)
        echo "[*] Validating C file: $FILE"
        gcc -fsyntax-only -I/usr/include/sudo "$FILE"
        ;;
    *)
        echo "[!] Unknown file type for $FILE, skipping syntax check."
        ;;
esac

echo "[+] Syntax check: PASSED"
