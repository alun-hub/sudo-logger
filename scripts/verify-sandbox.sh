#!/bin/bash
# scripts/verify-sandbox.sh — SAFE Verify sudo-logger sandbox enforcement

# SAFETY CHECK: Verify we are in a sandboxed cgroup.
MY_CG=$(cat /proc/self/cgroup | cut -d: -f3)
if [ "$MY_CG" != "/" ] && ! echo "$MY_CG" | grep -q "sudo-logger"; then
    echo -e "\e[31mERROR: This script must ONLY be run inside a sandboxed sudo-logger session.\e[0m"
    echo -e "Current Cgroup: $MY_CG"
    echo -e "Usage: sudo ./scripts/verify-sandbox.sh"
    exit 1
fi

BACKUP_DIR="/tmp/sandbox_recovery_$(date +%s)"
FILES_TO_TEST=("/etc/sudoers" "/etc/passwd" "/etc/shadow" "/etc/sudo-logger/agent.conf")

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

echo -e "${BLUE}=== sudo-logger Sandbox Verification (SAFE MODE) ===${NC}"
echo -e "Status: Sandboxed Session Detected (Cgroup: $MY_CG)"

# 1. CREATE BACKUPS
echo -n "Creating safety backups in $BACKUP_DIR... "
mkdir -p "$BACKUP_DIR"
for f in "${FILES_TO_TEST[@]}"; do
    if [ -f "$f" ]; then
        cp -a "$f" "$BACKUP_DIR/"
    fi
done
echo -e "${GREEN}DONE${NC}"

echo "----------------------------------------"
echo -e "${YELLOW}RESTORATION COMMAND (Run as plain root if tests fail):${NC}"
echo -e "  cp -a $BACKUP_DIR/* /etc/ && rm -rf $BACKUP_DIR"
echo "----------------------------------------"

TOTAL=0
PASSED=0

assert_blocked() {
    local cmd="$1"
    local desc="$2"
    ((TOTAL++))

    echo -n "Testing: $desc... "
    ERR=$(eval "$cmd" 2>&1)
    if [[ "$ERR" == *"Operation not permitted"* ]]; then
        echo -e "${GREEN}PASSED (Blocked)${NC}"
        ((PASSED++))
    else
        echo -e "${RED}FAILED (Allowed!)${NC}"
        echo -e "  Output: $ERR"
        echo -e "${RED}STOPPING TESTS IMMEDIATELY TO PROTECT SYSTEM.${NC}"
        echo -e "${YELLOW}Please restore your system now using the command above.${NC}"
        exit 1
    fi
}

# 2. PERFORM TESTS
# Write tests
assert_blocked "echo '#sandbox_test' >> /etc/sudoers" "Append to /etc/sudoers"
assert_blocked "echo 'nameserver 8.8.8.8' > /etc/passwd" "Overwrite /etc/passwd"

# Deletion tests
assert_blocked "rm -f /etc/sudo-logger/agent.conf" "Delete /etc/sudo-logger/agent.conf"
assert_blocked "rm -f /etc/shadow" "Delete /etc/shadow"

# Directory creation tests
assert_blocked "touch /etc/sudo-logger/test_canary" "Create file in /etc/sudo-logger/"
assert_blocked "mkdir /etc/pam.d/test_canary_dir" "Create dir in /etc/pam.d/"

# Rename tests
touch /tmp/evil_file
assert_blocked "mv /tmp/evil_file /etc/sudoers" "Rename onto /etc/sudoers"
rm -f /tmp/evil_file

# Process protection
# Look for REAL auditd, avoiding kernel threads
REAL_AUDIT_PID=$(pgrep -x auditd | head -n 1)
if [ -n "$REAL_AUDIT_PID" ]; then
    assert_blocked "kill -9 $REAL_AUDIT_PID" "SIGKILL to real auditd (PID $REAL_AUDIT_PID)"
else
    echo -e "Testing: Kill auditd... ${YELLOW}SKIPPED (no real auditd found)${NC}"
fi

# Try to kill the agent
AGENT_PID=$(pgrep -f sudo-logger-age | head -n 1)
if [ -n "$AGENT_PID" ]; then
    assert_blocked "kill -TERM $AGENT_PID" "SIGTERM to sudo-logger-agent (PID $AGENT_PID)"
fi

echo "----------------------------------------"
echo -e "${GREEN}SUMMARY: $PASSED/$TOTAL tests passed. Sandbox is ROBUST.${NC}"
echo -e "You can now safely remove the backup: rm -rf $BACKUP_DIR"
