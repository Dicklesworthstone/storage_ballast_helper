#!/usr/bin/env bash
# SBH Setup Validation Script
# Checks that sbh is properly configured and ready to use

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((ERRORS++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }

echo "SBH Setup Validation"
echo "====================="
echo

# 1. Check binary
echo "Binary:"

if command -v sbh &>/dev/null; then
    pass "sbh binary found: $(which sbh)"
    SBH_VERSION=$(sbh version 2>/dev/null || echo "unknown")
    pass "Version: $SBH_VERSION"
else
    fail "sbh binary not found in PATH"
fi

echo

# 2. Check configuration
echo "Configuration:"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sbh"
CONFIG_FILE="$CONFIG_DIR/config.toml"

if [ -d "$CONFIG_DIR" ]; then
    pass "Config directory exists: $CONFIG_DIR"
else
    fail "Config directory missing: $CONFIG_DIR"
fi

if [ -f "$CONFIG_FILE" ]; then
    pass "Config file exists: $CONFIG_FILE"
    if command -v sbh &>/dev/null; then
        if sbh config validate &>/dev/null; then
            pass "Config validates successfully"
        else
            fail "Config validation failed (run: sbh config validate)"
        fi
    fi
else
    warn "Config file missing (sbh will use defaults): $CONFIG_FILE"
fi

echo

# 3. Check data directory
echo "Data Directory:"

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sbh"

if [ -d "$DATA_DIR" ]; then
    pass "Data directory exists: $DATA_DIR"
else
    warn "Data directory missing (created on first run): $DATA_DIR"
fi

if [ -d "$DATA_DIR/ballast" ]; then
    BALLAST_COUNT=$(find "$DATA_DIR/ballast" -name 'SBH_BALLAST_FILE_*.dat' 2>/dev/null | wc -l)
    if [ "$BALLAST_COUNT" -gt 0 ]; then
        pass "Found $BALLAST_COUNT ballast file(s)"
    else
        warn "No ballast files provisioned (run: sbh ballast provision)"
    fi
else
    warn "Ballast directory missing (run: sbh ballast provision)"
fi

echo

# 4. Check daemon
echo "Daemon:"

if pgrep -x sbh &>/dev/null; then
    pass "sbh daemon process running (PID: $(pgrep -x sbh | head -1))"
elif systemctl --user is-active sbh &>/dev/null 2>&1; then
    pass "sbh running via systemd (user)"
elif sudo systemctl is-active sbh &>/dev/null 2>&1; then
    pass "sbh running via systemd (system)"
else
    warn "sbh daemon not running"
fi

echo

# 5. Check disk pressure
echo "Disk Pressure:"

if command -v sbh &>/dev/null; then
    if sbh check &>/dev/null 2>&1; then
        pass "Disk pressure is healthy"
    else
        warn "Disk pressure detected (run: sbh status)"
    fi
fi

echo

# 6. Check for multiple binaries
echo "Binary Conflicts:"

if command -v sbh &>/dev/null; then
    BINARY_COUNT=$(which -a sbh 2>/dev/null | sort -u | wc -l)
    if [ "$BINARY_COUNT" -gt 1 ]; then
        fail "Multiple sbh binaries found:"
        which -a sbh 2>/dev/null | sort -u | while read -r p; do
            echo "      $p"
        done
    else
        pass "Single sbh binary on PATH"
    fi
fi

echo

# 7. Summary
echo "====================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All checks passed! SBH is ready.${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}$WARNINGS warning(s), no errors. SBH may work with limitations.${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS error(s), $WARNINGS warning(s). Fix errors before using SBH.${NC}"
    exit 1
fi
