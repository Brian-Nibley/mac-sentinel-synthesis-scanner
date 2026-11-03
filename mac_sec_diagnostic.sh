#!/usr/bin/env bash
# mac_sec_diagnostic.sh — preflight permission check for Mac Sentinel Synthesis Scanner.
#
# Read-only. Makes no changes, needs no sudo, and sends nothing over the network.
# Run this BEFORE `mac_sentinel_synthesis_scanner.py report` to see which of macOS's
# privacy permissions (TCC) are already granted to whatever app you're running this
# from (Terminal, iTerm2, etc.), and which ones you'd need to grant for every report
# module to come back "ok" instead of "partial".
#
# Usage: bash mac_sec_diagnostic.sh

PASS=0
WARN=0
FAIL=0

status() {
  # status <PASS|WARN|FAIL|INFO> "<message>" ["<fix hint>"]
  local kind="$1" msg="$2" hint="${3:-}"
  case "$kind" in
    PASS) printf "  [ OK ]  %s\n" "$msg"; PASS=$((PASS + 1)) ;;
    WARN) printf "  [WARN]  %s\n" "$msg"; [ -n "$hint" ] && printf "          -> %s\n" "$hint"; WARN=$((WARN + 1)) ;;
    FAIL) printf "  [FAIL]  %s\n" "$msg"; [ -n "$hint" ] && printf "          -> %s\n" "$hint"; FAIL=$((FAIL + 1)) ;;
    INFO) printf "  [INFO]  %s\n" "$msg" ;;
  esac
}

section() { printf "\n%s\n" "$1"; }

echo "Mac Sentinel Synthesis Scanner — permission check"
echo "=================================================="

section "Platform"
if [ "$(uname -s)" = "Darwin" ]; then
  status PASS "Running on macOS ($(sw_vers -productVersion 2>/dev/null || echo unknown))"
else
  status FAIL "Not macOS — the scanner's collectors only run on macOS" "Use the 'demo' command to preview the dashboard on other platforms"
fi

section "Python"
if command -v python3 >/dev/null 2>&1; then
  PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)"
  PYOK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)' 2>/dev/null)"
  if [ "$PYOK" = "1" ]; then
    status PASS "python3 $PYVER found ($(command -v python3))"
  else
    status WARN "python3 found but version is $PYVER (3.9+ recommended)" "Install/update Command Line Tools: xcode-select --install"
  fi
else
  status FAIL "python3 not found" "Install Xcode Command Line Tools: xcode-select --install"
fi

section "Core command-line tools"
for tool in lsof nettop ps spctl csrutil fdesetup launchctl; do
  if command -v "$tool" >/dev/null 2>&1; then
    status PASS "$tool available"
  else
    status WARN "$tool not found on PATH" "That module will report as 'partial' or 'unavailable'"
  fi
done
if [ -x /usr/libexec/ApplicationFirewall/socketfilterfw ]; then
  status PASS "socketfilterfw available"
else
  status WARN "socketfilterfw not found" "macOS firewall status will be unavailable"
fi

section "Network visibility (no admin needed, but worth confirming)"
if lsof -nP -i -F pcPnT >/dev/null 2>&1; then
  status PASS "lsof can list network connections"
else
  status WARN "lsof -i returned an error" "Network findings may be incomplete"
fi

section "Downloads folder access"
if [ -r "$HOME/Downloads" ] && ls "$HOME/Downloads" >/dev/null 2>&1; then
  status PASS "Can read ~/Downloads"
else
  status FAIL "Cannot read ~/Downloads" \
    "System Settings > Privacy & Security > Files and Folders -> allow Terminal (or whatever app runs this script) to access Downloads"
fi

section "Full Disk Access (optional — widens a few checks, nothing requires it)"
if ls /Library/Logs >/dev/null 2>&1; then
  status PASS "Can read /Library/Logs"
else
  status WARN "Cannot read /Library/Logs" \
    "Optional: System Settings > Privacy & Security > Full Disk Access -> add Terminal (or your shell app) to read more Malwarebytes/XProtect log locations"
fi
if ls "$HOME/Library/Logs/DiagnosticReports" >/dev/null 2>&1 || ls /Library/Logs/DiagnosticReports >/dev/null 2>&1; then
  status PASS "Can read DiagnosticReports"
else
  status WARN "Cannot read DiagnosticReports" "Optional: same Full Disk Access grant as above surfaces XProtect detection reports"
fi

section "Unified log (optional — the report falls back to diagnostic reports without it)"
if log show --last 1m >/dev/null 2>&1; then
  status PASS "log show works for this account"
else
  status INFO "log show needs admin rights on this account — expected for a standard user; the report still works without it"
fi

section "LaunchAgents directory (used by 'install'/'uninstall', no sudo involved)"
if [ -d "$HOME/Library/LaunchAgents" ] || mkdir -p "$HOME/Library/LaunchAgents" 2>/dev/null; then
  status PASS "~/Library/LaunchAgents is writable"
else
  status WARN "Could not create/access ~/Library/LaunchAgents" "The 'install' command needs to write .plist files here"
fi

echo
echo "=================================================="
printf "Summary: %d ok, %d warnings, %d failed\n" "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "Fix the FAIL items above before running a report — those modules will otherwise be empty."
elif [ "$WARN" -gt 0 ]; then
  echo "You're good to go. The WARN items are optional — they only widen a few checks."
else
  echo "Everything's available. Run: python3 mac_sentinel_synthesis_scanner.py report --open"
fi
