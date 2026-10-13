#!/usr/bin/env bash
# Phase 2: Service & OS Fingerprinting
# Usage: sudo ./phase2_service_fingerprint.sh <TARGET-IP>

TARGET="$1"

[[ -z "$TARGET" ]] && { echo "Usage: sudo $0 <TARGET-IP>"; exit 1; }
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=validate_ipv4.sh
source "$SCRIPT_DIR/validate_ipv4.sh"
validate_ipv4 "$TARGET" || { echo "Error: invalid IPv4 target"; exit 2; }
[[ $EUID -ne 0 ]] && { echo "Error: must be root"; exit 1; }

OPEN_PORTS=$(nmap -sS -T4 --min-rate=5000 -Pn -n --open "$TARGET" 2>/dev/null \
    | grep -E "^[0-9]+/tcp" | cut -d'/' -f1 | paste -sd,)

[[ -z "$OPEN_PORTS" ]] && { echo "No open ports found"; exit 0; }

echo "Phase 2: Service & OS Fingerprinting"
echo "Target: $TARGET"
echo "Ports:  $OPEN_PORTS"
echo ""

nmap -sV -O -T4 -Pn -n \
     -p "$OPEN_PORTS" \
     --script "banner,ssl-enum-ciphers" \
     --script-timeout 30s \
     "$TARGET" 2>/dev/null | grep -v "^$"

echo ""
echo "Phase 2 complete"
