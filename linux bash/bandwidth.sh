#!/bin/bash

IP="$1"

if [[ -z "$IP" ]]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=validate_ipv4.sh
source "$SCRIPT_DIR/validate_ipv4.sh"
validate_ipv4 "$IP" || { echo "Error: invalid IPv4 target"; exit 2; }

# Extract first octet
FIRST_OCTET=$(echo "$IP" | cut -d. -f1)

# Determine class
if (( FIRST_OCTET >= 1 && FIRST_OCTET <= 126 )); then
    CLASS="A"
elif (( FIRST_OCTET >= 128 && FIRST_OCTET <= 191 )); then
    CLASS="B"
elif (( FIRST_OCTET >= 192 && FIRST_OCTET <= 223 )); then
    CLASS="C"
else
    CLASS="Unknown"
fi

echo "Target: $IP (Class $CLASS)"

# Only proceed for Class A or B (your requirement)
if [[ "$CLASS" != "A" && "$CLASS" != "B" ]]; then
    echo "Skipping SNMP (not Class A/B)"
    exit 0
fi

echo "Checking SNMP (UDP 161)..."

# Check if SNMP port is open
if nmap -sU -p 161 --open "$IP" 2>/dev/null | grep -q "161/udp open"; then
    echo "SNMP port is OPEN ✅"
    echo "Running snmp-check..."

    snmp-check "$IP"

else
    echo "SNMP port is CLOSED or FILTERED ❌"
fi
