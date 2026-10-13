#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

IP="$1"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=validate_ipv4.sh
source "$SCRIPT_DIR/validate_ipv4.sh"
validate_ipv4 "$IP" || { echo "Error: invalid IPv4 target"; exit 2; }

echo "Checking $IP..."

# Better: check if ANY reply comes
if ping -c 2 -w 6 "$IP" | grep -q "bytes from"; then
    echo "$IP is ONLINE ✅"

    echo "Running traceroute with nmap..."
    nmap -sn -Pn --traceroute "$IP"

else
    echo "$IP is OFFLINE ❌"
fi
