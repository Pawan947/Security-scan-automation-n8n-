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

echo "Target: $IP"
echo "Running Nmap (top ports + service/version detection)..."
echo "--------------------------------------------"

# IMPORTANT: add -Pn
OUTPUT=$(nmap -D RND:5 -sV -T6 -Pn "$IP" 2>/dev/null)

# Show open + filtered ports cleanly
echo "$OUTPUT" | grep -E "open|filtered" | grep "/tcp" | while read -r line; do
    PORT=$(echo "$line" | awk '{print $1}')
    STATE=$(echo "$line" | awk '{print $2}')
    SERVICE=$(echo "$line" | awk '{print $3}')
    VERSION=$(echo "$line" | cut -d' ' -f4-)

    printf "%-10s %-10s %-15s %s\n" "$PORT" "$STATE" "$SERVICE" "$VERSION"
done

echo "--------------------------------------------"
echo "Scan complete."
