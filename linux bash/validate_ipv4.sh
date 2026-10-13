#!/usr/bin/env bash

# Shared strict IPv4 validation for scanner entry points.
validate_ipv4() {
    local value="${1:-}"
    local IFS=.
    local -a octets

    [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    read -r -a octets <<< "$value"
    [[ ${#octets[@]} -eq 4 ]] || return 1

    local octet
    for octet in "${octets[@]}"; do
        ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
    done
}
