#!/usr/bin/env bash
# Phase 4: Deep Service-Specific Checks — Turbo Edition
# Advanced parallel scanning with aggressive timing for <60s completion
# Usage: sudo ./phase4_deep_checks.sh <TARGET-IP>

set -o pipefail
shopt -s nocasematch

TARGET="$1"
[[ -z "$TARGET" ]] && { echo "Usage: sudo $0 <TARGET-IP>"; exit 1; }
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=validate_ipv4.sh
source "$SCRIPT_DIR/validate_ipv4.sh"
validate_ipv4 "$TARGET" || { echo "Error: invalid IPv4 target"; exit 2; }
[[ $EUID -ne 0 ]] && { echo "Error: must be root"; exit 1; }

# ------------------------------------------------------------------
# PHASE 0: Blitzkrieg port discovery — masscan then nmap validate
# ------------------------------------------------------------------
echo "[*] Rapid port discovery via masscan..."
MASSCAN_PORTS=$(mktemp)
masscan -p1-65535,U:1-65535 "$TARGET" \
    --rate=10000 --wait=10 --open-only \
    -oG "$MASSCAN_PORTS" 2>/dev/null &
MASSCAN_PID=$!

# Fallback: ultra-fast nmap while masscan runs
sleep 3
TCP_PORTS=$(nmap -sS -T5 --min-rate=10000 --max-rtt-timeout=200ms \
    --initial-rtt-timeout=100ms --min-hostgroup=256 \
    -p- -Pn -n --open "$TARGET" 2>/dev/null \
    | grep -E "^[0-9]+/tcp" | cut -d'/' -f1 | paste -sd,)

UDP_PORTS=$(nmap -sU -T5 --min-rate=5000 --max-rtt-timeout=300ms \
    --top-ports=100 -Pn -n --open "$TARGET" 2>/dev/null \
    | grep -E "^[0-9]+/udp" | cut -d'/' -f1 | paste -sd,)

# Wait for masscan to finish, merge results
wait $MASSCAN_PID 2>/dev/null
MASSCAN_TCP=$(grep -oP '\d+/open/tcp' "$MASSCAN_PORTS" 2>/dev/null | cut -d'/' -f1 | paste -sd,)
MASSCAN_UDP=$(grep -oP '\d+/open/udp' "$MASSCAN_PORTS" 2>/dev/null | cut -d'/' -f1 | paste -sd,)
rm -f "$MASSCAN_PORTS"

# Merge masscan + nmap results
ALL_TCP=$(echo "${TCP_PORTS},${MASSCAN_TCP}" | tr ',' '\n' | sort -un | paste -sd,)
ALL_UDP=$(echo "${UDP_PORTS},${MASSCAN_UDP}" | tr ',' '\n' | sort -un | paste -sd,)

OPEN_PORTS="$ALL_TCP"
OPEN_UDP="$ALL_UDP"

[[ -z "$OPEN_PORTS" ]] && { echo "[-] No open TCP ports found"; exit 0; }

echo "[+] TCP: $OPEN_PORTS"
echo "[+] UDP: ${OPEN_UDP:-none}"
echo ""

# ------------------------------------------------------------------
# SHARED: Aggressive nmap flags for all service scans
# ------------------------------------------------------------------
NMAP_FAST=(-T5 --min-rate=10000 --max-rtt-timeout=300ms --initial-rtt-timeout=100ms --min-hostgroup=128 --max-scan-delay=0)
NMAP_OPTS=("${NMAP_FAST[@]}" -Pn -n --open)
TIMEOUT=45

# ------------------------------------------------------------------
# UTILITY: Parallel execution wrapper
# ------------------------------------------------------------------
_parallel() {
    local max_jobs="$1"; shift
    local pids=()
    local i=0
    for cmd in "$@"; do
        eval "$cmd" &
        pids+=($!)
        ((i++))
        if (( i % max_jobs == 0 )); then
            for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
            pids=()
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
}

# ------------------------------------------------------------------
# SERVICE: Web (HTTP/HTTPS)
# ------------------------------------------------------------------
_web() {
    [[ -z "$OPEN_PORTS" ]] && return
    local web_ports
    web_ports=$(echo "$OPEN_PORTS" | tr ',' '\n' | awk '$1>=80 && $1<=8443 || $1==8080 || $1==8888 || $1==9090 || $1==3000 || $1==5000 || $1==9000' | paste -sd,)
    [[ -z "$web_ports" ]] && return

    echo "=== WEB ==="

    # Aggressive nmap web vuln + enum scripts
    nmap -p"$web_ports" "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "http-enum,http-default-accounts,http-config-backup,http-methods,http-security-headers,\
http-title,http-shellshock,http-vuln-cve2017-5638,http-vuln-cve2017-1001000,\
http-vuln-cve2015-1635,http-iis-web-vuln,http-apache-negotiation,\
http-phpmyadmin-dir,http-wordpress-enum,http-joomla-brute,\
http-dombased-xss,http-stored-xss,http-sql-injection,\
http-cors,http-server-header,http-errors,http-webdav-scan" \
        "$TARGET" 2>/dev/null &

    # Feroxbuster directory fuzzing (if installed) — fast wordlist
    if command -v feroxbuster &>/dev/null; then
        for port in $(echo "$web_ports" | tr ',' ' '); do
            local proto="http"
            [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
            timeout 25 feroxbuster -q -u "${proto}://${TARGET}:${port}" \
                -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
                -t 64 --depth 2 --smart --scan-limit 4 2>/dev/null &
        done
    fi
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: SMB (with advanced checks)
# ------------------------------------------------------------------
_smb() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)(445|139)(,|$)"; then return; fi
    echo "=== SMB ==="

    # Deep SMB enumeration
    nmap -p445,139 "${NMAP_OPTS[@]}" --script-timeout 25s \
        --script "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,\
smb2-capabilities,smb2-security-mode,smb-vuln-*,\
smb-ls,smb-server-stats,smb-system-info,\
smb-protocols,smb-print-text" \
        "$TARGET" 2>/dev/null &

    # CrackMapExec for deep recon
    if command -v crackmapexec &>/dev/null; then
        timeout 20 crackmapexec smb "$TARGET" 2>/dev/null &
    fi

    # SMBMap if available
    if command -v smbmap &>/dev/null; then
        timeout 15 smbmap -H "$TARGET" -u '' -p '' 2>/dev/null &
    fi

    # Impacket enumeration
    if command -v samrdump &>/dev/null; then
        timeout 15 samrdump "$TARGET" 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: SNMP — aggressive community brute + MIB walk
# ------------------------------------------------------------------
_snmp() {
    [[ -z "$OPEN_UDP" ]] && return
    if ! echo "$OPEN_UDP" | grep -q "161"; then return; fi
    echo "=== SNMP ==="

    # Deep SNMP scripts
    nmap -sU -p161 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "snmp-info,snmp-netstat,snmp-processes,snmp-sysdescr,\
snmp-interfaces,snmp-brute,snmp-ios-config,snmp-hh3c-login" \
        "$TARGET" 2>/dev/null &

    # Aggressive community string brute
    if command -v onesixtyone &>/dev/null; then
        echo -e "public\nprivate\nmanager\nadmin\ncisco\npassword\nsecret\ncommunity\nAll\nPublic\nPrivate\ntest\nread\nwrite\nsnmp\nsnmpd\ndefault\nmonitor\ncontrol" > /tmp/snmp_comm.txt
        timeout 15 onesixtyone -c /tmp/snmp_comm.txt "$TARGET" 2>/dev/null
        rm -f /tmp/snmp_comm.txt &
    fi

    # Extended snmpwalk with found communities
    for comm in public private manager admin cisco; do
        timeout 3 snmpwalk -v2c -c "$comm" -t 1 "$TARGET" 1.3.6.1.2.1.1.1.0 2>/dev/null | head -2 &
    done

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: DNS — zone transfer, recursion, enumeration
# ------------------------------------------------------------------
_dns() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)53(,|$)"; then return; fi
    echo "=== DNS ==="

    nmap -sU -sT -p53 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "dns-recursion,dns-nsid,dns-service-discovery,\
dns-brute,dns-cache-snoop,dns-zone-transfer" \
        --script-args dns-brute.domain=local,dns-cache-snoop.mode=timed \
        "$TARGET" 2>/dev/null &

    # Quick zone transfer + dig enumeration
    if command -v dig &>/dev/null; then
        timeout 5 dig AXFR "@${TARGET}" 2>/dev/null &
        timeout 5 dig ANY "@${TARGET}" 2>/dev/null &
    fi

    # dnsrecon
    if command -v dnsrecon &>/dev/null; then
        timeout 15 dnsrecon -d local -n "$TARGET" -t axfr 2>/dev/null &
        timeout 15 dnsrecon -d local -n "$TARGET" -t brt 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: NFS — mount enumeration + showmount
# ------------------------------------------------------------------
_nfs() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)(2049|111|20048)(,|$)"; then return; fi
    echo "=== NFS ==="

    nmap -p111,2049,20048 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "nfs-showmount,nfs-ls,nfs-statfs,rpcinfo,\
nfs-portmap,nfs-rmtab" \
        --script-args nfs-ls.dir=/ \
        "$TARGET" 2>/dev/null &

    if command -v showmount &>/dev/null; then
        timeout 10 showmount -e "$TARGET" 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: RDP — credential brute + encryption checks
# ------------------------------------------------------------------
_rdp() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)3389(,|$)"; then return; fi
    echo "=== RDP ==="

    nmap -p3389 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020,\
rdp-sec-check,cve-2019-0708" \
        "$TARGET" 2>/dev/null &

    if command -v crowbar &>/dev/null; then
        timeout 20 crowbar -b rdp -s "$TARGET/32" -u Administrator \
            -w /usr/share/wordlists/seclists/Passwords/common-passwords.txt \
            -t 4 -n 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: VNC — brute + auth bypass checks
# ------------------------------------------------------------------
_vnc() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)590[0-9](,|$)"; then return; fi
    echo "=== VNC ==="

    nmap -p5900-5910 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "vnc-info,vnc-title,vnc-auth,\
realvnc-auth-bypass,vnc-brute" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: MSSQL — brute + enum
# ------------------------------------------------------------------
_mssql() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)1433(,|$)"; then return; fi
    echo "=== MSSQL ==="

    nmap -p1433 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "ms-sql-info,ms-sql-ntlm-info,ms-sql-brute,\
ms-sql-empty-password,ms-sql-config,ms-sql-dump-hashes" \
        --script-args mssql.instance-port=1433 \
        "$TARGET" 2>/dev/null &

    if command -v crackmapexec &>/dev/null; then
        timeout 20 crackmapexec mssql "$TARGET" 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: MySQL — blank root + enum
# ------------------------------------------------------------------
_mysql() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)3306(,|$)"; then return; fi
    echo "=== MySQL ==="

    nmap -p3306 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "mysql-info,mysql-enum,mysql-brute,\
mysql-empty-password,mysql-query,mysql-audit" \
        --script-args mysql-enum.userdb=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: PostgreSQL — default creds + enum
# ------------------------------------------------------------------
_postgres() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)5432(,|$)"; then return; fi
    echo "=== PostgreSQL ==="

    nmap -p5432 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "pgsql-dump-hash,pgsql-brute,pgsql-enum-dbs" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: SSH — auth methods + weak keys
# ------------------------------------------------------------------
_ssh() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)22(,|$)"; then return; fi
    echo "=== SSH ==="

    nmap -p22 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,\
ssh-vulnkey" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: FTP — anonymous + bounce + vulns
# ------------------------------------------------------------------
_ftp() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)21(,|$)"; then return; fi
    echo "=== FTP ==="

    nmap -p21 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,\
ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,\
ftp-syst,ftp-ntlm-info" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Telnet — brute + env
# ------------------------------------------------------------------
_telnet() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)23(,|$)"; then return; fi
    echo "=== Telnet ==="

    nmap -p23 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "telnet-ntlm-info,telnet-brute,telnet-encryption" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: LDAP — anonymous bind + enum
# ------------------------------------------------------------------
_ldap() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)389|636(,|$)"; then return; fi
    echo "=== LDAP ==="

    nmap -p389,636,3268,3269 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "ldap-rootdse,ldap-brute,ldap-search,\
ldap-novell-getpass" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: SMTP — relay check + user enum
# ------------------------------------------------------------------
_smtp() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)25|465|587(,|$)"; then return; fi
    echo "=== SMTP ==="

    nmap -p25,465,587 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "smtp-commands,smtp-open-relay,smtp-enum-users,\
smtp-vuln-cve2010-4344,smtp-ntlm-info" \
        --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} \
        "$TARGET" 2>/dev/null &

    # Quick relay test via swaks if available
    if command -v swaks &>/dev/null; then
        timeout 10 swaks --to test@test.com --server "$TARGET" 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Redis — unauthenticated access + keys
# ------------------------------------------------------------------
_redis() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)6379(,|$)"; then return; fi
    echo "=== Redis ==="

    nmap -p6379 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "redis-info,redis-brute" \
        "$TARGET" 2>/dev/null &

    if command -v redis-cli &>/dev/null; then
        timeout 5 bash -c "echo 'INFO' | redis-cli -h $TARGET -p 6379" 2>/dev/null &
        timeout 5 bash -c "echo 'KEYS *' | redis-cli -h $TARGET -p 6379" 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Memcached — stats dump
# ------------------------------------------------------------------
_memcached() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)11211(,|$)"; then return; fi
    echo "=== Memcached ==="

    nmap -p11211 "${NMAP_OPTS[@]}" --script-timeout 10s \
        --script "memcached-info" \
        "$TARGET" 2>/dev/null &

    timeout 5 bash -c "echo -e 'stats\nquit' | nc -w 3 $TARGET 11211" 2>/dev/null &

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: MongoDB — no-auth access
# ------------------------------------------------------------------
_mongodb() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)27017|27018(,|$)"; then return; fi
    echo "=== MongoDB ==="

    nmap -p27017,27018 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "mongodb-info,mongodb-databases" \
        "$TARGET" 2>/dev/null &

    if command -v mongo &>/dev/null; then
        timeout 5 mongo --host "$TARGET" --eval "db.adminCommand('listDatabases')" 2>/dev/null &
    fi

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Elasticsearch — info + indices
# ------------------------------------------------------------------
_elastic() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)9200(,|$)"; then return; fi
    echo "=== Elasticsearch ==="

    nmap -p9200 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "http-title,http-server-header" \
        "$TARGET" 2>/dev/null &

    # Direct REST API queries
    for endpoint in "/" "/_cat/indices?v" "/_cluster/health" "/_nodes"; do
        timeout 3 curl -s "http://${TARGET}:9200${endpoint}" 2>/dev/null &
    done

    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Kafka — metadata enum
# ------------------------------------------------------------------
_kafka() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)9092(,|$)"; then return; fi
    echo "=== Kafka ==="
    # Simple metadata probe
    timeout 5 bash -c "echo '' | nc -w 3 $TARGET 9092" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Jenkins — script console discovery
# ------------------------------------------------------------------
_jenkins() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)8080(,|$)"; then return; fi
    echo "=== Jenkins ==="
    timeout 10 curl -s "http://${TARGET}:8080/script" 2>/dev/null &
    timeout 10 curl -s "http://${TARGET}:8080/loginError" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: CUPS — printer info
# ------------------------------------------------------------------
_cups() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)631(,|$)"; then return; fi
    echo "=== CUPS ==="
    nmap -p631 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "cups-info,cups-queue-info" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Kerberos — enum users
# ------------------------------------------------------------------
_kerberos() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)88(,|$)"; then return; fi
    echo "=== Kerberos ==="
    nmap -p88 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "krb5-enum-users" \
        --script-args krb5-enum-users.realm=LOCAL \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Rsync — module enumeration
# ------------------------------------------------------------------
_rsync() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)873(,|$)"; then return; fi
    echo "=== Rsync ==="
    timeout 10 rsync -av --list-only "rsync://${TARGET}/" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: IPMI — cipher zero + info leak
# ------------------------------------------------------------------
_ipmi() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)623(,|$)"; then return; fi
    echo "=== IPMI ==="
    nmap -sU -p623 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "ipmi-*" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# SERVICE: Modbus — SCADA discovery
# ------------------------------------------------------------------
_modbus() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)502(,|$)"; then return; fi
    echo "=== Modbus ==="
    nmap -p502 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "modbus-discover" \
        "$TARGET" 2>/dev/null &
    wait
    echo ""
}

# ------------------------------------------------------------------
# EXECUTION: Fire all in parallel — max 6 concurrent service groups
# ------------------------------------------------------------------
echo "[*] Launching ${TIMEOUT}s parallel service scans..."
echo ""

export TARGET OPEN_PORTS OPEN_UDP NMAP_OPTS

_parallel 6 \
    "_web" "_smb" "_ssh" "_ftp" "_dns" \
    "_snmp" "_nfs" "_rdp" "_vnc" "_smtp" \
    "_mssql" "_mysql" "_postgres" "_ldap" \
    "_redis" "_memcached" "_mongodb" "_elastic" \
    "_jenkins" "_cups" "_kerberos" "_rsync" \
    "_ipmi" "_modbus" "_kafka" "_telnet"

echo ""
echo "[+] Phase 4 complete — $(date '+%H:%M:%S')"
