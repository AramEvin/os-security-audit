#!/usr/bin/env bash
# IT Security LLC
# debian_cis_audit.sh (v3.0)
#
# Comprehensive Technical Security Audit for Debian/Ubuntu
# systems (DEB/Linux). Aligned with ISO/IEC 27001 technical controls
# (Annex A: A.8, A.12, A.13) and CIS Benchmarks for Linux methodology
# (Level 1 / Level 2).
#
# This script ONLY READS system state (read-only audit).
#   [PASS] - Control satisfied
#   [WARN] - Deviation / Level 2 / requires attention
#   [FAIL] - Critical non-compliance (Level 1)
#   [INFO] - Informational entry, does not affect score
#
# Output:
#   - Console (colored)
#   - /var/log/debian_cis_audit_report.log   (text report, cumulative)
#   - /var/log/debian_cis_audit_report.html  (modern interactive web report)

set -u
set -o pipefail

# ============================================================================
# 0. GLOBAL PARAMETERS & INITIALIZATION
# ============================================================================

readonly SCRIPT_VERSION="3.0"
readonly AUDITOR_NAME="IT Security LLC"
readonly REPORT_FILE="/var/log/debian_cis_audit_report.log"
readonly HTML_REPORT_FILE="/var/log/debian_cis_audit_report.html"
readonly TMP_REPORT="$(mktemp /tmp/debian_cis_audit.XXXXXX)"
readonly HOSTNAME_FQDN="$(hostname -f || hostname)"
readonly RUN_TS="$(date '+%Y-%m-%d %H:%M:%S %Z')"
readonly KERNEL_VER="$(uname -r || echo 'N/A')"
readonly UPTIME_INFO="$(uptime -p || uptime || echo 'N/A')"

COUNT_PASS=0
COUNT_WARN=0
COUNT_FAIL=0
COUNT_INFO=0

declare -a FINDINGS=()      # LEVEL<0x1f>SECTION<0x1f>MESSAGE<0x1f>REMEDIATION
CURRENT_SECTION="1. INITIALIZATION AND OS INFORMATION"

if [[ -t 1 ]]; then
    C_RED="\033[1;31m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"
    C_BLUE="\033[1;34m"; C_BOLD="\033[1m"; C_RESET="\033[0m"
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

cleanup() { rm -f "${TMP_REPORT}" || true; }
trap cleanup EXIT INT TERM

log_raw() {
    echo -e "$1"
    echo -e "$1" | sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g' >> "${TMP_REPORT}"
}

log_section() {
    local title="$1"
    CURRENT_SECTION="${title}"
    log_raw ""
    log_raw "${C_BLUE}${C_BOLD}==================================================================${C_RESET}"
    log_raw "${C_BLUE}${C_BOLD} ${title}${C_RESET}"
    log_raw "${C_BLUE}${C_BOLD}==================================================================${C_RESET}"
}

pass() {
    local msg="$1"
    COUNT_PASS=$((COUNT_PASS+1))
    log_raw "  ${C_GREEN}[PASS]${C_RESET} ${msg}"
    FINDINGS+=("PASS"$'\x1f'"${CURRENT_SECTION}"$'\x1f'"${msg}"$'\x1f'"")
}
warn() {
    local msg="$1" rem="${2:-}"
    COUNT_WARN=$((COUNT_WARN+1))
    log_raw "  ${C_YELLOW}[WARN]${C_RESET} ${msg}"
    [[ -n "${rem}" ]] && log_raw "         -> Recommendation: ${rem}"
    FINDINGS+=("WARN"$'\x1f'"${CURRENT_SECTION}"$'\x1f'"${msg}"$'\x1f'"${rem}")
}
fail() {
    local msg="$1" rem="${2:-}"
    COUNT_FAIL=$((COUNT_FAIL+1))
    log_raw "  ${C_RED}[FAIL]${C_RESET} ${msg}"
    [[ -n "${rem}" ]] && log_raw "         -> Recommendation: ${rem}"
    FINDINGS+=("FAIL"$'\x1f'"${CURRENT_SECTION}"$'\x1f'"${msg}"$'\x1f'"${rem}")
}
info() {
    local msg="$1"
    COUNT_INFO=$((COUNT_INFO+1))
    log_raw "  ${C_BOLD}[INFO]${C_RESET} ${msg}"
    FINDINGS+=("INFO"$'\x1f'"${CURRENT_SECTION}"$'\x1f'"${msg}"$'\x1f'"")
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

svc_loaded() {
    local state
    state="$(systemctl show -p LoadState --value "$1" 2>/dev/null)"
    [[ "${state}" == "loaded" ]]
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"
    printf '%s' "${s}"
}

# ============================================================================
# 1. ROOT CHECK AND OS INFORMATION
# ============================================================================

log_section "1. INITIALIZATION AND OS INFORMATION"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${C_RED}${C_BOLD}[FAIL] Script must be run as root (UID 0).${C_RESET}" >&2
    echo "Current user: $(id -un) (UID $(id -u))" >&2
    echo "Re-run using: sudo bash $0" >&2
    exit 1
fi

log_raw "${C_BOLD}Technical Security Audit (CIS / ISO 27001) - Debian/Ubuntu Linux${C_RESET}"
log_raw "Script Version : ${SCRIPT_VERSION}"
log_raw "Host           : ${HOSTNAME_FQDN}"
log_raw "Date/Time      : ${RUN_TS}"
log_raw "Report File    : ${REPORT_FILE}"

OS_ID="unknown"
OS_ID_LIKE=""
OS_VERSION_ID="unknown"
OS_INFO="unknown"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_ID_LIKE="${ID_LIKE:-}"
    OS_VERSION_ID="${VERSION_ID:-unknown}"
    OS_INFO="${PRETTY_NAME:-${NAME:-unknown}}"
elif [[ -r /etc/debian_version ]]; then
    OS_INFO="Debian $(cat /etc/debian_version)"
fi

DEBIAN_FAMILY=0
if [[ "${OS_ID}" =~ ^(debian|ubuntu|mint|kali|pop|raspbian)$ ]] || \
   [[ " ${OS_ID_LIKE} " == *" debian "* ]] || \
   [[ " ${OS_ID_LIKE} " == *" ubuntu "* ]] || \
   [[ -r /etc/debian_version ]]; then
    DEBIAN_FAMILY=1
fi

log_raw "OS             : ${OS_INFO}"
log_raw "OS ID          : ${OS_ID}"
log_raw "OS VERSION_ID   : ${OS_VERSION_ID}"
log_raw "Debian family  : $([[ ${DEBIAN_FAMILY} -eq 1 ]] && echo yes || echo no)"

if [[ ${DEBIAN_FAMILY} -ne 1 ]]; then
    warn "OS not recognized as Debian/Ubuntu-compatible (${OS_INFO}); Debian-specific checks might not apply" \
         "Execute this audit on Debian/Ubuntu and verify /etc/os-release"
else
    pass "Detected Debian/Ubuntu-compatible system: ${OS_INFO}"
fi

# ============================================================================
# 2. LOGGING & AUDIT SUBSYSTEM (auditd / rsyslog / journald / logrotate)
# ============================================================================

log_section "2. LOGGING AND AUDIT SUBSYSTEM (auditd / rsyslog / journald)"

AUDITD_ACTIVE="inactive"
if have_cmd systemctl; then
    if svc_loaded auditd.service; then
        AUDITD_ACTIVE="$(systemctl is-active auditd 2>/dev/null)"
        AUDITD_ENABLED="$(systemctl is-enabled auditd 2>/dev/null)"

        if [[ "${AUDITD_ACTIVE}" == "active" ]]; then
            pass "auditd is active (systemctl is-active: active)"
        else
            fail "auditd is NOT active (current state: ${AUDITD_ACTIVE:-unknown})" \
                 "systemctl enable --now auditd"
        fi

        if [[ "${AUDITD_ENABLED}" == "enabled" ]]; then
            pass "auditd is enabled on boot (is-enabled: enabled)"
        else
            fail "auditd is NOT enabled on boot (is-enabled: ${AUDITD_ENABLED:-unknown})" \
                 "systemctl enable auditd"
        fi
    else
        fail "auditd service is not installed (unit auditd.service missing)" \
             "apt update && apt install -y auditd audispd-plugins && systemctl enable --now auditd"
    fi
else
    warn "systemctl is unavailable - unable to verify auditd status"
fi

if [[ "${AUDITD_ACTIVE}" == "active" ]] && have_cmd auditctl; then
    AUDIT_RULES="$(auditctl -l)"
    RULES_COUNT="$(echo "${AUDIT_RULES}" | grep -cv '^$' || echo 0)"

    if [[ "${RULES_COUNT}" -eq 0 ]] || echo "${AUDIT_RULES}" | grep -qi "no rules"; then
        fail "auditctl -l: No active audit rules detected" \
             "cp /usr/share/doc/auditd/examples/rules/10-base-config.rules /etc/audit/rules.d/ && augeas-reload || augenrules --load"
    else
        pass "Detected audit rules count: ${RULES_COUNT}"
        if echo "${AUDIT_RULES}" | grep -q "/etc/passwd"; then
            pass "Audit rule exists for tracking /etc/passwd modifications"
        else
            fail "Missing audit rule for tracking /etc/passwd" \
                 "echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/rules.d/identity.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | grep -q "/etc/shadow"; then
            pass "Audit rule exists for tracking /etc/shadow modifications"
        else
            fail "Missing audit rule for tracking /etc/shadow" \
                 "echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/identity.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | grep -qE "/etc/sudoers"; then
            pass "Audit rule exists for tracking /etc/sudoers modifications"
        else
            fail "Missing audit rule for tracking /etc/sudoers" \
                 "echo '-w /etc/sudoers -p wa -k scope' >> /etc/audit/rules.d/scope.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | grep -q "execve"; then
            pass "Audit rule exists for execve syscalls"
        else
            warn "Missing audit rule for execve (CIS 4.1.13)" \
                 "Add rules -a always,exit -F arch=b64 -S execve ... to /etc/audit/rules.d/exec.rules"
        fi
        if echo "${AUDIT_RULES}" | grep -qE "/etc/hosts|/etc/network/interfaces|network"; then
            pass "Audit rule exists for tracking network configuration changes"
        else
            warn "Missing audit rule for network configuration changes (CIS 4.1.7)" \
                 "echo '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale' >> /etc/audit/rules.d/network.rules"
        fi
        if echo "${AUDIT_RULES}" | tail -1 | grep -q "^-e 2$" || auditctl -s | grep -q "enabled 2"; then
            pass "auditd configuration is locked in immutable mode (-e 2)"
        else
            warn "auditd is not in immutable mode (-e 2)" \
                 "echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules && augenrules --load"
        fi
    fi
elif [[ "${AUDITD_ACTIVE}" == "active" ]]; then
    warn "auditctl utility not found - audit rules content could not be verified"
fi

if have_cmd systemctl; then
    for svc in rsyslog systemd-journald; do
        if svc_loaded "${svc}.service"; then
            state="$(systemctl is-active "${svc}" 2>/dev/null)"
            if [[ "${state}" == "active" ]]; then
                pass "Service ${svc} is active"
            else
                warn "Service ${svc} is not active (state: ${state:-unknown})"
            fi
        else
            info "Unit ${svc}.service does not exist on this system"
        fi
    done
fi

if [[ -f /etc/systemd/journald.conf ]]; then
    if grep -qE '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf; then
        pass "journald is configured for persistent storage (Storage=persistent)"
    else
        warn "journald is not configured to Storage=persistent - logs will not survive a reboot" \
             "mkdir -p /var/log/journal && sed -i 's/^#\\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf && systemctl restart systemd-journald"
    fi
fi

if [[ -f /etc/logrotate.conf ]]; then
    pass "Main configuration file /etc/logrotate.conf found"
    LR_ROTATE="$(grep -E '^\s*rotate\s+[0-9]+' /etc/logrotate.conf | awk '{print $2}' | head -1)"
    if [[ -n "${LR_ROTATE:-}" ]]; then
        if [[ "${LR_ROTATE}" -ge 4 ]]; then
            pass "Log rotation depth: ${LR_ROTATE} (>= 4)"
        else
            warn "Log rotation depth is low: ${LR_ROTATE} (recommended >= 4)"
        fi
    else
        info "Parameter 'rotate' is not explicitly defined in logrotate.conf"
    fi
    if grep -qE '^\s*compress\s*$' /etc/logrotate.conf; then
        pass "Log compression on rotation is enabled (compress)"
    else
        warn "Log compression (compress) is not enabled" \
             "echo 'compress' >> /etc/logrotate.conf"
    fi
    if [[ -d /etc/logrotate.d ]]; then
        LR_DROPINS="$(find /etc/logrotate.d -type f | wc -l)"
        info "Found drop-in configurations in /etc/logrotate.d: ${LR_DROPINS}"
    fi
else
    fail "File /etc/logrotate.conf is missing" "apt install -y logrotate"
fi

# ============================================================================
# 3. NETWORK SECURITY, OPEN PORTS, AND FIREWALL
# ============================================================================

log_section "3. NETWORK SECURITY AND FIREWALL"

if have_cmd ss; then
    info "Gathering open ports via 'ss -tulpn'"
    PORT_DATA="$(ss -tulpn)"
    echo "${PORT_DATA}" | tail -n +2 | while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        log_raw "         ${line}"
    done
    LISTEN_COUNT="$(echo "${PORT_DATA}" | grep -cE 'LISTEN|UNCONN')"
    info "Total listening sockets (TCP LISTEN / UDP UNCONN): ${LISTEN_COUNT}"
    WILDCARD_LISTEN="$(echo "${PORT_DATA}" | grep -E 'LISTEN' | grep -cE '0\.0\.0\.0:|\*:|\[::\]:')"
    if [[ "${WILDCARD_LISTEN}" -gt 0 ]]; then
        warn "Detected ${WILDCARD_LISTEN} TCP ports listening on all interfaces (0.0.0.0/::)" \
             "Restrict application bind address to a specific interface; close unused ports in UFW/iptables"
    fi
elif have_cmd netstat; then
    info "ss not found, falling back to netstat -tulpn"
    netstat -tulpn | tail -n +3 | while IFS= read -r line; do
        log_raw "         ${line}"
    done
else
    warn "Neither ss nor netstat utility was found"
fi

FW_CONFIGURED=0
if have_cmd ufw && ufw status | grep -q "Status: active"; then
    FW_CONFIGURED=1
    pass "UFW is active"
    UFW_DEFAULT="$(ufw status verbose | grep -i "Default:" || echo "unknown")"
    info "UFW Policies: ${UFW_DEFAULT}"
    if echo "${UFW_DEFAULT}" | grep -qE "deny \(incoming\)|reject \(incoming\)"; then
        pass "Default incoming traffic policy: deny/reject (implicit deny, secure)"
    else
        fail "Default incoming traffic policy allows connections" \
             "ufw default deny incoming && ufw reload"
    fi
elif have_cmd nft && nft list ruleset | grep -q 'table'; then
    FW_CONFIGURED=1
    pass "nftables is active and contains rules"
elif have_cmd iptables; then
    IPT_POLICY_INPUT="$(iptables -L INPUT -n | head -1 | grep -oP '(?<=policy )\S+(?=\))')"
    if [[ -n "${IPT_POLICY_INPUT:-}" ]]; then
        FW_CONFIGURED=1
        if [[ "${IPT_POLICY_INPUT}" == "DROP" || "${IPT_POLICY_INPUT}" == "REJECT" ]]; then
            pass "iptables INPUT policy: ${IPT_POLICY_INPUT}"
        else
            fail "iptables INPUT policy: ${IPT_POLICY_INPUT} - allows traffic by default" \
                 "iptables -P INPUT DROP"
        fi
    fi
else
    fail "No active firewall detected (UFW, nftables, iptables)" "apt install -y ufw && ufw enable"
fi
[[ "${FW_CONFIGURED}" -eq 0 ]] && fail "No active firewall detected" "ufw enable"

declare -A SYSCTL_EXPECTED=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.default.accept_source_route"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.secure_redirects"]="0"
    ["net.ipv4.conf.default.secure_redirects"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.conf.all.rp_filter"]="1"
    ["net.ipv4.conf.default.rp_filter"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv6.conf.all.accept_ra"]="0"
    ["net.ipv6.conf.all.accept_redirects"]="0"
)

if have_cmd sysctl; then
    for key in "${!SYSCTL_EXPECTED[@]}"; do
        expected="${SYSCTL_EXPECTED[$key]}"
        actual="$(sysctl -n "${key}" 2>/dev/null)"
        if [[ -z "${actual}" ]]; then
            info "sysctl ${key} is unavailable in this kernel - skipped"
        elif [[ "${actual}" == "${expected}" ]]; then
            pass "sysctl ${key} = ${actual} (expected: ${expected})"
        else
            fail "sysctl ${key} = ${actual} (expected: ${expected})" \
                 "echo '${key} = ${expected}' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w ${key}=${expected}"
        fi
    done
else
    warn "sysctl utility is unavailable"
fi

# ============================================================================
# 4. USERS, PERMISSIONS, ACL, AND SSH
# ============================================================================

log_section "4. USER ACCOUNTS, PERMISSIONS, AND SSH SERVICE"

UID0_USERS="$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')"
if [[ -z "${UID0_USERS}" ]]; then
    pass "Only root has UID 0"
else
    fail "Additional accounts with UID 0 detected: ${UID0_USERS//$'\n'/, }" \
         "usermod -u <new_uid> <user> or remove the account"
fi

if [[ -r /etc/shadow ]]; then
    EMPTY_PW_USERS="$(awk -F: '($2 == "" ) {print $1}' /etc/shadow)"
    if [[ -z "${EMPTY_PW_USERS}" ]]; then
        pass "No accounts with empty passwords detected"
    else
        fail "Accounts with EMPTY passwords: ${EMPTY_PW_USERS//$'\n'/, }" \
             "passwd -l <user> or set a password: passwd <user>"
    fi
    LOCKED_MISMATCH="$(awk -F: '($2 !~ /^!|^\*/ && $2 != "") {print $1}' /etc/shadow | wc -l)"
    info "Accounts with active password hashes: ${LOCKED_MISMATCH}"
else
    warn "/etc/shadow is not readable"
fi

check_perm() {
    local path="$1" expected_modes="$2" expected_owner="$3" expected_group="$4"
    [[ -e "${path}" ]] || { info "${path} does not exist - skipped"; return; }

    local actual_mode actual_owner actual_group
    actual_mode="$(stat -c '%a' "${path}")"
    actual_owner="$(stat -c '%U' "${path}")"
    actual_group="$(stat -c '%G' "${path}")"

    local mode_ok=0 actual_num=$((10#${actual_mode:-0}))
    IFS='|' read -ra modes_arr <<< "${expected_modes}"
    for m in "${modes_arr[@]}"; do
        [[ "${actual_num}" -eq $((10#${m})) ]] && mode_ok=1
    done

    if [[ "${mode_ok}" -eq 1 ]]; then
        pass "${path}: permissions ${actual_mode} (expected: ${expected_modes})"
    else
        fail "${path}: permissions ${actual_mode} (expected: ${expected_modes})" \
             "chmod $(echo "${expected_modes}" | cut -d'|' -f1) ${path}"
    fi

    if [[ "${actual_owner}" == "${expected_owner}" && "${actual_group}" == "${expected_group}" ]]; then
        pass "${path}: owner ${actual_owner}:${actual_group}"
    else
        fail "${path}: owner ${actual_owner}:${actual_group} (expected: ${expected_owner}:${expected_group})" \
             "chown ${expected_owner}:${expected_group} ${path}"
    fi
}

# On Debian/Ubuntu /etc/shadow and /etc/gshadow typically use group 'shadow' (0640)
check_perm "/etc/shadow"   "000|600|0400|640|0640" "root" "shadow"
check_perm "/etc/gshadow"  "000|600|0400|640|0640" "root" "shadow"
check_perm "/etc/passwd"   "644|0644"              "root" "root"
check_perm "/etc/group"    "644|0644"              "root" "root"
check_perm "/etc/crontab"  "600|0600|644"          "root" "root"

if have_cmd getfacl; then
    for dir in /var/log /etc /home; do
        [[ -d "${dir}" ]] || continue
        ACL_ENTRIES="$(getfacl -R -s "${dir}" 2>/dev/null | grep -c '^# file:')"
        if [[ "${ACL_ENTRIES}" -gt 0 ]]; then
            info "${dir}: objects with non-standard ACLs: ${ACL_ENTRIES} (manual inspection required)"
        else
            pass "${dir}: no non-standard ACLs detected"
        fi
    done
else
    warn "getfacl utility not found (acl package)" "apt install -y acl"
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "${SSHD_CONFIG}" ]]; then
    get_sshd_value() {
        grep -iE "^\s*${1}\s+" "${SSHD_CONFIG}" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v '^\s*#' | awk '{print $2}' | tail -1
    }

    PERMIT_ROOT="$(get_sshd_value PermitRootLogin)"
    if [[ "${PERMIT_ROOT,,}" == "no" ]]; then
        pass "PermitRootLogin no"
    else
        fail "PermitRootLogin is not explicitly set to 'no' (current: ${PERMIT_ROOT:-default})" \
             "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config.d/50-cis.conf && systemctl restart sshd"
    fi

    PASS_AUTH="$(get_sshd_value PasswordAuthentication)"
    if [[ "${PASS_AUTH,,}" == "no" ]]; then
        pass "PasswordAuthentication no"
    else
        warn "PasswordAuthentication is not explicitly set to 'no' (current: ${PASS_AUTH:-default yes})" \
             "echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/50-cis.conf && systemctl restart sshd"
    fi

    PROTO="$(get_sshd_value Protocol)"
    if [[ -z "${PROTO}" || "${PROTO}" == "2" ]]; then
        pass "SSH Protocol 2 / modern OpenSSH"
    else
        fail "SSH Protocol = '${PROTO}' - legacy protocol configuration detected" \
             "Remove Protocol 1 directive from sshd_config"
    fi

    EMPTY_PASS_SSH="$(get_sshd_value PermitEmptyPasswords)"
    if [[ "${EMPTY_PASS_SSH,,}" == "no" || -z "${EMPTY_PASS_SSH}" ]]; then
        pass "PermitEmptyPasswords no / unset (default no)"
    else
        fail "PermitEmptyPasswords = '${EMPTY_PASS_SSH}'" \
             "echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config.d/50-cis.conf && systemctl restart sshd"
    fi

    X11_FWD="$(get_sshd_value X11Forwarding)"
    if [[ "${X11_FWD,,}" == "no" ]]; then
        pass "X11Forwarding no"
    else
        warn "X11Forwarding is not explicitly disabled (current: ${X11_FWD:-unset})" \
             "echo 'X11Forwarding no' >> /etc/ssh/sshd_config.d/50-cis.conf && systemctl restart sshd"
    fi

    MAX_AUTH_TRIES="$(get_sshd_value MaxAuthTries)"
    if [[ -n "${MAX_AUTH_TRIES}" && "${MAX_AUTH_TRIES}" -le 4 ]]; then
        pass "MaxAuthTries = ${MAX_AUTH_TRIES} (<=4)"
    else
        warn "MaxAuthTries = '${MAX_AUTH_TRIES:-unset (default 6)}'" \
             "echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config.d/50-cis.conf && systemctl restart sshd"
    fi

    CIPHERS="$(get_sshd_value Ciphers)"
    if [[ -n "${CIPHERS}" ]]; then
        if echo "${CIPHERS}" | grep -qiE 'arcfour|3des|blowfish|cbc'; then
            fail "Weak SSH ciphers enabled: ${CIPHERS}" \
                 "Set Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
        else
            pass "Ciphers defined explicitly, no weak algorithms detected: ${CIPHERS}"
        fi
    else
        info "Ciphers directive is not set explicitly - using default OpenSSH set"
    fi

    SSHD_PERM="$(stat -c '%a' "${SSHD_CONFIG}")"
    if [[ $((10#${SSHD_PERM:-0})) -eq 600 || $((10#${SSHD_PERM:-0})) -eq 644 ]]; then
        pass "${SSHD_CONFIG}: permissions ${SSHD_PERM}"
    else
        warn "${SSHD_CONFIG}: permissions ${SSHD_PERM} (recommended 0600)" \
             "chmod 600 ${SSHD_CONFIG}"
    fi
else
    fail "File ${SSHD_CONFIG} not found" "apt install -y openssh-server"
fi

# ============================================================================
# 5. SERVICES AND INSTALLED PACKAGES (DEB / APT)
# ============================================================================

log_section "5. SERVICES, UPDATES, AND DEB PACKAGE INTEGRITY"

INSECURE_SERVICES=(telnet.socket telnet.service rsh.socket rsh.service \
                    rlogin.socket rexec.socket vsftpd.service ftp.service \
                    tftp.service tftp.socket ypserv.service ypbind.service \
                    nis.service xinetd.service)

if have_cmd systemctl; then
    FOUND_INSECURE=0
    for svc in "${INSECURE_SERVICES[@]}"; do
        if svc_loaded "${svc}"; then
            state="$(systemctl is-active "${svc}" 2>/dev/null)"
            enabled="$(systemctl is-enabled "${svc}" 2>/dev/null)"
            if [[ "${state}" == "active" || "${enabled}" == "enabled" ]]; then
                fail "Insecure service active/enabled: ${svc} (active=${state}, enabled=${enabled})" \
                     "systemctl disable --now ${svc} && apt purge -y <service-package>"
                FOUND_INSECURE=1
            else
                info "Insecure service ${svc} installed, but inactive and disabled on boot"
            fi
        fi
    done
    [[ "${FOUND_INSECURE}" -eq 0 ]] && pass "No active insecure services (telnet/rsh/ftp/tftp/NIS) detected"

    ACTIVE_SVC_COUNT="$(systemctl list-units --type=service --state=running | grep -c '\.service')"
    info "Total running services (systemctl --state=running): ${ACTIVE_SVC_COUNT}"
else
    warn "systemctl is unavailable - insecure services check skipped"
fi

if have_cmd debsums; then
    info "Running package integrity check (debsums -c)..."
    DEBSUMS_OUTPUT="$(debsums -c 2>&1)"
    CRITICAL_BIN_CHANGES="$(echo "${DEBSUMS_OUTPUT}" | grep -E ' /(s?bin|usr/s?bin)/')"

    if [[ -z "${CRITICAL_BIN_CHANGES}" ]]; then
        pass "No modified binary files in /bin, /sbin, /usr/bin, /usr/sbin"
    else
        CHANGE_COUNT="$(echo "${CRITICAL_BIN_CHANGES}" | grep -cv '^$')"
        fail "Modifications detected in system binary files, affected objects: ${CHANGE_COUNT}" \
             "apt-get --reinstall install <package>"
        echo "${CRITICAL_BIN_CHANGES}" | head -20 | while IFS= read -r line; do
            log_raw "         ${line}"
        done
        [[ "${CHANGE_COUNT}" -gt 20 ]] && log_raw "         ... (showing first 20 of ${CHANGE_COUNT})"
    fi
else
    warn "debsums utility is not installed. Binary checksum verification skipped." \
         "apt install -y debsums"
fi

if have_cmd apt; then
    info "Checking available package updates via apt..."
    apt-get update -qq >/dev/null 2>&1 || true
    UPGRADABLE="$(apt list --upgradable 2>/dev/null | grep -v 'Listing...' || true)"
    if [[ -n "${UPGRADABLE}" ]]; then
        UPDATE_COUNT="$(echo "${UPGRADABLE}" | grep -cv '^$')"
        warn "Package updates available: ~${UPDATE_COUNT}" \
             "apt update && apt upgrade -y"
    else
        pass "System is fully updated"
    fi
else
    warn "apt utility not found"
fi

# ============================================================================
# 6. GRUB2 BOOTLOADER, CONSOLE, AND APPARMOR / SELINUX (CIS 1.4 / 1.6)
# ============================================================================

log_section "6. GRUB2 BOOTLOADER, CONSOLE, AND APPARMOR/SELINUX"

GRUB_CFG=""
for cfg in /boot/grub/grub.cfg /boot/efi/EFI/debian/grub.cfg /boot/efi/EFI/ubuntu/grub.cfg; do
    if [[ -f "${cfg}" ]]; then
        GRUB_CFG="${cfg}"
        break
    fi
done

if [[ -n "${GRUB_CFG}" ]]; then
    if grep -qE '^\s*password' "${GRUB_CFG}" || grep -qE '^\s*password_pbkdf2' "${GRUB_CFG}" || [[ -f /etc/grub.d/40_custom_user ]]; then
        pass "GRUB2 is password protected"
    else
        fail "GRUB2 bootloader is NOT password protected (CIS 1.4.2)" \
             "grub-mkpasswd-pbkdf2 and configure user/password in /etc/grub.d/40_custom"
    fi

    GRUB_PERM="$(stat -c '%a' "${GRUB_CFG}")"
    if [[ $((10#${GRUB_PERM:-0})) -eq 600 || $((10#${GRUB_PERM:-0})) -eq 400 ]]; then
        pass "${GRUB_CFG}: permissions ${GRUB_PERM}"
    else
        fail "${GRUB_CFG}: permissions ${GRUB_PERM} (expected 0600/0400)" \
             "chmod 600 ${GRUB_CFG}"
    fi
else
    warn "GRUB2 configuration file not found in standard paths"
fi

# On Debian/Ubuntu the primary LSM is AppArmor, but SELinux may also be installed
if have_cmd aa-status; then
    if aa-status --enabled 2>/dev/null; then
        pass "AppArmor is active and enabled (CIS 1.6)"
    else
        fail "AppArmor is DISABLED" "systemctl enable --now apparmor"
    fi
elif have_cmd getenforce; then
    SELINUX_STATE="$(getenforce)"
    if [[ "${SELINUX_STATE}" == "Enforcing" ]]; then
        pass "SELinux is active and in Enforcing mode"
    else
        warn "SELinux state: ${SELINUX_STATE}" "setenforce 1"
    fi
else
    fail "Neither AppArmor (aa-status) nor SELinux (getenforce) utilities were found" \
         "apt install -y apparmor apparmor-utils && systemctl enable --now apparmor"
fi

if svc_loaded "debug-shell.service"; then
    DEBUG_SHELL_ACTIVE="$(systemctl is-active debug-shell.service 2>/dev/null)"
    if [[ "${DEBUG_SHELL_ACTIVE}" == "active" ]]; then
        fail "debug-shell.service is ACTIVE (provides root shell on TTY9)" \
             "systemctl mask --now debug-shell.service"
    else
        pass "debug-shell.service is not active"
    fi
fi

# ============================================================================
# 7. KERNEL & MEMORY PROTECTION
# ============================================================================

log_section "7. KERNEL HARDENING AND MEMORY PROTECTION"

ASLR_VAL="$(sysctl -n kernel.randomize_va_space || echo 0)"
if [[ "${ASLR_VAL}" -eq 2 ]]; then
    pass "ASLR is fully enabled (kernel.randomize_va_space = 2)"
elif [[ "${ASLR_VAL}" -eq 1 ]]; then
    warn "ASLR is partially enabled (kernel.randomize_va_space = 1)" \
         "sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-cis-hardening.conf"
else
    fail "ASLR is DISABLED (kernel.randomize_va_space = ${ASLR_VAL})" \
         "sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-cis-hardening.conf"
fi

PTRACE_VAL="$(sysctl -n kernel.yama.ptrace_scope || echo 0)"
if [[ "${PTRACE_VAL}" -ge 1 ]]; then
    pass "ptrace scope is restricted (kernel.yama.ptrace_scope = ${PTRACE_VAL})"
else
    warn "ptrace is unrestricted (kernel.yama.ptrace_scope = 0)" \
         "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w kernel.yama.ptrace_scope=1"
fi

DUMPABLE="$(sysctl -n fs.suid_dumpable || echo 1)"
if [[ "${DUMPABLE}" -eq 0 ]]; then
    pass "Core dumps for SUID processes are disabled (fs.suid_dumpable = 0)"
else
    fail "SUID processes can generate core dumps (fs.suid_dumpable = ${DUMPABLE})" \
         "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w fs.suid_dumpable=0"
fi

if [[ -f /etc/security/limits.conf ]]; then
    if grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null; then
        pass "Core dump creation restricted in limits.conf (* hard core 0)"
    else
        warn "Restriction 'hard core 0' not found in /etc/security/limits.conf" \
             "echo '* hard core 0' >> /etc/security/limits.d/10-cis-coredump.conf"
    fi
fi

KEXEC_VAL="$(sysctl -n kernel.kexec_load_disabled || echo 0)"
if [[ "${KEXEC_VAL}" -eq 1 ]]; then
    pass "Kernel loading via kexec_load is disabled (kernel.kexec_load_disabled = 1)"
else
    warn "kexec_load is allowed (kernel.kexec_load_disabled = 0)" \
         "echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w kernel.kexec_load_disabled=1"
fi

# ============================================================================
# 8. AUDIT SUMMARY
# ============================================================================

log_section "8. AUDIT SUMMARY"

TOTAL_CHECKS=$((COUNT_PASS + COUNT_WARN + COUNT_FAIL))
log_raw "  ${C_GREEN}PASS : ${COUNT_PASS}${C_RESET}"
log_raw "  ${C_YELLOW}WARN : ${COUNT_WARN}${C_RESET}"
log_raw "  ${C_RED}FAIL : ${COUNT_FAIL}${C_RESET}"
log_raw "  INFO : ${COUNT_INFO}"
log_raw "  Total classified checks: ${TOTAL_CHECKS}"

if [[ "${COUNT_FAIL}" -gt 0 ]]; then
    log_raw ""
    log_raw "  ${C_RED}${C_BOLD}RESULT: Critical non-compliances detected (FAIL). Remediation required.${C_RESET}"
    EXIT_CODE=2
elif [[ "${COUNT_WARN}" -gt 0 ]]; then
    log_raw ""
    log_raw "  ${C_YELLOW}${C_BOLD}RESULT: No critical non-compliances, but warnings exist (WARN).${C_RESET}"
    EXIT_CODE=1
else
    log_raw ""
    log_raw "  ${C_GREEN}${C_BOLD}RESULT: All checks passed successfully.${C_RESET}"
    EXIT_CODE=0
fi

# ============================================================================
# 9. SAVE TEXT REPORT
# ============================================================================

{
    echo "==================================================================="
    echo " Security Audit Report (CIS / ISO 27001) - Debian/Ubuntu Linux"
    echo " Host: ${HOSTNAME_FQDN}  Date: ${RUN_TS}"
    echo "==================================================================="
    cat "${TMP_REPORT}"
} >> "${REPORT_FILE}"

if [[ $? -eq 0 ]]; then
    log_raw ""
    log_raw "Text report saved/updated : ${REPORT_FILE}"
else
    log_raw ""
    log_raw "${C_YELLOW}[WARN] Failed to write to ${REPORT_FILE}${C_RESET}"
fi

# ============================================================================
# 10. GENERATE HTML REPORT
# ============================================================================

generate_html_report() {
    local total=$((COUNT_PASS + COUNT_WARN + COUNT_FAIL))
    local score=0
    local p_pct=0 w_pct=0 f_pct=0

    if [[ ${total} -gt 0 ]]; then
        score=$(( (COUNT_PASS * 100) / total ))
        p_pct=$(( (COUNT_PASS * 100) / total ))
        w_pct=$(( (COUNT_WARN * 100) / total ))
        f_pct=$(( 100 - p_pct - w_pct ))
    fi

    local status_badge_class="status-pass"
    local status_text="Compliant"
    if [[ ${COUNT_FAIL} -gt 0 ]]; then
        status_badge_class="status-fail"
        status_text="Immediate Remediation Required"
    elif [[ ${COUNT_WARN} -gt 0 ]]; then
        status_badge_class="status-warn"
        status_text="Requires Attention"
    fi

    {
        cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit — ${HOSTNAME_FQDN}</title>
<style>
:root {
  --bg-main: #0b0f19;
  --bg-card: #151c2c;
  --bg-hover: #1e293b;
  --border-color: #2e3a52;
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;

  --pass-color: #10b981;
  --pass-bg: rgba(16, 185, 129, 0.12);
  --warn-color: #f59e0b;
  --warn-bg: rgba(245, 158, 11, 0.12);
  --fail-color: #ef4444;
  --fail-bg: rgba(239, 68, 68, 0.12);
  --info-color: #3b82f6;
  --info-bg: rgba(59, 130, 246, 0.12);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background-color: var(--bg-main);
  color: var(--text-main);
  line-height: 1.5;
  padding: 30px 20px;
}

.container {
  max-width: 1280px;
  margin: 0 auto;
}

/* Header UI */
.header-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 28px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 20px;
}

.header-title h1 {
  font-size: 24px;
  font-weight: 700;
  margin-bottom: 6px;
  letter-spacing: -0.02em;
}

.header-title p {
  color: var(--text-muted);
  font-size: 14px;
}

.status-tag {
  display: inline-block;
  padding: 6px 14px;
  border-radius: 9999px;
  font-size: 13px;
  font-weight: 600;
}
.status-pass { background: var(--pass-bg); color: var(--pass-color); border: 1px solid var(--pass-color); }
.status-warn { background: var(--warn-bg); color: var(--warn-color); border: 1px solid var(--warn-color); }
.status-fail { background: var(--fail-bg); color: var(--fail-color); border: 1px solid var(--fail-color); }

/* Executive Grid & Score Ring */
.dashboard-grid {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 24px;
  margin-bottom: 24px;
}

@media (max-width: 900px) {
  .dashboard-grid { grid-template-columns: 1fr; }
}

.score-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
}

.score-ring {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  background: conic-gradient(var(--pass-color) ${score}%, var(--border-color) 0);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 12px;
  position: relative;
}

.score-ring-inner {
  width: 96px;
  height: 96px;
  border-radius: 50%;
  background: var(--bg-card);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 26px;
  font-weight: 800;
}

.kpi-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
}

.kpi-title {
  color: var(--text-muted);
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 8px;
  text-transform: uppercase;
}

.kpi-value {
  font-size: 32px;
  font-weight: 700;
}

.kpi-card.pass .kpi-value { color: var(--pass-color); }
.kpi-card.warn .kpi-value { color: var(--warn-color); }
.kpi-card.fail .kpi-value { color: var(--fail-color); }
.kpi-card.info .kpi-value { color: var(--info-color); }

/* System Metadata Box */
.meta-grid {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 24px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  font-size: 13px;
}

.meta-item strong {
  display: block;
  color: var(--text-muted);
  font-size: 11px;
  text-transform: uppercase;
  margin-bottom: 2px;
}

/* Controls & Filter Bar */
.filter-bar {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
}

.filter-chips {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.chip {
  background: var(--bg-main);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.chip:hover, .chip.active {
  background: var(--bg-hover);
  color: var(--text-main);
  border-color: var(--text-muted);
}

.search-input {
  background: var(--bg-main);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 13px;
  outline: none;
  min-width: 240px;
}

/* Audit Results Table */
.results-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

th {
  background: #0f1523;
  color: var(--text-muted);
  font-size: 12px;
  text-transform: uppercase;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border-color);
}

th:first-child,
td:first-child {
  text-align: center;
  width: 110px;
}

td {
  padding: 16px 18px;
  border-bottom: 1px solid var(--border-color);
  font-size: 14px;
  vertical-align: middle;
}

tr:last-child td { border-bottom: none; }
tr:hover { background: var(--bg-hover); }

.badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  line-height: 1;
}

.badge-PASS { background: var(--pass-bg); color: var(--pass-color); border: 1px solid var(--pass-color); }
.badge-WARN { background: var(--warn-bg); color: var(--warn-color); border: 1px solid var(--warn-color); }
.badge-FAIL { background: var(--fail-bg); color: var(--fail-color); border: 1px solid var(--fail-color); }
.badge-INFO { background: var(--info-bg); color: var(--info-color); border: 1px solid var(--info-color); }

.remediation-block {
  margin-top: 10px;
  background: #0b0f19;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 10px 12px;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 12px;
  color: #a5b4fc;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.copy-btn {
  background: var(--border-color);
  color: var(--text-main);
  border: none;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 11px;
  cursor: pointer;
}
.copy-btn:hover { background: var(--text-muted); }

footer {
  margin-top: 40px;
  text-align: center;
  color: var(--text-muted);
  font-size: 13px;
}

@media print {
  body { background: #fff; color: #000; padding: 0; }
  .filter-bar, .copy-btn { display: none; }
  .header-card, .score-card, .kpi-card, .meta-grid, .results-card {
    border: 1px solid #ccc;
    background: #fff;
    color: #000;
  }
}
</style>
</head>
<body>

<div class="container">
  <!-- Header Section -->
  <div class="header-card">
    <div class="header-title">
      <h1>Debian/Ubuntu Security Audit Report (CIS / ISO 27001)</h1>
      <p>Automated technical system compliance verification</p>
    </div>
    <span class="status-tag ${status_badge_class}">${status_text}</span>
  </div>

  <!-- Executive Summary Section -->
  <div class="dashboard-grid">
    <div class="score-card">
      <div class="score-ring">
        <div class="score-ring-inner">${score}%</div>
      </div>
      <div style="font-size:14px; font-weight:600;">Compliance Index</div>
      <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">Based on CIS Benchmarks checks</div>
    </div>

    <div class="kpi-cards">
      <div class="kpi-card pass">
        <span class="kpi-title">Passed (PASS)</span>
        <span class="kpi-value">${COUNT_PASS}</span>
      </div>
      <div class="kpi-card warn">
        <span class="kpi-title">Warnings (WARN)</span>
        <span class="kpi-value">${COUNT_WARN}</span>
      </div>
      <div class="kpi-card fail">
        <span class="kpi-title">Failures (FAIL)</span>
        <span class="kpi-value">${COUNT_FAIL}</span>
      </div>
      <div class="kpi-card info">
        <span class="kpi-title">Information (INFO)</span>
        <span class="kpi-value">${COUNT_INFO}</span>
      </div>
    </div>
  </div>

  <!-- Metadata System Box -->
  <div class="meta-grid">
    <div class="meta-item"><strong>Target Host</strong>${HOSTNAME_FQDN}</div>
    <div class="meta-item"><strong>Operating System</strong>${OS_INFO}</div>
    <div class="meta-item"><strong>Kernel Version</strong>${KERNEL_VER}</div>
    <div class="meta-item"><strong>Uptime</strong>${UPTIME_INFO}</div>
    <div class="meta-item"><strong>Scan Date</strong>${RUN_TS}</div>
    <div class="meta-item"><strong>Auditor</strong>${AUDITOR_NAME} (v${SCRIPT_VERSION})</div>
  </div>

  <!-- Interactive Controls Bar -->
  <div class="filter-bar">
    <div class="filter-chips">
      <button class="chip active" onclick="filterResults('ALL', this)">All Results</button>
      <button class="chip" onclick="filterResults('FAIL', this)">FAIL (${COUNT_FAIL})</button>
      <button class="chip" onclick="filterResults('WARN', this)">WARN (${COUNT_WARN})</button>
      <button class="chip" onclick="filterResults('PASS', this)">PASS (${COUNT_PASS})</button>
      <button class="chip" onclick="filterResults('INFO', this)">INFO (${COUNT_INFO})</button>
    </div>
    <input type="text" id="searchInput" class="search-input" placeholder="Search checks or sections..." onkeyup="searchTable()">
  </div>

  <!-- Results Table -->
  <div class="results-card">
    <table id="auditTable">
      <thead>
        <tr>
          <th style="width: 110px; text-align: center;">Status</th>
          <th style="width: 280px;">Section</th>
          <th>Audit Finding / Actionable Remediation</th>
        </tr>
      </thead>
      <tbody>
HTMLHEAD

        for item in "${FINDINGS[@]}"; do
            IFS=$'\x1f' read -r level sec msg rem <<< "${item}"
            local level_esc sec_esc msg_esc rem_esc js_rem_esc
            level_esc="$(html_escape "${level}")"
            sec_esc="$(html_escape "${sec:-—}")"
            msg_esc="$(html_escape "${msg}")"
            rem_esc="$(html_escape "${rem}")"
            js_rem_esc="${rem_esc//\'/\\\'}"

            echo "<tr class=\"audit-row\" data-status=\"${level_esc}\">"
            echo "  <td style=\"text-align: center;\"><span class=\"badge badge-${level_esc}\">${level_esc}</span></td>"
            echo "  <td><strong style=\"font-size:13px; color:var(--text-main);\">${sec_esc}</strong></td>"
            echo "  <td>"
            echo "    <div>${msg_esc}</div>"
            if [[ -n "${rem_esc}" ]]; then
                echo "    <div class=\"remediation-block\">"
                echo "      <span><strong>Fix:</strong> <code>${rem_esc}</code></span>"
                echo "      <button class=\"copy-btn\" onclick=\"navigator.clipboard.writeText('${js_rem_esc}')\">Copy</button>"
                echo "    </div>"
            fi
            echo "  </td>"
            echo "</tr>"
        done

        cat <<HTMLFOOT
      </tbody>
    </table>
  </div>

  <footer>
    Generated automatically by <code>debian_cis_audit.sh</code> (v${SCRIPT_VERSION}) &copy; ${AUDITOR_NAME}
  </footer>
</div>

<script>
function filterResults(status, btn) {
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');

  const rows = document.querySelectorAll('.audit-row');
  rows.forEach(row => {
    if (status === 'ALL' || row.getAttribute('data-status') === status) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}

function searchTable() {
  const query = document.getElementById('searchInput').value.toLowerCase();
  const rows = document.querySelectorAll('.audit-row');

  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    row.style.display = text.includes(query) ? '' : 'none';
  });
}
</script>

</body>
</html>
HTMLFOOT
    } > "${HTML_REPORT_FILE}"

    if [[ $? -eq 0 ]]; then
        log_raw "HTML report saved      : ${HTML_REPORT_FILE}"
    else
        log_raw "${C_YELLOW}[WARN] Failed to write HTML report to ${HTML_REPORT_FILE}${C_RESET}"
    fi
}

generate_html_report
exit "${EXIT_CODE:-0}"
