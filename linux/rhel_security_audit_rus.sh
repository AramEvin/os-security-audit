#!/usr/bin/env bash
# IT Security LLC
# rhel_cis_audit.sh (v3.0)
#
# Комплексный технический аудит безопасности Red Hat Enterprise Linux (RHEL)
# систем (RPM/Linux). Ориентирован на технические контроли ISO/IEC 27001
# (Annex A: A.8, A.12, A.13) и методологию CIS Benchmarks for Linux
# (Level 1 / Level 2).
#
# Скрипт только ЧИТАЕТ состояние системы (read-only аудит).
#   [PASS] - контроль выполнен
#   [WARN] - отклонение от рекомендации / Level 2 / требует внимания
#   [FAIL] - критическое несоответствие (Level 1)
#   [INFO] - информационная строка, не влияет на итоговую оценку
#
# Вывод:
#   - консоль (цветной)
#   - /var/log/rhel_cis_audit_report.log   (текстовый отчёт, накопительно)
#   - /var/log/rhel_cis_audit_report.html  (современный интерактивный веб-отчёт)

set -u
set -o pipefail

# ============================================================================
# 0. ГЛОБАЛЬНЫЕ ПАРАМЕТРЫ И ИНИЦИАЛИЗАЦИЯ
# ============================================================================

readonly SCRIPT_VERSION="3.0"
readonly AUDITOR_NAME="IT Security LLC"
readonly REPORT_FILE="/var/log/rhel_cis_audit_report.log"
readonly HTML_REPORT_FILE="/var/log/rhel_cis_audit_report.html"
readonly TMP_REPORT="$(mktemp /tmp/rhel_cis_audit.XXXXXX)"
readonly HOSTNAME_FQDN="$(hostname -f  || hostname)"
readonly RUN_TS="$(date '+%Y-%m-%d %H:%M:%S %Z')"
readonly KERNEL_VER="$(uname -r  || echo 'N/A')"
readonly UPTIME_INFO="$(uptime -p  || uptime  || echo 'N/A')"

COUNT_PASS=0
COUNT_WARN=0
COUNT_FAIL=0
COUNT_INFO=0

declare -a FINDINGS=()      # LEVEL<0x1f>SECTION<0x1f>MESSAGE<0x1f>REMEDIATION
CURRENT_SECTION="1. ИНИЦИАЛИЗАЦИЯ И СВЕДЕНИЯ ОБ ОС"

if [[ -t 1 ]]; then
    C_RED="\033[1;31m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"
    C_BLUE="\033[1;34m"; C_BOLD="\033[1m"; C_RESET="\033[0m"
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

cleanup() { rm -f "${TMP_REPORT}"  || true; }
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
    [[ -n "${rem}" ]] && log_raw "         -> Рекомендация: ${rem}"
    FINDINGS+=("WARN"$'\x1f'"${CURRENT_SECTION}"$'\x1f'"${msg}"$'\x1f'"${rem}")
}
fail() {
    local msg="$1" rem="${2:-}"
    COUNT_FAIL=$((COUNT_FAIL+1))
    log_raw "  ${C_RED}[FAIL]${C_RESET} ${msg}"
    [[ -n "${rem}" ]] && log_raw "         -> Рекомендация: ${rem}"
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
    state="$(systemctl show -p LoadState --value "$1" )"
    [[ "${state}" == "loaded" ]]
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"
    printf '%s' "${s}"
}

# ============================================================================
# 1. ПРОВЕРКА ЗАПУСКА ОТ ROOT И СВЕДЕНИЯ ОБ ОС
# ============================================================================

log_section "1. ИНИЦИАЛИЗАЦИЯ И СВЕДЕНИЯ ОБ ОС"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${C_RED}${C_BOLD}[FAIL] Скрипт должен быть запущен от root (UID 0).${C_RESET}" >&2
    echo "Текущий пользователь: $(id -un) (UID $(id -u))" >&2
    echo "Повторите запуск: sudo bash $0" >&2
    exit 1
fi

log_raw "${C_BOLD}Технический аудит безопасности (CIS / ISO 27001) - Red Hat Enterprise Linux${C_RESET}"
log_raw "Версия скрипта : ${SCRIPT_VERSION}"
log_raw "Хост           : ${HOSTNAME_FQDN}"
log_raw "Дата/время     : ${RUN_TS}"
log_raw "Файл отчёта    : ${REPORT_FILE}"

OS_ID="unknown"
OS_ID_LIKE=""
OS_VERSION_ID="unknown"
OS_INFO="неизвестно"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_ID_LIKE="${ID_LIKE:-}"
    OS_VERSION_ID="${VERSION_ID:-unknown}"
    OS_INFO="${PRETTY_NAME:-${NAME:-неизвестно}}"
elif [[ -r /etc/redhat-release ]]; then
    OS_INFO="$(cat /etc/redhat-release )"
fi

RHEL_FAMILY=0
if [[ "${OS_ID}" =~ ^(rhel|redhat|rocky|almalinux|centos|ol)$ ]] || \
   [[ " ${OS_ID_LIKE} " == *" rhel "* ]] || \
   [[ " ${OS_ID_LIKE} " == *" fedora "* ]] || \
   [[ -r /etc/redhat-release ]]; then
    RHEL_FAMILY=1
fi

log_raw "ОС             : ${OS_INFO}"
log_raw "OS ID          : ${OS_ID}"
log_raw "OS VERSION_ID   : ${OS_VERSION_ID}"
log_raw "RHEL family    : $([[ ${RHEL_FAMILY} -eq 1 ]] && echo yes || echo no)"

if [[ ${RHEL_FAMILY} -ne 1 ]]; then
    warn "ОС не определена как RHEL/RHEL-compatible (${OS_INFO}); RHEL-специфичные проверки могут быть неприменимы" \
         "Запускайте этот аудит на RHEL 8/9/10 или совместимой RPM-системе и проверьте /etc/os-release"
else
    pass "Обнаружена RHEL/RHEL-compatible система: ${OS_INFO}"
fi

# ============================================================================
# 2. АУДИТ ПОДСИСТЕМЫ ЛОГИРОВАНИЯ (auditd / rsyslog / journald / logrotate)
# ============================================================================

log_section "2. ПОДСИСТЕМА ЛОГИРОВАНИЯ И АУДИТА (auditd / rsyslog / journald)"

AUDITD_ACTIVE="inactive"
if have_cmd systemctl; then
    if svc_loaded auditd.service; then
        AUDITD_ACTIVE="$(systemctl is-active auditd )"
        AUDITD_ENABLED="$(systemctl is-enabled auditd )"

        if [[ "${AUDITD_ACTIVE}" == "active" ]]; then
            pass "auditd активен (systemctl is-active: active)"
        else
            fail "auditd НЕ активен (текущее состояние: ${AUDITD_ACTIVE:-unknown})" \
                 "systemctl enable --now auditd"
        fi

        if [[ "${AUDITD_ENABLED}" == "enabled" ]]; then
            pass "auditd включен в автозагрузку (is-enabled: enabled)"
        else
            fail "auditd НЕ включен в автозагрузку (is-enabled: ${AUDITD_ENABLED:-unknown})" \
                 "systemctl enable auditd"
        fi
    else
        fail "Служба auditd не установлена (юнит auditd.service отсутствует)" \
             "dnf install audit audit-libs && systemctl enable --now auditd"
    fi
else
    warn "systemctl недоступен - невозможно проверить статус auditd"
fi

if [[ "${AUDITD_ACTIVE}" == "active" ]] && have_cmd auditctl; then
    AUDIT_RULES="$(auditctl -l )"
    RULES_COUNT="$(echo "${AUDIT_RULES}" | grep -cv '^$'  || echo 0)"

    if [[ "${RULES_COUNT}" -eq 0 ]] || echo "${AUDIT_RULES}" | grep -qi "no rules"; then
        fail "auditctl -l: активных правил аудита не обнаружено" \
             "cp /usr/share/audit/sample-rules/30-*.rules /etc/audit/rules.d/ && augenrules --load"
    else
        pass "Обнаружено правил аудита: ${RULES_COUNT}"
        if echo "${AUDIT_RULES}" | grep -q "/etc/passwd"; then
            pass "Есть правило аудита изменений /etc/passwd"
        else
            fail "Отсутствует правило аудита изменений /etc/passwd" \
                 "echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/rules.d/identity.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | grep -q "/etc/shadow"; then
            pass "Есть правило аудита изменений /etc/shadow"
        else
            fail "Отсутствует правило аудита изменений /etc/shadow" \
                 "echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/identity.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | grep -qE "/etc/sudoers"; then
            pass "Есть правило аудита изменений /etc/sudoers"
        else
            fail "Отсутствует правило аудита изменений /etc/sudoers" \
                 "echo '-w /etc/sudoers -p wa -k scope' >> /etc/audit/rules.d/scope.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | grep -q "execve"; then
            pass "Есть правило аудита вызовов execve"
        else
            warn "Отсутствует правило аудита execve (CIS 4.1.13)" \
                 "Добавить правила -a always,exit -F arch=b64 -S execve ... в /etc/audit/rules.d/exec.rules"
        fi
        if echo "${AUDIT_RULES}" | grep -qE "/etc/hosts|/etc/sysconfig/network|network"; then
            pass "Есть правило аудита изменений сетевой конфигурации"
        else
            warn "Отсутствует правило аудита изменений сетевой конфигурации (CIS 4.1.7)" \
                 "echo '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale' >> /etc/audit/rules.d/network.rules"
        fi
        if echo "${AUDIT_RULES}" | tail -1 | grep -q "^-e 2$" || auditctl -s  | grep -q "enabled 2"; then
            pass "Конфигурация auditd заблокирована в immutable-режиме (-e 2)"
        else
            warn "auditd не в immutable-режиме (-e 2)" \
                 "echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules && augenrules --load"
        fi
    fi
elif [[ "${AUDITD_ACTIVE}" == "active" ]]; then
    warn "Утилита auditctl не найдена - содержимое правил аудита не проверено"
fi

if have_cmd systemctl; then
    for svc in rsyslog systemd-journald; do
        if svc_loaded "${svc}.service"; then
            state="$(systemctl is-active "${svc}" )"
            if [[ "${state}" == "active" ]]; then
                pass "Служба ${svc} активна"
            else
                warn "Служба ${svc} не активна (состояние: ${state:-unknown})"
            fi
        else
            info "Юнит ${svc}.service отсутствует в системе"
        fi
    done
fi

if [[ -f /etc/systemd/journald.conf ]]; then
    if grep -qE '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf; then
        pass "journald сконфигурирован на постоянное хранение (Storage=persistent)"
    else
        warn "journald не настроен на Storage=persistent - журналы не переживут перезагрузку" \
             "mkdir -p /var/log/journal && sed -i 's/^#\\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf && systemctl restart systemd-journald"
    fi
fi

if [[ -f /etc/logrotate.conf ]]; then
    pass "Найден основной конфигурационный файл /etc/logrotate.conf"
    LR_ROTATE="$(grep -E '^\s*rotate\s+[0-9]+' /etc/logrotate.conf | awk '{print $2}' | head -1)"
    if [[ -n "${LR_ROTATE:-}" ]]; then
        if [[ "${LR_ROTATE}" -ge 4 ]]; then
            pass "Глубина ротации логов: ${LR_ROTATE} (>= 4)"
        else
            warn "Глубина ротации логов мала: ${LR_ROTATE} (рекомендуется >= 4)"
        fi
    else
        info "Параметр 'rotate' не задан явно в logrotate.conf"
    fi
    if grep -qE '^\s*compress\s*$' /etc/logrotate.conf; then
        pass "Сжатие ротированных логов включено (compress)"
    else
        warn "Сжатие логов (compress) не включено" \
             "echo 'compress' >> /etc/logrotate.conf"
    fi
    if [[ -d /etc/logrotate.d ]]; then
        LR_DROPINS="$(find /etc/logrotate.d -type f  | wc -l)"
        info "Найдено dropin-конфигураций в /etc/logrotate.d: ${LR_DROPINS}"
    fi
else
    fail "Файл /etc/logrotate.conf отсутствует" "dnf install logrotate"
fi

# ============================================================================
# 3. СКАНИРОВАНИЕ СЕТИ, ПОРТОВ И МЕЖСЕТЕВОГО ЭКРАНА
# ============================================================================

log_section "3. СЕТЕВАЯ БЕЗОПАСНОСТЬ И МЕЖСЕТЕВОЙ ЭКРАН"

if have_cmd ss; then
    info "Сбор данных открытых портов через 'ss -tulpn'"
    PORT_DATA="$(ss -tulpn )"
    echo "${PORT_DATA}" | tail -n +2 | while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        log_raw "         ${line}"
    done
    LISTEN_COUNT="$(echo "${PORT_DATA}" | grep -cE 'LISTEN|UNCONN')"
    info "Всего слушающих сокетов (TCP LISTEN / UDP UNCONN): ${LISTEN_COUNT}"
    WILDCARD_LISTEN="$(echo "${PORT_DATA}" | grep -E 'LISTEN' | grep -cE '0\.0\.0\.0:|\*:|\[::\]:')"
    if [[ "${WILDCARD_LISTEN}" -gt 0 ]]; then
        warn "Обнаружено ${WILDCARD_LISTEN} TCP-портов, слушающих на всех интерфейсах (0.0.0.0/::)" \
             "Ограничить bind-адрес прикладных сервисов конкретным интерфейсом; закрыть неиспользуемые порты в firewalld"
    fi
elif have_cmd netstat; then
    info "ss не найден, используется netstat -tulpn"
    netstat -tulpn  | tail -n +3 | while IFS= read -r line; do
        log_raw "         ${line}"
    done
else
    warn "Ни ss, ни netstat не найдены"
fi

FW_CONFIGURED=0
if have_cmd firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
    FW_CONFIGURED=1
    pass "firewalld активен"
    FW_ZONE="$(firewall-cmd --get-default-zone )"
    FW_TARGET="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-all  | grep -oP '(?<=target: )\S+')"
    info "Зона по умолчанию: ${FW_ZONE:-неизвестно}, target: ${FW_TARGET:-неизвестно}"
    if [[ "${FW_TARGET}" == "DROP" || "${FW_TARGET}" == "REJECT" || "${FW_TARGET}" == "default" ]]; then
        pass "Политика по умолчанию для зоны '${FW_ZONE}': ${FW_TARGET} (implicit deny, безопасно)"
    elif [[ "${FW_TARGET}" == "ACCEPT" ]]; then
        fail "Политика по умолчанию для зоны '${FW_ZONE}': ACCEPT - весь входящий трафик разрешён" \
             "firewall-cmd --permanent --zone=${FW_ZONE} --set-target=default && firewall-cmd --reload"
    else
        warn "Политика по умолчанию для зоны '${FW_ZONE}': ${FW_TARGET:-неизвестно} - проверьте вручную"
    fi
    FW_OPEN_SERVICES="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-services )"
    FW_OPEN_PORTS="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-ports )"
    info "Разрешённые сервисы в зоне '${FW_ZONE}': ${FW_OPEN_SERVICES:-нет}"
    info "Разрешённые порты в зоне '${FW_ZONE}': ${FW_OPEN_PORTS:-нет}"
elif have_cmd iptables; then
    IPT_POLICY_INPUT="$(iptables -L INPUT -n  | head -1 | grep -oP '(?<=policy )\S+(?=\))')"
    if [[ -n "${IPT_POLICY_INPUT:-}" ]]; then
        FW_CONFIGURED=1
        if [[ "${IPT_POLICY_INPUT}" == "DROP" || "${IPT_POLICY_INPUT}" == "REJECT" ]]; then
            pass "iptables INPUT policy: ${IPT_POLICY_INPUT}"
        else
            fail "iptables INPUT policy: ${IPT_POLICY_INPUT} - разрешает трафик по умолчанию" \
                 "iptables -P INPUT DROP"
        fi
    fi
else
    fail "Не обнаружено ни firewalld, ни iptables" "dnf install firewalld && systemctl enable --now firewalld"
fi
[[ "${FW_CONFIGURED}" -eq 0 ]] && fail "Активный межсетевой экран не обнаружен" "systemctl enable --now firewalld"

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
        actual="$(sysctl -n "${key}" )"
        if [[ -z "${actual}" ]]; then
            info "sysctl ${key} недоступен в данном ядре - пропущено"
        elif [[ "${actual}" == "${expected}" ]]; then
            pass "sysctl ${key} = ${actual} (ожидаемо: ${expected})"
        else
            fail "sysctl ${key} = ${actual} (ожидаемо: ${expected})" \
                 "echo '${key} = ${expected}' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w ${key}=${expected}"
        fi
    done
else
    warn "Утилита sysctl недоступна"
fi

# ============================================================================
# 4. ПОЛЬЗОВАТЕЛИ, ПРАВА ДОСТУПА, ACL И SSH
# ============================================================================

log_section "4. УЧЁТНЫЕ ЗАПИСИ, ПРАВА ДОСТУПА И СЛУЖБА SSH"

UID0_USERS="$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')"
if [[ -z "${UID0_USERS}" ]]; then
    pass "Только root имеет UID 0"
else
    fail "Дополнительные учётные записи с UID 0: ${UID0_USERS//$'\n'/, }" \
         "usermod -u <новый_uid> <пользователь> либо удалить учётную запись"
fi

if [[ -r /etc/shadow ]]; then
    EMPTY_PW_USERS="$(awk -F: '($2 == "" ) {print $1}' /etc/shadow)"
    if [[ -z "${EMPTY_PW_USERS}" ]]; then
        pass "Учётных записей с пустым паролем не обнаружено"
    else
        fail "Учётные записи с ПУСТЫМ паролем: ${EMPTY_PW_USERS//$'\n'/, }" \
             "passwd -l <пользователь> либо установить пароль: passwd <пользователь>"
    fi
    LOCKED_MISMATCH="$(awk -F: '($2 !~ /^!|^\*/ && $2 != "") {print $1}' /etc/shadow | wc -l)"
    info "Учётных записей с установленным hash пароля: ${LOCKED_MISMATCH}"
else
    warn "/etc/shadow недоступен для чтения"
fi

check_perm() {
    local path="$1" expected_modes="$2" expected_owner="$3" expected_group="$4"
    [[ -e "${path}" ]] || { info "${path} не существует - пропущено"; return; }

    local actual_mode actual_owner actual_group
    actual_mode="$(stat -c '%a' "${path}" )"
    actual_owner="$(stat -c '%U' "${path}" )"
    actual_group="$(stat -c '%G' "${path}" )"

    local mode_ok=0 actual_num=$((10#${actual_mode:-0}))
    IFS='|' read -ra modes_arr <<< "${expected_modes}"
    for m in "${modes_arr[@]}"; do
        [[ "${actual_num}" -eq $((10#${m})) ]] && mode_ok=1
    done

    if [[ "${mode_ok}" -eq 1 ]]; then
        pass "${path}: права ${actual_mode} (ожидались: ${expected_modes})"
    else
        fail "${path}: права ${actual_mode} (ожидались: ${expected_modes})" \
             "chmod $(echo "${expected_modes}" | cut -d'|' -f1) ${path}"
    fi

    if [[ "${actual_owner}" == "${expected_owner}" && "${actual_group}" == "${expected_group}" ]]; then
        pass "${path}: владелец ${actual_owner}:${actual_group}"
    else
        fail "${path}: владелец ${actual_owner}:${actual_group} (ожидалось: ${expected_owner}:${expected_group})" \
             "chown ${expected_owner}:${expected_group} ${path}"
    fi
}

check_perm "/etc/shadow"   "000|600|0400" "root" "root"
check_perm "/etc/gshadow"  "000|600|0400" "root" "root"
check_perm "/etc/passwd"   "644|0644"     "root" "root"
check_perm "/etc/group"    "644|0644"     "root" "root"
check_perm "/etc/crontab"  "600|0600|644" "root" "root"

if have_cmd getfacl; then
    for dir in /var/log /etc /home; do
        [[ -d "${dir}" ]] || continue
        ACL_ENTRIES="$(getfacl -R -s "${dir}"  | grep -c '^# file:')"
        if [[ "${ACL_ENTRIES}" -gt 0 ]]; then
            info "${dir}: объектов с нестандартными ACL: ${ACL_ENTRIES} (требуется ручная проверка)"
        else
            pass "${dir}: нестандартных ACL не обнаружено"
        fi
    done
else
    warn "Утилита getfacl не найдена (пакет acl)" "dnf install acl"
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "${SSHD_CONFIG}" ]]; then
    get_sshd_value() {
        grep -iE "^\s*${1}\s+" "${SSHD_CONFIG}"  | grep -v '^\s*#' | awk '{print $2}' | tail -1
    }

    PERMIT_ROOT="$(get_sshd_value PermitRootLogin)"
    if [[ "${PERMIT_ROOT,,}" == "no" ]]; then
        pass "PermitRootLogin no"
    else
        fail "PermitRootLogin не задан явно как 'no' (текущее: ${PERMIT_ROOT:-по умолчанию})" \
             "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd"
    fi

    PASS_AUTH="$(get_sshd_value PasswordAuthentication)"
    if [[ "${PASS_AUTH,,}" == "no" ]]; then
        pass "PasswordAuthentication no"
    else
        warn "PasswordAuthentication не задан явно как 'no' (текущее: ${PASS_AUTH:-по умолчанию yes})" \
             "echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && systemctl restart sshd"
    fi

    PROTO="$(get_sshd_value Protocol)"
    if [[ -z "${PROTO}" || "${PROTO}" == "2" ]]; then
        pass "SSH Protocol 2 / современный OpenSSH"
    else
        fail "SSH Protocol = '${PROTO}' - обнаружена конфигурация устаревшего протокола" \
             "Удалить директиву Protocol 1 из sshd_config"
    fi

    EMPTY_PASS_SSH="$(get_sshd_value PermitEmptyPasswords)"
    if [[ "${EMPTY_PASS_SSH,,}" == "no" || -z "${EMPTY_PASS_SSH}" ]]; then
        pass "PermitEmptyPasswords no / не задано (default no)"
    else
        fail "PermitEmptyPasswords = '${EMPTY_PASS_SSH}'" \
             "echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config && systemctl restart sshd"
    fi

    X11_FWD="$(get_sshd_value X11Forwarding)"
    if [[ "${X11_FWD,,}" == "no" ]]; then
        pass "X11Forwarding no"
    else
        warn "X11Forwarding не отключен явно (текущее: ${X11_FWD:-не задано})" \
             "echo 'X11Forwarding no' >> /etc/ssh/sshd_config && systemctl restart sshd"
    fi

    MAX_AUTH_TRIES="$(get_sshd_value MaxAuthTries)"
    if [[ -n "${MAX_AUTH_TRIES}" && "${MAX_AUTH_TRIES}" -le 4 ]]; then
        pass "MaxAuthTries = ${MAX_AUTH_TRIES} (<=4)"
    else
        warn "MaxAuthTries = '${MAX_AUTH_TRIES:-не задано (default 6)}'" \
             "echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config && systemctl restart sshd"
    fi

    CIPHERS="$(get_sshd_value Ciphers)"
    if [[ -n "${CIPHERS}" ]]; then
        if echo "${CIPHERS}" | grep -qiE 'arcfour|3des|blowfish|cbc'; then
            fail "Разрешены слабые шифры SSH: ${CIPHERS}" \
                 "Задать Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
        else
            pass "Ciphers заданы явно, слабых алгоритмов не обнаружено: ${CIPHERS}"
        fi
    else
        info "Директива Ciphers не задана явно - используется набор по умолчанию OpenSSH"
    fi

    SSHD_PERM="$(stat -c '%a' "${SSHD_CONFIG}" )"
    if [[ $((10#${SSHD_PERM:-0})) -eq 600 || $((10#${SSHD_PERM:-0})) -eq 644 ]]; then
        pass "${SSHD_CONFIG}: права доступа ${SSHD_PERM}"
    else
        warn "${SSHD_CONFIG}: права доступа ${SSHD_PERM} (рекомендуется 0600)" \
             "chmod 600 ${SSHD_CONFIG}"
    fi
else
    fail "Файл ${SSHD_CONFIG} не найден" "dnf install openssh-server"
fi

# ============================================================================
# 5. СЛУЖБЫ И УСТАНОВЛЕННЫЕ ПАКЕТЫ (RPM)
# ============================================================================

log_section "5. СЛУЖБЫ, ОБНОВЛЕНИЯ И ЦЕЛОСТНОСТЬ RPM"

INSECURE_SERVICES=(telnet.socket telnet.service rsh.socket rsh.service \
                    rlogin.socket rexec.socket vsftpd.service ftp.service \
                    tftp.service tftp.socket ypserv.service ypbind.service \
                    nis.service xinetd.service)

if have_cmd systemctl; then
    FOUND_INSECURE=0
    for svc in "${INSECURE_SERVICES[@]}"; do
        if svc_loaded "${svc}"; then
            state="$(systemctl is-active "${svc}" )"
            enabled="$(systemctl is-enabled "${svc}" )"
            if [[ "${state}" == "active" || "${enabled}" == "enabled" ]]; then
                fail "Небезопасная служба активна/включена: ${svc} (active=${state}, enabled=${enabled})" \
                     "systemctl disable --now ${svc} && dnf remove <пакет-службы>"
                FOUND_INSECURE=1
            else
                info "Небезопасная служба ${svc} установлена, но неактивна и не в автозагрузке"
            fi
        fi
    done
    [[ "${FOUND_INSECURE}" -eq 0 ]] && pass "Активных небезопасных служб (telnet/rsh/ftp/tftp/NIS) не обнаружено"

    ACTIVE_SVC_COUNT="$(systemctl list-units --type=service --state=running  | grep -c '\.service')"
    info "Всего запущенных служб (systemctl --state=running): ${ACTIVE_SVC_COUNT}"
else
    warn "systemctl недоступен - проверка небезопасных служб пропущена"
fi

if have_cmd rpm; then
    info "Запуск проверки целостности пакетов (rpm -Va)..."
    RPM_VA_OUTPUT="$(rpm -Va )"
    CRITICAL_BIN_CHANGES="$(echo "${RPM_VA_OUTPUT}" | grep -E ' /(s?bin|usr/s?bin)/' | grep -E '^..5|^.M|^..U|^..G')"

    if [[ -z "${CRITICAL_BIN_CHANGES}" ]]; then
        pass "Изменённых бинарных файлов в /bin,/sbin,/usr/bin,/usr/sbin не обнаружено"
    else
        CHANGE_COUNT="$(echo "${CRITICAL_BIN_CHANGES}" | grep -cv '^$')"
        fail "Обнаружены изменения в системных бинарных файлах, затронуто объектов: ${CHANGE_COUNT}" \
             "rpm -Vf <файл>; переустановить пакет при необходимости: rpm -Uvh --replacepkgs <пакет>"
        echo "${CRITICAL_BIN_CHANGES}" | head -20 | while IFS= read -r line; do
            log_raw "         ${line}"
        done
        [[ "${CHANGE_COUNT}" -gt 20 ]] && log_raw "         ... (показаны первые 20 из ${CHANGE_COUNT})"
    fi

    MISSING_FILES="$(echo "${RPM_VA_OUTPUT}" | grep -c '^missing')"
    [[ "${MISSING_FILES}" -gt 0 ]] && warn "rpm -Va: отсутствующих файлов пакетов: ${MISSING_FILES}"
else
    warn "Утилита rpm не найдена"
fi

if have_cmd dnf; then
    info "Проверка доступных обновлений через dnf..."
    UPDATE_OUTPUT="$(dnf -q check-update )"; UPDATE_RC=$?
    if [[ ${UPDATE_RC} -eq 100 ]]; then
        UPDATE_COUNT="$(echo "${UPDATE_OUTPUT}" | grep -cE '^\S+\.\S+\s+\S+\s+\S+$')"
        warn "Доступны обновления пакетов: ~${UPDATE_COUNT}" \
             "dnf update --security (протестировать перед прод-раскаткой)"
    elif [[ ${UPDATE_RC} -eq 0 ]]; then
        pass "Система полностью обновлена"
    else
        warn "Не удалось проверить обновления через dnf (rc=${UPDATE_RC})"
    fi
elif have_cmd yum; then
    info "Проверка доступных обновлений через yum..."
    UPDATE_OUTPUT="$(yum -q check-update )"; UPDATE_RC=$?
    if [[ ${UPDATE_RC} -eq 100 ]]; then
        UPDATE_COUNT="$(echo "${UPDATE_OUTPUT}" | grep -cE '^\S+\.\S+\s+\S+\s+\S+$')"
        warn "Доступны обновления пакетов: ~${UPDATE_COUNT}" "yum update --security"
    elif [[ ${UPDATE_RC} -eq 0 ]]; then
        pass "Система полностью обновлена"
    else
        warn "Не удалось проверить обновления через yum (rc=${UPDATE_RC})"
    fi
else
    warn "Ни dnf, ни yum не найдены"
fi

# ============================================================================
# 6. ЗАГРУЗЧИК GRUB2, КОНСОЛЬ И SELINUX (CIS 1.4 / 1.6)
# ============================================================================

log_section "6. ЗАГРУЗЧИК GRUB2, КОНСОЛЬ И SELINUX"

GRUB_CFG=""
for cfg in /boot/grub2/grub.cfg /boot/efi/EFI/redhat/grub.cfg /boot/efi/EFI/rocky/grub.cfg /boot/efi/EFI/almalinux/grub.cfg /boot/efi/EFI/centos/grub.cfg; do
    if [[ -f "${cfg}" ]]; then
        GRUB_CFG="${cfg}"
        break
    fi
done

if [[ -n "${GRUB_CFG}" ]]; then
    if grep -qE '^\s*password' "${GRUB_CFG}" || grep -qE '^\s*password_pbkdf2' "${GRUB_CFG}" || [[ -f /boot/grub2/user.cfg ]]; then
        pass "GRUB2 защищён паролем (user.cfg / password_pbkdf2)"
    else
        fail "Загрузчик GRUB2 НЕ защищён паролем (CIS 1.4.2)" \
             "grub2-setpassword"
    fi

    GRUB_PERM="$(stat -c '%a' "${GRUB_CFG}" )"
    if [[ $((10#${GRUB_PERM:-0})) -eq 600 || $((10#${GRUB_PERM:-0})) -eq 400 ]]; then
        pass "${GRUB_CFG}: права доступа ${GRUB_PERM}"
    else
        fail "${GRUB_CFG}: права доступа ${GRUB_PERM} (ожидалось 0600/0400)" \
             "chmod 600 ${GRUB_CFG}"
    fi
else
    warn "Конфигурационный файл GRUB2 не найден в стандартных путях"
fi

if have_cmd getenforce; then
    SELINUX_STATE="$(getenforce )"
    if [[ "${SELINUX_STATE}" == "Enforcing" ]]; then
        pass "SELinux активен и находится в режиме Enforcing (CIS 1.6.1.2)"
    elif [[ "${SELINUX_STATE}" == "Permissive" ]]; then
        warn "SELinux находится в режиме Permissive (журналирует, но не блокирует)" \
             "setenforce 1 && sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
    else
        fail "SELinux ОТКЛЮЧЕН (состояние: ${SELINUX_STATE})" \
             "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
    fi
else
    fail "Утилита getenforce не найдена (SELinux не установлен)" "dnf install selinux-policy-targeted libselinux-utils"
fi

if [[ -f /etc/sysconfig/init ]]; then
    if grep -qE '^\s*SINGLE=/sbin/sulogin' /etc/sysconfig/init; then
        pass "Однопользовательский режим требует аутентификацию (SINGLE=/sbin/sulogin)"
    else
        warn "Однопользовательский режим не зафиксирован на sulogin в /etc/sysconfig/init"
    fi
fi

if svc_loaded "debug-shell.service"; then
    DEBUG_SHELL_ACTIVE="$(systemctl is-active debug-shell.service )"
    if [[ "${DEBUG_SHELL_ACTIVE}" == "active" ]]; then
        fail "Служба debug-shell.service АКТИВНА (предоставляет root-оболочку на TTY9)" \
             "systemctl mask --now debug-shell.service"
    else
        pass "Служба debug-shell.service не активна"
    fi
fi

# ============================================================================
# 7. ЯДРО, ДИСПЕТЧЕРЫ ПАМЯТИ И БЕЗОПАСНОСТЬ ПАМЯТИ
# ============================================================================

log_section "7. БЕЗОПАСНОСТЬ ЯДРА И ЗАЩИТА ПАМЯТИ"

ASLR_VAL="$(sysctl -n kernel.randomize_va_space  || echo 0)"
if [[ "${ASLR_VAL}" -eq 2 ]]; then
    pass "ASLR полностью включен (kernel.randomize_va_space = 2)"
elif [[ "${ASLR_VAL}" -eq 1 ]]; then
    warn "ASLR включен частично (kernel.randomize_va_space = 1)" \
         "sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-cis-hardening.conf"
else
    fail "ASLR ОТКЛЮЧЕН (kernel.randomize_va_space = ${ASLR_VAL})" \
         "sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-cis-hardening.conf"
fi

PTRACE_VAL="$(sysctl -n kernel.yama.ptrace_scope  || echo 0)"
if [[ "${PTRACE_VAL}" -ge 1 ]]; then
    pass "Защита ptrace ограничена (kernel.yama.ptrace_scope = ${PTRACE_VAL})"
else
    warn "ptrace не ограничен (kernel.yama.ptrace_scope = 0)" \
         "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w kernel.yama.ptrace_scope=1"
fi

DUMPABLE="$(sysctl -n fs.suid_dumpable  || echo 1)"
if [[ "${DUMPABLE}" -eq 0 ]]; then
    pass "Дампы памяти SUID-процессов отключены (fs.suid_dumpable = 0)"
else
    fail "SUID-процессы могут создавать дампы памяти (fs.suid_dumpable = ${DUMPABLE})" \
         "echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w fs.suid_dumpable=0"
fi

if [[ -f /etc/security/limits.conf ]]; then
    if grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null; then
        pass "Создание core dump ограничено в limits.conf (* hard core 0)"
    else
        warn "Ограничение 'hard core 0' не найдено в /etc/security/limits.conf" \
             "echo '* hard core 0' >> /etc/security/limits.d/10-cis-coredump.conf"
    fi
fi

KEXEC_VAL="$(sysctl -n kernel.kexec_load_disabled  || echo 0)"
if [[ "${KEXEC_VAL}" -eq 1 ]]; then
    pass "Загрузка нового ядра через kexec_load отключена (kernel.kexec_load_disabled = 1)"
else
    warn "kexec_load разрешён (kernel.kexec_load_disabled = 0)" \
         "echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/99-cis-hardening.conf && sysctl -w kernel.kexec_load_disabled=1"
fi

# ============================================================================
# 8. ИТОГОВАЯ СВОДКА
# ============================================================================

log_section "8. ИТОГОВАЯ СВОДКА АУДИТА"

TOTAL_CHECKS=$((COUNT_PASS + COUNT_WARN + COUNT_FAIL))
log_raw "  ${C_GREEN}PASS : ${COUNT_PASS}${C_RESET}"
log_raw "  ${C_YELLOW}WARN : ${COUNT_WARN}${C_RESET}"
log_raw "  ${C_RED}FAIL : ${COUNT_FAIL}${C_RESET}"
log_raw "  INFO : ${COUNT_INFO}"
log_raw "  Всего классифицированных проверок: ${TOTAL_CHECKS}"

if [[ "${COUNT_FAIL}" -gt 0 ]]; then
    log_raw ""
    log_raw "  ${C_RED}${C_BOLD}РЕЗУЛЬТАТ: обнаружены критические несоответствия (FAIL). Требуется устранение.${C_RESET}"
    EXIT_CODE=2
elif [[ "${COUNT_WARN}" -gt 0 ]]; then
    log_raw ""
    log_raw "  ${C_YELLOW}${C_BOLD}РЕЗУЛЬТАТ: критических несоответствий нет, но есть замечания (WARN).${C_RESET}"
    EXIT_CODE=1
else
    log_raw ""
    log_raw "  ${C_GREEN}${C_BOLD}РЕЗУЛЬТАТ: все проверки пройдены успешно.${C_RESET}"
    EXIT_CODE=0
fi

# ============================================================================
# 9. СОХРАНЕНИЕ ТЕКСТОВОГО ОТЧЁТА
# ============================================================================

{
    echo "==================================================================="
    echo " Security Audit Report (CIS / ISO 27001) - RPM Linux"
    echo " Host: ${HOSTNAME_FQDN}  Date: ${RUN_TS}"
    echo "==================================================================="
    cat "${TMP_REPORT}"
} >> "${REPORT_FILE}"

if [[ $? -eq 0 ]]; then
    log_raw ""
    log_raw "Текстовый отчёт сохранён/дополнен: ${REPORT_FILE}"
else
    log_raw ""
    log_raw "${C_YELLOW}[WARN] Не удалось записать ${REPORT_FILE}${C_RESET}"
fi

# ============================================================================
# 10. ГЕНЕРАЦИЯ ОБНОВЛЕННОГО HTML-ОТЧЁТА (UI/UX 2026)
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
    local status_text="Соответствует требованиям"
    if [[ ${COUNT_FAIL} -gt 0 ]]; then
        status_badge_class="status-fail"
        status_text="Требуется немедленное устранение"
    elif [[ ${COUNT_WARN} -gt 0 ]]; then
        status_badge_class="status-warn"
        status_text="Требует внимания"
    fi

    {
        cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Аудит безопасности — ${HOSTNAME_FQDN}</title>
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
      <h1>Отчёт аудита безопасности RHEL (CIS / ISO 27001)</h1>
      <p>Автоматизированная проверка технического соответствия системы</p>
    </div>
    <span class="status-tag ${status_badge_class}">${status_text}</span>
  </div>

  <!-- Executive Summary Section -->
  <div class="dashboard-grid">
    <div class="score-card">
      <div class="score-ring">
        <div class="score-ring-inner">${score}%</div>
      </div>
      <div style="font-size:14px; font-weight:600;">Индекс соответствия</div>
      <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">Основан на прохождении CIS Benchmarks</div>
    </div>

    <div class="kpi-cards">
      <div class="kpi-card pass">
        <span class="kpi-title">Успешно (PASS)</span>
        <span class="kpi-value">${COUNT_PASS}</span>
      </div>
      <div class="kpi-card warn">
        <span class="kpi-title">Замечания (WARN)</span>
        <span class="kpi-value">${COUNT_WARN}</span>
      </div>
      <div class="kpi-card fail">
        <span class="kpi-title">Ошибки (FAIL)</span>
        <span class="kpi-value">${COUNT_FAIL}</span>
      </div>
      <div class="kpi-card info">
        <span class="kpi-title">Справочно (INFO)</span>
        <span class="kpi-value">${COUNT_INFO}</span>
      </div>
    </div>
  </div>

  <!-- Metadata System Box -->
  <div class="meta-grid">
    <div class="meta-item"><strong>Целевой хост</strong>${HOSTNAME_FQDN}</div>
    <div class="meta-item"><strong>Операционная система</strong>${OS_INFO}</div>
    <div class="meta-item"><strong>Версия ядра</strong>${KERNEL_VER}</div>
    <div class="meta-item"><strong>Время работы (Uptime)</strong>${UPTIME_INFO}</div>
    <div class="meta-item"><strong>Дата сканирования</strong>${RUN_TS}</div>
    <div class="meta-item"><strong>Аудитор</strong>${AUDITOR_NAME} (v${SCRIPT_VERSION})</div>
  </div>

  <!-- Interactive Controls Bar -->
  <div class="filter-bar">
    <div class="filter-chips">
      <button class="chip active" onclick="filterResults('ALL', this)">Все результаты</button>
      <button class="chip" onclick="filterResults('FAIL', this)">FAIL (${COUNT_FAIL})</button>
      <button class="chip" onclick="filterResults('WARN', this)">WARN (${COUNT_WARN})</button>
      <button class="chip" onclick="filterResults('PASS', this)">PASS (${COUNT_PASS})</button>
      <button class="chip" onclick="filterResults('INFO', this)">INFO (${COUNT_INFO})</button>
    </div>
    <input type="text" id="searchInput" class="search-input" placeholder="Поиск по проверкам или разделам..." onkeyup="searchTable()">
  </div>

  <!-- Results Table -->
  <div class="results-card">
    <table id="auditTable">
      <thead>
        <tr>
          <th style="width: 110px; text-align: center;">Статус</th>
          <th style="width: 280px;">Раздел</th>
          <th>Результат проверки / Пошаговая рекомендация</th>
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
                echo "      <button class=\"copy-btn\" onclick=\"navigator.clipboard.writeText('${js_rem_esc}')\">Копировать</button>"
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
    Сгенерировано автоматически <code>rhel_cis_audit.sh</code> (v${SCRIPT_VERSION}) &copy; ${AUDITOR_NAME}
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
        log_raw "HTML-отчёт сохранён    : ${HTML_REPORT_FILE}"
    else
        log_raw "${C_YELLOW}[WARN] Не удалось записать HTML-отчёт ${HTML_REPORT_FILE}${C_RESET}"
    fi
}

generate_html_report
exit "${EXIT_CODE:-0}"
