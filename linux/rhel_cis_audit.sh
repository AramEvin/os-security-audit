#!/usr/bin/env bash
#
# rhel_cis_audit.sh (v2.0)
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
#   - /var/log/rhel_cis_audit_report.html  (веб-версия отчёта, перезаписывается)
#
# v1.1 changelog (по итогам реального прогона на wazuh-lb-1):
#   - Исправлено определение ОС (дублирование вывода при отсутствии
#     /etc/redhat-release и /etc/os-release).
#   - Обнаружение служб (auditd/rsyslog/journald/insecure) переведено
#     с ненадёжного grep по `systemctl list-unit-files` на
#     `systemctl show -p LoadState`, которое не даёт ложных "не найден".
#   - Исправлено сравнение прав доступа: stat возвращал "0" вместо "000",
#     что давало ложный [FAIL] для уже корректных /etc/shadow, /etc/gshadow.
#   - Исправлена логика оценки firewalld target: target "default" в зоне
#     public - штатное безопасное поведение (implicit deny), а не ACCEPT.
#     Раньше это давало ложный критический [FAIL].
#   - Добавлены конкретные команды-рекомендации (remediation) к находкам.
#   - Добавлена генерация HTML-отчёта (веб-версия для руководства/аудита).

set -u
set -o pipefail

# ============================================================================
# 0. ГЛОБАЛЬНЫЕ ПАРАМЕТРЫ И ИНИЦИАЛИЗАЦИЯ
# ============================================================================

readonly SCRIPT_VERSION="2.0"
readonly AUDITOR_NAME="IT Security LLC"
readonly REPORT_FILE="/var/log/rhel_cis_audit_report.log"
readonly HTML_REPORT_FILE="/var/log/rhel_cis_audit_report.html"
readonly TMP_REPORT="$(mktemp /tmp/rhel_cis_audit.XXXXXX)"
readonly HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
readonly RUN_TS="$(date '+%Y-%m-%d %H:%M:%S %Z')"

COUNT_PASS=0
COUNT_WARN=0
COUNT_FAIL=0
COUNT_INFO=0

declare -a FINDINGS=()      # LEVEL<0x1f>SECTION<0x1f>MESSAGE<0x1f>REMEDIATION
CURRENT_SECTION=""

if [[ -t 1 ]]; then
    C_RED="\033[1;31m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"
    C_BLUE="\033[1;34m"; C_BOLD="\033[1m"; C_RESET="\033[0m"
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

cleanup() { rm -f "${TMP_REPORT}" 2>/dev/null || true; }
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

# pass/warn/fail/info: $1=сообщение, $2=рекомендация (опционально, для warn/fail)
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

# Надёжная проверка существования юнита systemd (не зависит от формата
# вывода list-unit-files, который на некоторых сборках даёт ложные
# "не найден" даже для системных юнитов вроде systemd-journald.service).
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
# 1. ПРОВЕРКА ЗАПУСКА ОТ ROOT
# ============================================================================

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

# --- Определение ОС: RHEL и RHEL-compatible системы ---
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
    OS_INFO="$(cat /etc/redhat-release 2>/dev/null)"
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

log_section "2. АУДИТ ПОДСИСТЕМЫ ЛОГИРОВАНИЯ (auditd / rsyslog / journald)"

AUDITD_ACTIVE="inactive"
if have_cmd systemctl; then
    if svc_loaded auditd.service; then
        AUDITD_ACTIVE="$(systemctl is-active auditd 2>/dev/null)"
        AUDITD_ENABLED="$(systemctl is-enabled auditd 2>/dev/null)"

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
    AUDIT_RULES="$(auditctl -l 2>/dev/null)"
    RULES_COUNT="$(echo "${AUDIT_RULES}" | grep -cv '^$' 2>/dev/null || echo 0)"

    if [[ "${RULES_COUNT}" -eq 0 ]] || echo "${AUDIT_RULES}" | grep -qi "no rules"; then
        fail "auditctl -l: активных правил аудита не обнаружено" \
             "Развернуть базовый набор CIS-правил: cp /usr/share/audit/sample-rules/30-*.rules /etc/audit/rules.d/ && augenrules --load"
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
                 "Добавить правила -a always,exit -F arch=b64 -S execve ... согласно CIS Audit Rules"
        fi
        if echo "${AUDIT_RULES}" | grep -qE "/etc/hosts|/etc/sysconfig/network|network"; then
            pass "Есть правило аудита изменений сетевой конфигурации"
        else
            warn "Отсутствует правило аудита изменений сетевой конфигурации (CIS 4.1.7)" \
                 "echo '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale' >> /etc/audit/rules.d/network.rules"
        fi
        if echo "${AUDIT_RULES}" | tail -1 | grep -q "^-e 2$" || auditctl -s 2>/dev/null | grep -q "enabled 2"; then
            pass "Конфигурация auditd заблокирована в immutable-режиме (-e 2)"
        else
            warn "auditd не в immutable-режиме (-e 2)" \
                 "echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules && augenrules --load (требует перезагрузки для применения)"
        fi
    fi
elif [[ "${AUDITD_ACTIVE}" == "active" ]]; then
    warn "Утилита auditctl не найдена - содержимое правил аудита не проверено"
fi

if have_cmd systemctl; then
    for svc in rsyslog systemd-journald; do
        if svc_loaded "${svc}.service"; then
            state="$(systemctl is-active "${svc}" 2>/dev/null)"
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
        LR_DROPINS="$(find /etc/logrotate.d -type f 2>/dev/null | wc -l)"
        info "Найдено dropin-конфигураций в /etc/logrotate.d: ${LR_DROPINS}"
    fi
else
    fail "Файл /etc/logrotate.conf отсутствует" "dnf install logrotate"
fi

# ============================================================================
# 3. СКАНИРОВАНИЕ СЕТИ, ПОРТОВ И МЕЖСЕТЕВОГО ЭКРАНА
# ============================================================================

log_section "3. СЕТЬ, ОТКРЫТЫЕ ПОРТЫ И МЕЖСЕТЕВОЙ ЭКРАН"

if have_cmd ss; then
    info "Сбор данных через 'ss -tulpn'"
    PORT_DATA="$(ss -tulpn 2>/dev/null)"
    echo "${PORT_DATA}" | tail -n +2 | while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        log_raw "         ${line}"
    done
    LISTEN_COUNT="$(echo "${PORT_DATA}" | grep -cE 'LISTEN|UNCONN')"
    info "Всего слушающих сокетов (TCP LISTEN / UDP UNCONN): ${LISTEN_COUNT}"
    WILDCARD_LISTEN="$(echo "${PORT_DATA}" | grep -E 'LISTEN' | grep -cE '0\.0\.0\.0:|\*:|\[::\]:')"
    if [[ "${WILDCARD_LISTEN}" -gt 0 ]]; then
        warn "Обнаружено ${WILDCARD_LISTEN} TCP-портов, слушающих на всех интерфейсах (0.0.0.0/::)" \
             "Ограничить bind-адрес прикладных сервисов (haproxy/exporters) конкретным интерфейсом там, где внешний доступ не требуется; для управляющих портов (9090/9100/9101/8404) закрыть внешний доступ через firewalld/security group"
    fi
elif have_cmd netstat; then
    info "ss не найден, используется netstat -tulpn"
    netstat -tulpn 2>/dev/null | tail -n +3 | while IFS= read -r line; do
        log_raw "         ${line}"
    done
else
    warn "Ни ss, ни netstat не найдены"
fi

FW_CONFIGURED=0
if have_cmd firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
    FW_CONFIGURED=1
    pass "firewalld активен"
    FW_ZONE="$(firewall-cmd --get-default-zone 2>/dev/null)"
    FW_TARGET="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-all 2>/dev/null | grep -oP '(?<=target: )\S+')"
    info "Зона по умолчанию: ${FW_ZONE:-неизвестно}, target: ${FW_TARGET:-неизвестно}"
    # ВАЖНО: target "default" в firewalld - штатное безопасное поведение
    # (implicit deny для непереченных сервисов/портов), это НЕ то же самое,
    # что ACCEPT. Раньше скрипт ошибочно требовал буквально "DROP"/"REJECT"
    # и давал ложный критический FAIL на стандартной конфигурации.
    if [[ "${FW_TARGET}" == "DROP" || "${FW_TARGET}" == "REJECT" || "${FW_TARGET}" == "default" ]]; then
        pass "Политика по умолчанию для зоны '${FW_ZONE}': ${FW_TARGET} (implicit deny, безопасно)"
    elif [[ "${FW_TARGET}" == "ACCEPT" ]]; then
        fail "Политика по умолчанию для зоны '${FW_ZONE}': ACCEPT - весь непереченный входящий трафик разрешён" \
             "firewall-cmd --permanent --zone=${FW_ZONE} --set-target=default && firewall-cmd --reload"
    else
        warn "Политика по умолчанию для зоны '${FW_ZONE}': ${FW_TARGET:-неизвестно} - проверьте вручную"
    fi
    FW_OPEN_SERVICES="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-services 2>/dev/null)"
    FW_OPEN_PORTS="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-ports 2>/dev/null)"
    info "Разрешённые сервисы в зоне '${FW_ZONE}': ${FW_OPEN_SERVICES:-нет}"
    info "Разрешённые порты в зоне '${FW_ZONE}': ${FW_OPEN_PORTS:-нет}"
elif have_cmd iptables; then
    IPT_POLICY_INPUT="$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '(?<=policy )\S+(?=\))')"
    if [[ -n "${IPT_POLICY_INPUT:-}" ]]; then
        FW_CONFIGURED=1
        if [[ "${IPT_POLICY_INPUT}" == "DROP" || "${IPT_POLICY_INPUT}" == "REJECT" ]]; then
            pass "iptables INPUT policy: ${IPT_POLICY_INPUT}"
        else
            fail "iptables INPUT policy: ${IPT_POLICY_INPUT} - разрешает трафик по умолчанию" \
                 "iptables -P INPUT DROP (после проверки, что все нужные правила ACCEPT уже добавлены)"
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
        actual="$(sysctl -n "${key}" 2>/dev/null)"
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
# 4. ПОЛЬЗОВАТЕЛИ, ПРАВА ДОСТУПА И ACL
# ============================================================================

log_section "4. ПОЛЬЗОВАТЕЛИ, ПРАВА ДОСТУПА И ACL"

UID0_USERS="$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')"
if [[ -z "${UID0_USERS}" ]]; then
    pass "Только root имеет UID 0"
else
    fail "Дополнительные учётные записи с UID 0: ${UID0_USERS//$'\n'/, }" \
         "usermod -u <новый_uid> <пользователь> либо удалить учётную запись, если она не легитимна"
fi

if [[ -r /etc/shadow ]]; then
    EMPTY_PW_USERS="$(awk -F: '($2 == "" ) {print $1}' /etc/shadow)"
    if [[ -z "${EMPTY_PW_USERS}" ]]; then
        pass "Учётных записей с пустым паролем не обнаружено"
    else
        fail "Учётные записи с ПУСТЫМ паролем: ${EMPTY_PW_USERS//$'\n'/, }" \
             "passwd -l <пользователь> либо установить пароль: passwd <пользователь>"
    fi
    LOCKED_MISMATCH="$(awk -F: '($2 !~ /^\!|^\*/ && $2 != "") {print $1}' /etc/shadow | wc -l)"
    info "Учётных записей с установленным hash пароля: ${LOCKED_MISMATCH}"
else
    warn "/etc/shadow недоступен для чтения"
fi

# Исправлено: stat -c '%a' может вернуть "0" вместо "000" - строковое
# сравнение с "000" ложно проваливалось. Сравниваем числовые значения
# по основанию 10 (цифры совпадают, интерпретация как восьмеричное число
# здесь не требуется - нужно лишь сравнение "паттерна цифр").
check_perm() {
    local path="$1" expected_modes="$2" expected_owner="$3" expected_group="$4"
    [[ -e "${path}" ]] || { info "${path} не существует - пропущено"; return; }

    local actual_mode actual_owner actual_group
    actual_mode="$(stat -c '%a' "${path}" 2>/dev/null)"
    actual_owner="$(stat -c '%U' "${path}" 2>/dev/null)"
    actual_group="$(stat -c '%G' "${path}" 2>/dev/null)"

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
        ACL_ENTRIES="$(getfacl -R -s "${dir}" 2>/dev/null | grep -c '^# file:')"
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
        grep -iE "^\s*${1}\s+" "${SSHD_CONFIG}" 2>/dev/null | grep -v '^\s*#' | awk '{print $2}' | tail -1
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
             "Убедиться, что для всех пользователей настроены SSH-ключи, затем: echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && systemctl restart sshd"
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

    SSHD_PERM="$(stat -c '%a' "${SSHD_CONFIG}" 2>/dev/null)"
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

log_section "5. СЛУЖБЫ И УСТАНОВЛЕННЫЕ ПАКЕТЫ"

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
                fail "Небезопасная служба активна/включена: ${svc} (active=${state}, enabled=${enabled})" \
                     "systemctl disable --now ${svc} && dnf remove <пакет-службы>"
                FOUND_INSECURE=1
            else
                info "Небезопасная служба ${svc} установлена, но неактивна и не в автозагрузке"
            fi
        fi
    done
    [[ "${FOUND_INSECURE}" -eq 0 ]] && pass "Активных небезопасных служб (telnet/rsh/ftp/tftp/NIS) не обнаружено"

    ACTIVE_SVC_COUNT="$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c '\.service')"
    info "Всего запущенных служб (systemctl --state=running): ${ACTIVE_SVC_COUNT}"
else
    warn "systemctl недоступен - проверка небезопасных служб пропущена"
fi

if have_cmd rpm; then
    info "Запуск проверки целостности пакетов (rpm -Va)..."
    RPM_VA_OUTPUT="$(rpm -Va 2>/dev/null)"
    CRITICAL_BIN_CHANGES="$(echo "${RPM_VA_OUTPUT}" | grep -E ' /(s?bin|usr/s?bin)/' | grep -E '^..5|^.M|^..U|^..G')"

    if [[ -z "${CRITICAL_BIN_CHANGES}" ]]; then
        pass "Изменённых бинарных файлов в /bin,/sbin,/usr/bin,/usr/sbin не обнаружено"
    else
        CHANGE_COUNT="$(echo "${CRITICAL_BIN_CHANGES}" | grep -cv '^$')"
        fail "Обнаружены изменения в системных бинарных файлах, затронуто объектов: ${CHANGE_COUNT}" \
             "Сверить с эталонным пакетом: rpm -Vf <файл>; при подозрении на компрометацию - переустановить пакет: rpm -Uvh --replacepkgs <пакет>"
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
    UPDATE_OUTPUT="$(dnf -q check-update 2>/dev/null)"; UPDATE_RC=$?
    if [[ ${UPDATE_RC} -eq 100 ]]; then
        UPDATE_COUNT="$(echo "${UPDATE_OUTPUT}" | grep -cE '^\S+\.\S+\s+\S+\s+\S+$')"
        warn "Доступны обновления пакетов: ~${UPDATE_COUNT}" \
             "dnf update --security (протестировать в стейджинге перед прод-раскаткой)"
    elif [[ ${UPDATE_RC} -eq 0 ]]; then
        pass "Система полностью обновлена"
    else
        warn "Не удалось проверить обновления через dnf (rc=${UPDATE_RC})"
    fi
elif have_cmd yum; then
    info "Проверка доступных обновлений через yum..."
    UPDATE_OUTPUT="$(yum -q check-update 2>/dev/null)"; UPDATE_RC=$?
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
# 6. ИТОГОВАЯ СВОДКА
# ============================================================================

log_section "6. ИТОГОВАЯ СВОДКА АУДИТА"

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
# 7. СОХРАНЕНИЕ ТЕКСТОВОГО ОТЧЁТА
# ============================================================================

{
    echo "==================================================================="
    echo " Security Audit Report (CIS / ISO 27001) - RPM Linux"
    echo " Host: ${HOSTNAME_FQDN}  Date: ${RUN_TS}"
    echo "==================================================================="
    cat "${TMP_REPORT}"
} >> "${REPORT_FILE}" 2>/dev/null

if [[ $? -eq 0 ]]; then
    log_raw ""
    log_raw "Текстовый отчёт сохранён/дополнен: ${REPORT_FILE}"
else
    log_raw ""
    log_raw "${C_YELLOW}[WARN] Не удалось записать ${REPORT_FILE}${C_RESET}"
fi

# ============================================================================
# 8. ГЕНЕРАЦИЯ HTML-ОТЧЁТА (веб-версия)
# ============================================================================

generate_html_report() {
    local total=$((COUNT_PASS+COUNT_WARN+COUNT_FAIL))
    local p_pct=0 w_pct=0 f_pct=0
    if [[ ${total} -gt 0 ]]; then
        p_pct=$(( COUNT_PASS*100/total )); w_pct=$(( COUNT_WARN*100/total ))
        f_pct=$((100-p_pct-w_pct))
    fi

    {
        cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Аудит безопасности - ${HOSTNAME_FQDN}</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--border:#262b36;--text:#e6e9ef;--muted:#8b93a7;
      --pass:#2ecc71;--warn:#f5c542;--fail:#ff5c5c;--info:#5aa9e6;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Segoe UI',Roboto,Arial,sans-serif;line-height:1.5}
header{padding:28px 40px;border-bottom:1px solid var(--border);background:linear-gradient(135deg,#171a21,#10131a)}
header h1{margin:0 0 6px;font-size:21px}
header .meta{color:var(--muted);font-size:13px}
header .auditor{display:inline-flex;align-items:center;gap:8px;margin-top:10px;background:#1c202a;border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:12.5px;color:#c6d0e0}
header .auditor b{color:var(--text)}
.wrap{max-width:1100px;margin:0 auto;padding:24px 40px 60px}
.top-row{display:flex;gap:24px;flex-wrap:wrap;align-items:center;margin:24px 0 10px}
.summary{display:flex;gap:16px;flex-wrap:wrap;flex:1}
.card{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.card .num{font-size:28px;font-weight:700}
.card.pass .num{color:var(--pass)} .card.warn .num{color:var(--warn)}
.card.fail .num{color:var(--fail)} .card.info .num{color:var(--info)}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.bar{height:10px;border-radius:6px;overflow:hidden;display:flex;background:#0b0d12;margin:14px 0 28px;border:1px solid var(--border)}
.bar span{height:100%}
.donut-wrap{flex:0 0 auto;display:flex;flex-direction:column;align-items:center;gap:10px}
.donut{width:150px;height:150px;border-radius:50%;position:relative}
.donut-hole{position:absolute;inset:16px;border-radius:50%;background:var(--panel);display:flex;flex-direction:column;align-items:center;justify-content:center;border:1px solid var(--border)}
.donut-hole .pct{font-size:22px;font-weight:700}
.donut-hole .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.donut-legend{display:flex;gap:14px;font-size:11.5px;color:var(--muted)}
.donut-legend span{display:inline-flex;align-items:center;gap:5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.dot.pass{background:var(--pass)} .dot.warn{background:var(--warn)} .dot.fail{background:var(--fail)}
.verdict{padding:14px 18px;border-radius:10px;font-weight:600;margin-bottom:28px;border:1px solid var(--border)}
.verdict.fail{background:#2a1414;color:var(--fail);border-color:#4a1f1f}
.verdict.warn{background:#2a2414;color:var(--warn);border-color:#4a3f1f}
.verdict.pass{background:#132a1b;color:var(--pass);border-color:#1f4a2c}
section.block{margin-bottom:22px;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
section.block h2{margin:0;padding:14px 20px;font-size:15px;background:#1c202a;border-bottom:1px solid var(--border)}
.row{display:flex;gap:12px;padding:9px 20px;border-bottom:1px solid #1d212b;font-size:13.5px;align-items:flex-start}
.row:last-child{border-bottom:none}
.badge{flex:0 0 60px;text-align:center;border-radius:5px;padding:2px 0;font-size:11px;font-weight:700;letter-spacing:.03em;height:fit-content}
.badge.pass{background:#132a1b;color:var(--pass)} .badge.warn{background:#2a2414;color:var(--warn)}
.badge.fail{background:#2a1414;color:var(--fail)} .badge.info{background:#111f2e;color:var(--info)}
.msg{flex:1;color:var(--text)}
.fix{margin-top:4px;font-size:12px;color:var(--muted)}
.fix b{color:#c6d0e0}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px}
@media (max-width:600px){header,.wrap{padding-left:16px;padding-right:16px}}
</style>
</head>
<body>
<header>
  <h1>Аудит безопасности - CIS Benchmark / ISO 27001</h1>
  <div class="meta">Хост: ${HOSTNAME_FQDN} &nbsp;•&nbsp; ОС: $(html_escape "${OS_INFO}") &nbsp;•&nbsp; Дата: ${RUN_TS} &nbsp;•&nbsp; Скрипт v${SCRIPT_VERSION}</div>
  <div class="auditor">&#128737; Аудитор: <b>${AUDITOR_NAME}</b></div>
</header>
<div class="wrap">
  <div class="top-row">
    <div class="summary">
      <div class="card pass"><div class="num">${COUNT_PASS}</div><div class="lbl">Pass</div></div>
      <div class="card warn"><div class="num">${COUNT_WARN}</div><div class="lbl">Warn</div></div>
      <div class="card fail"><div class="num">${COUNT_FAIL}</div><div class="lbl">Fail</div></div>
      <div class="card info"><div class="num">${COUNT_INFO}</div><div class="lbl">Info</div></div>
    </div>
    <div class="donut-wrap">
      <div class="donut" style="background:conic-gradient(var(--pass) 0% ${p_pct}%, var(--warn) ${p_pct}% $((p_pct+w_pct))%, var(--fail) $((p_pct+w_pct))% 100%)">
        <div class="donut-hole"><div class="pct">${p_pct}%</div><div class="lbl">PASS</div></div>
      </div>
      <div class="donut-legend">
        <span><i class="dot pass"></i>Pass ${COUNT_PASS}</span>
        <span><i class="dot warn"></i>Warn ${COUNT_WARN}</span>
        <span><i class="dot fail"></i>Fail ${COUNT_FAIL}</span>
      </div>
    </div>
  </div>
  <div class="bar"><span style="width:${p_pct}%;background:var(--pass)"></span><span style="width:${w_pct}%;background:var(--warn)"></span><span style="width:${f_pct}%;background:var(--fail)"></span></div>
HTMLHEAD

        if [[ "${COUNT_FAIL}" -gt 0 ]]; then
            echo "  <div class=\"verdict fail\">Обнаружены критические несоответствия (FAIL: ${COUNT_FAIL}). Требуется устранение перед подтверждением соответствия ISO/IEC 27001.</div>"
        elif [[ "${COUNT_WARN}" -gt 0 ]]; then
            echo "  <div class=\"verdict warn\">Критических несоответствий нет, есть замечания (WARN: ${COUNT_WARN}).</div>"
        else
            echo "  <div class=\"verdict pass\">Все проверки пройдены успешно.</div>"
        fi

        local prev_section="" section_open=0
        for entry in "${FINDINGS[@]}"; do
            IFS=$'\x1f' read -r lvl sect msg rem <<< "${entry}"
            if [[ "${sect}" != "${prev_section}" ]]; then
                [[ ${section_open} -eq 1 ]] && echo "  </section>"
                echo "  <section class=\"block\"><h2>$(html_escape "${sect}")</h2>"
                section_open=1
                prev_section="${sect}"
            fi
            local lvl_lc="${lvl,,}"
            echo -n "    <div class=\"row\"><div class=\"badge ${lvl_lc}\">${lvl}</div><div class=\"msg\">$(html_escape "${msg}")"
            [[ -n "${rem}" ]] && echo -n "<div class=\"fix\"><b>Рекомендация:</b> $(html_escape "${rem}")</div>"
            echo "</div></div>"
        done
        [[ ${section_open} -eq 1 ]] && echo "  </section>"

        cat <<HTMLFOOT
</div>
<footer>${AUDITOR_NAME} &bull; rhel_cis_audit.sh v${SCRIPT_VERSION} &bull; ${RUN_TS} &bull; Только для внутреннего использования</footer>
</body>
</html>
HTMLFOOT
    } > "${HTML_REPORT_FILE}" 2>/dev/null
}

generate_html_report
if [[ -s "${HTML_REPORT_FILE}" ]]; then
    log_raw "HTML-отчёт сохранён: ${HTML_REPORT_FILE}"
else
    log_raw "${C_YELLOW}[WARN] Не удалось создать HTML-отчёт ${HTML_REPORT_FILE}${C_RESET}"
fi

exit "${EXIT_CODE}"
