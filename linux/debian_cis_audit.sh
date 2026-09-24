#!/usr/bin/env bash
#
# debian_cis_audit.sh (v1.0)
#
# Комплексный технический аудит безопасности Debian / Ubuntu и производных
# (dpkg/apt, systemd). Порт redos_cis_audit.sh v1.1. Ориентирован на
# технические контроли ISO/IEC 27001 (Annex A: A.8, A.12, A.13) и методологию
# CIS Benchmarks for Debian / Ubuntu Linux (Level 1 / Level 2).
#
# Скрипт только ЧИТАЕТ состояние системы (read-only аудит).
#   [PASS] - контроль выполнен
#   [WARN] - отклонение от рекомендации / Level 2 / требует внимания
#   [FAIL] - критическое несоответствие (Level 1)
#   [INFO] - информационная строка, не влияет на итоговую оценку
#
# Вывод:
#   - консоль (цветной)
#   - /var/log/debian_cis_audit_report.log   (текстовый отчёт, накопительно)
#   - /var/log/debian_cis_audit_report.html  (веб-версия отчёта, перезаписывается)
#
# Коды возврата: 0 = всё PASS, 1 = есть WARN, 2 = есть FAIL, 1 при запуске не от root.
#
# Отличия от redos_cis_audit.sh (RPM):
#   - rpm -Va / dnf check-update -> dpkg -V / apt-get -s upgrade; пакетные
#     рекомендации переписаны на apt.
#   - Права /etc/shadow и /etc/gshadow: на Debian штатно 0640 root:shadow.
#     Старая проверка "000|600|0400 root:root" дала бы ложный [FAIL].
#     check_perm теперь проверяет "не более разрешающие, чем MAX" и
#     допускает список групп (shadow|root).
#   - sshd: эффективная конфигурация читается через `sshd -T` (учитывает
#     Include /etc/ssh/sshd_config.d/*.conf, где в Debian/Ubuntu и лежат
#     настройки cloud-init и т.п.); fallback - разбор файлов. Служба
#     называется ssh, а не sshd. PermitRootLogin prohibit-password
#     (штатный default) оценивается как WARN, а не FAIL.
#   - journald: Storage=auto + существующий /var/log/journal = постоянное
#     хранение (штатное поведение Debian), а не отклонение.
#   - Межсетевой экран: firewalld -> ufw -> nftables -> iptables.
#     Для iptables политика ACCEPT с завершающим DROP/REJECT не считается FAIL.
#   - ВАЖНО: dpkg -V проверяет только КОНТРОЛЬНЫЕ СУММЫ файлов; права и
#     владельцев dpkg не хранит, поэтому chmod u+s / chown на системном
#     бинарнике этой проверкой не ловится (в отличие от rpm -V). Для
#     контроля атрибутов нужен FIM (Wazuh syscheck / AIDE). Маска флагов
#     исправлена (в RPM-версии позиции U/G были указаны неверно).
#   - Исправлен подсчёт правил auditctl (двойной "0" при пустом выводе).
#   - Добавлено: unattended-upgrades, reboot-required, dpkg --audit,
#     свежесть индекса apt, AppArmor, dpkg-пакеты небезопасных служб.

set -u
set -o pipefail
export LC_ALL=C   # предсказуемый формат вывода ufw/apt/dpkg/systemctl

# ============================================================================
# 0. ГЛОБАЛЬНЫЕ ПАРАМЕТРЫ И ИНИЦИАЛИЗАЦИЯ
# ============================================================================

readonly SCRIPT_VERSION="1.0"
readonly AUDITOR_NAME="IT Security LLC"
readonly REPORT_FILE="/var/log/debian_cis_audit_report.log"
readonly HTML_REPORT_FILE="/var/log/debian_cis_audit_report.html"
readonly TMP_REPORT="$(mktemp /tmp/debian_cis_audit.XXXXXX)"
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
# вывода list-unit-files).
svc_loaded() {
    local state
    state="$(systemctl show -p LoadState --value "$1" 2>/dev/null)"
    [[ "${state}" == "loaded" ]]
}

# Пакет установлен (dpkg-query возвращает "installed" только для полностью
# установленных пакетов; "config-files" и т.п. не считаются).
pkg_installed() {
    have_cmd dpkg-query || return 1
    [[ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" == "installed" ]]
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

log_raw "${C_BOLD}Технический аудит безопасности (CIS / ISO 27001) - Debian/Ubuntu (dpkg)${C_RESET}"
log_raw "Версия скрипта : ${SCRIPT_VERSION}"
log_raw "Хост           : ${HOSTNAME_FQDN}"
log_raw "Дата/время     : ${RUN_TS}"
log_raw "Файл отчёта    : ${REPORT_FILE}"

# --- Определение ОС: /etc/os-release (есть на всех современных Debian/Ubuntu) ---
OS_INFO="неизвестно"; OS_FAMILY=""
if [[ -r /etc/os-release ]]; then
    OS_INFO="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-${NAME:-неизвестно}}")"
    OS_FAMILY="$(. /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}")"
elif [[ -r /etc/debian_version ]]; then
    OS_INFO="Debian $(cat /etc/debian_version 2>/dev/null)"
    OS_FAMILY="debian"
fi
[[ -z "${OS_INFO}" ]] && OS_INFO="неизвестно"
log_raw "ОС             : ${OS_INFO}"
log_raw "Ядро           : $(uname -r 2>/dev/null)"
if ! echo "${OS_FAMILY}" | grep -qiE 'debian|ubuntu'; then
    info "Обнаружена ОС не из семейства Debian/Ubuntu (${OS_INFO}) - dpkg/apt-проверки могут быть неприменимы; для RHEL-семейства используйте redos_cis_audit.sh"
fi
if ! have_cmd dpkg; then
    info "dpkg не найден - пакетные проверки будут пропущены"
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
             "apt install auditd audispd-plugins && systemctl enable --now auditd"
    fi
else
    warn "systemctl недоступен - невозможно проверить статус auditd"
fi

if [[ "${AUDITD_ACTIVE}" == "active" ]] && have_cmd auditctl; then
    AUDIT_RULES="$(auditctl -l 2>/dev/null)"
    RULES_COUNT="$(printf '%s\n' "${AUDIT_RULES}" | grep -cv '^$' || true)"

    if [[ "${RULES_COUNT:-0}" -eq 0 ]] || echo "${AUDIT_RULES}" | grep -qi "no rules"; then
        fail "auditctl -l: активных правил аудита не обнаружено" \
             "Развернуть базовый набор правил (CIS / Neo23x0 auditd; примеры: /usr/share/doc/auditd/examples/) в /etc/audit/rules.d/*.rules && augenrules --load"
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
        if echo "${AUDIT_RULES}" | grep -qE "/etc/hosts|/etc/hostname|/etc/network|/etc/netplan|sethostname|network"; then
            pass "Есть правило аудита изменений сетевой конфигурации"
        else
            warn "Отсутствует правило аудита изменений сетевой конфигурации (CIS 4.1.7)" \
                 "printf '%s\n' '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale' '-w /etc/hosts -p wa -k system-locale' '-w /etc/network -p wa -k system-locale' '-w /etc/netplan -p wa -k system-locale' >> /etc/audit/rules.d/network.rules && augenrules --load"
        fi
        if echo "${AUDIT_RULES}" | tail -1 | grep -q "^-e 2$" || auditctl -s 2>/dev/null | grep -q "enabled 2"; then
            pass "Конфигурация auditd заблокирована в immutable-режиме (-e 2)"
        else
            warn "auditd не в immutable-режиме (-e 2)" \
                 "echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules && augenrules --load (требует перезагрузки для применения)"
        fi
    fi
elif [[ "${AUDITD_ACTIVE}" == "active" ]]; then
    warn "Утилита auditctl не найдена - содержимое правил аудита не проверено" "apt install auditd"
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
            if [[ "${svc}" == "rsyslog" ]]; then
                info "Юнит rsyslog.service отсутствует (на Debian 12+ rsyslog не ставится по умолчанию - логи только в journald; для централизованного сбора логов: apt install rsyslog)"
            else
                info "Юнит ${svc}.service отсутствует в системе"
            fi
        fi
    done
fi

# journald: эффективная конфигурация с учётом drop-in'ов. Storage=auto
# (штатный default Debian/Ubuntu) даёт постоянное хранение, если существует
# каталог /var/log/journal.
JOURNALD_CFG=""
if have_cmd systemd-analyze; then
    JOURNALD_CFG="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null)"
fi
if [[ -z "${JOURNALD_CFG}" && -f /etc/systemd/journald.conf ]]; then
    JOURNALD_CFG="$(cat /etc/systemd/journald.conf 2>/dev/null)"
fi
if [[ -n "${JOURNALD_CFG}" ]]; then
    J_STORAGE="$(echo "${JOURNALD_CFG}" | grep -E '^\s*Storage\s*=' | tail -1 | cut -d= -f2 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    if [[ "${J_STORAGE}" == "persistent" ]]; then
        pass "journald сконфигурирован на постоянное хранение (Storage=persistent)"
    elif [[ ( -z "${J_STORAGE}" || "${J_STORAGE}" == "auto" ) && -d /var/log/journal ]]; then
        pass "journald: Storage=${J_STORAGE:-auto (default)} и каталог /var/log/journal существует - журналы переживут перезагрузку"
    else
        warn "journald не обеспечивает постоянное хранение (Storage=${J_STORAGE:-auto (default)}, /var/log/journal $([[ -d /var/log/journal ]] && echo существует || echo отсутствует))" \
             "mkdir -p /var/log/journal && printf '[Journal]\nStorage=persistent\n' > /etc/systemd/journald.conf.d/50-persistent.conf && systemctl restart systemd-journald"
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
        warn "Сжатие логов (compress) не включено в logrotate.conf (в Debian/Ubuntu строка закомментирована; отдельные пакеты задают compress в /etc/logrotate.d)" \
             "sed -i 's/^#\\s*compress\\s*$/compress/' /etc/logrotate.conf"
    fi
    if [[ -d /etc/logrotate.d ]]; then
        LR_DROPINS="$(find /etc/logrotate.d -type f 2>/dev/null | wc -l)"
        info "Найдено dropin-конфигураций в /etc/logrotate.d: ${LR_DROPINS}"
    fi
else
    fail "Файл /etc/logrotate.conf отсутствует" "apt install logrotate"
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
    LISTEN_COUNT="$(echo "${PORT_DATA}" | grep -cE 'LISTEN|UNCONN' || true)"
    info "Всего слушающих сокетов (TCP LISTEN / UDP UNCONN): ${LISTEN_COUNT}"
    WILDCARD_LISTEN="$(echo "${PORT_DATA}" | grep -E 'LISTEN' | grep -cE '0\.0\.0\.0:|\*:|\[::\]:' || true)"
    if [[ "${WILDCARD_LISTEN}" -gt 0 ]]; then
        warn "Обнаружено ${WILDCARD_LISTEN} TCP-портов, слушающих на всех интерфейсах (0.0.0.0/::)" \
             "Ограничить bind-адрес прикладных сервисов (haproxy/exporters) конкретным интерфейсом там, где внешний доступ не требуется; для управляющих портов (9090/9100/9101/8404) закрыть внешний доступ через ufw/nftables/security group"
    fi
elif have_cmd netstat; then
    info "ss не найден, используется netstat -tulpn"
    netstat -tulpn 2>/dev/null | tail -n +3 | while IFS= read -r line; do
        log_raw "         ${line}"
    done
else
    warn "Ни ss, ни netstat не найдены" "apt install iproute2"
fi

# Межсетевой экран: firewalld -> ufw -> nftables -> iptables.
FW_CONFIGURED=0
FW_HINT="Ubuntu: apt install ufw && ufw allow OpenSSH && ufw default deny incoming && ufw --force enable (СНАЧАЛА разрешите SSH, иначе потеряете доступ); Debian: apt install nftables && systemctl enable --now nftables (или ufw)"

if have_cmd firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
    FW_CONFIGURED=1
    pass "firewalld активен"
    FW_ZONE="$(firewall-cmd --get-default-zone 2>/dev/null)"
    FW_TARGET="$(firewall-cmd --permanent --zone="${FW_ZONE}" --list-all 2>/dev/null | grep -oP '(?<=target: )\S+')"
    info "Зона по умолчанию: ${FW_ZONE:-неизвестно}, target: ${FW_TARGET:-неизвестно}"
    # target "default" - штатное безопасное поведение (implicit deny), не ACCEPT.
    if [[ "${FW_TARGET}" == "DROP" || "${FW_TARGET}" == "REJECT" || "${FW_TARGET}" == "default" ]]; then
        pass "Политика по умолчанию для зоны '${FW_ZONE}': ${FW_TARGET} (implicit deny, безопасно)"
    elif [[ "${FW_TARGET}" == "ACCEPT" ]]; then
        fail "Политика по умолчанию для зоны '${FW_ZONE}': ACCEPT - весь непереченный входящий трафик разрешён" \
             "firewall-cmd --permanent --zone=${FW_ZONE} --set-target=default && firewall-cmd --reload"
    else
        warn "Политика по умолчанию для зоны '${FW_ZONE}': ${FW_TARGET:-неизвестно} - проверьте вручную"
    fi
    info "Разрешённые сервисы в зоне '${FW_ZONE}': $(firewall-cmd --permanent --zone="${FW_ZONE}" --list-services 2>/dev/null)"
    info "Разрешённые порты в зоне '${FW_ZONE}': $(firewall-cmd --permanent --zone="${FW_ZONE}" --list-ports 2>/dev/null)"
fi

if [[ "${FW_CONFIGURED}" -eq 0 ]] && have_cmd ufw; then
    UFW_STATUS="$(ufw status verbose 2>/dev/null)"
    if echo "${UFW_STATUS}" | grep -q '^Status: active'; then
        FW_CONFIGURED=1
        pass "ufw активен"
        UFW_IN="$(echo "${UFW_STATUS}" | grep -oP '^Default:\s*\K\w+(?= \(incoming\))')"
        if [[ "${UFW_IN}" == "deny" || "${UFW_IN}" == "reject" ]]; then
            pass "ufw: политика по умолчанию для входящих: ${UFW_IN} (implicit deny, безопасно)"
        else
            fail "ufw: политика по умолчанию для входящих: ${UFW_IN:-неизвестно} - непереченный входящий трафик разрешён" \
                 "ufw default deny incoming"
        fi
        info "ufw: правил ALLOW: $(echo "${UFW_STATUS}" | grep -c 'ALLOW' || true)"
    else
        info "ufw установлен, но неактивен (Status: inactive) - проверяются nftables/iptables"
    fi
fi

# nftables (нативные правила): ищем базовые цепочки input с policy drop
NFT_RULESET=""
if [[ "${FW_CONFIGURED}" -eq 0 ]] && have_cmd nft; then
    NFT_RULESET="$(nft list ruleset 2>/dev/null)"
    if echo "${NFT_RULESET}" | grep -E 'hook input' | grep -q 'policy drop'; then
        FW_CONFIGURED=1
        pass "nftables: найдена базовая цепочка input с policy drop (implicit deny, безопасно)"
    fi
fi

# iptables (в Debian 10+ это обычно iptables-nft). Политика ACCEPT с
# завершающим DROP/REJECT - допустимая конфигурация.
if [[ "${FW_CONFIGURED}" -eq 0 ]] && have_cmd iptables; then
    IPT_INPUT="$(iptables -S INPUT 2>/dev/null)"
    IPT_POLICY_INPUT="$(echo "${IPT_INPUT}" | head -1 | grep -oP '(?<=-P INPUT )\S+')"
    if [[ -n "${IPT_POLICY_INPUT:-}" ]]; then
        IPT_LAST="$(echo "${IPT_INPUT}" | tail -1)"
        if [[ "${IPT_POLICY_INPUT}" == "DROP" || "${IPT_POLICY_INPUT}" == "REJECT" ]]; then
            FW_CONFIGURED=1
            pass "iptables INPUT policy: ${IPT_POLICY_INPUT}"
        elif echo "${IPT_LAST}" | grep -qE '^-A INPUT .*-j (DROP|REJECT)( |$)'; then
            FW_CONFIGURED=1
            pass "iptables INPUT policy: ${IPT_POLICY_INPUT}, но завершающее правило цепочки - DROP/REJECT (implicit deny)"
        elif [[ "$(echo "${IPT_INPUT}" | wc -l)" -gt 1 ]]; then
            FW_CONFIGURED=1
            fail "iptables INPUT policy: ${IPT_POLICY_INPUT} - разрешает трафик по умолчанию" \
                 "iptables -P INPUT DROP (после проверки, что все нужные правила ACCEPT, включая SSH, уже добавлены)"
        fi
    fi
fi

if [[ "${FW_CONFIGURED}" -eq 0 ]] && echo "${NFT_RULESET}" | grep -q 'hook input'; then
    FW_CONFIGURED=1
    warn "nftables: базовые цепочки input есть, но policy drop не найдена - проверьте вручную (nft list ruleset)"
fi

[[ "${FW_CONFIGURED}" -eq 0 ]] && fail "Активный межсетевой экран не обнаружен (ufw/nftables/iptables/firewalld)" "${FW_HINT}"

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
    ["kernel.randomize_va_space"]="2"
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
    warn "Утилита sysctl недоступна" "apt install procps"
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

# Проверка прав: права должны быть НЕ БОЛЕЕ разрешающими, чем MAX (маска
# восьмеричная), владелец - точный, группа - из списка "g1|g2".
# Так штатные Debian-значения (/etc/shadow = 0640 root:shadow) проходят,
# а 0644/0666 - нет. Сравнение чисто арифметическое, без строкового
# сопоставления "0" и "000".
check_perm() {
    local path="$1" max_mode="$2" expected_owner="$3" expected_groups="$4"
    [[ -e "${path}" ]] || { info "${path} не существует - пропущено"; return; }

    local actual_mode actual_owner actual_group
    actual_mode="$(stat -c '%a' "${path}" 2>/dev/null)"
    actual_owner="$(stat -c '%U' "${path}" 2>/dev/null)"
    actual_group="$(stat -c '%G' "${path}" 2>/dev/null)"

    if [[ "${actual_mode}" =~ ^[0-7]+$ ]] && (( (8#${actual_mode} & ~8#${max_mode}) == 0 )); then
        pass "${path}: права ${actual_mode} (не более разрешающие, чем ${max_mode})"
    else
        fail "${path}: права ${actual_mode:-?} (допустимо не более ${max_mode})" \
             "chmod ${max_mode} ${path}"
    fi

    if [[ "${actual_owner}" == "${expected_owner}" && "|${expected_groups}|" == *"|${actual_group}|"* ]]; then
        pass "${path}: владелец ${actual_owner}:${actual_group}"
    else
        fail "${path}: владелец ${actual_owner}:${actual_group} (ожидалось: ${expected_owner}:(${expected_groups}))" \
             "chown ${expected_owner}:${expected_groups%%|*} ${path}"
    fi
}

check_perm "/etc/shadow"   "640" "root" "shadow|root"
check_perm "/etc/gshadow"  "640" "root" "shadow|root"
check_perm "/etc/passwd"   "644" "root" "root"
check_perm "/etc/group"    "644" "root" "root"
check_perm "/etc/crontab"  "644" "root" "root"

if have_cmd getfacl; then
    for dir in /var/log /etc /home; do
        [[ -d "${dir}" ]] || continue
        ACL_ENTRIES="$(getfacl -R -s "${dir}" 2>/dev/null | grep -c '^# file:' || true)"
        if [[ "${ACL_ENTRIES}" -gt 0 ]]; then
            info "${dir}: объектов с нестандартными ACL: ${ACL_ENTRIES} (требуется ручная проверка; на /var/log/journal ACL для adm/systemd-journal штатны)"
        else
            pass "${dir}: нестандартных ACL не обнаружено"
        fi
    done
else
    warn "Утилита getfacl не найдена (пакет acl)" "apt install acl"
fi

# --- SSH ---
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_T=""
if have_cmd sshd; then
    SSHD_T="$(sshd -T 2>/dev/null)"
fi

if [[ -f "${SSHD_CONFIG}" || -n "${SSHD_T}" ]]; then
    # Куда писать правки: если в sshd_config есть Include drop-in каталога,
    # файл 00-* читается первым (в sshd побеждает первое значение), поэтому
    # он гарантированно перекрывает 50-cloud-init.conf и т.п.
    if grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "${SSHD_CONFIG}" 2>/dev/null; then
        SSH_FIX_FILE="/etc/ssh/sshd_config.d/00-cis-hardening.conf"
    else
        SSH_FIX_FILE="${SSHD_CONFIG}"
    fi
    SSH_APPLY="sshd -t && systemctl reload ssh"

    if [[ -n "${SSHD_T}" ]]; then
        info "SSH: используется эффективная конфигурация (sshd -T, с учётом Include и Match-независимых значений)"
    else
        info "SSH: sshd -T недоступен (нет /run/sshd или не установлен openssh-server) - разбор файлов конфигурации (sshd_config + sshd_config.d)"
    fi

    # $1 - ключ в нижнем регистре. Первое найденное значение побеждает (как в sshd).
    get_sshd_value() {
        local key="$1" val f
        if [[ -n "${SSHD_T}" ]]; then
            awk -v k="${key}" '$1==k {print $2; exit}' <<< "${SSHD_T}"
            return
        fi
        local -a files=()
        if [[ "${SSH_FIX_FILE}" != "${SSHD_CONFIG}" ]]; then
            for f in /etc/ssh/sshd_config.d/*.conf; do [[ -f "${f}" ]] && files+=("${f}"); done
        fi
        files+=("${SSHD_CONFIG}")
        for f in "${files[@]}"; do
            val="$(awk -v k="${key}" 'tolower($1)=="match"{exit} tolower($1)==k {print $2; exit}' "${f}" 2>/dev/null)"
            if [[ -n "${val}" ]]; then echo "${val}"; return; fi
        done
    }

    PERMIT_ROOT="$(get_sshd_value permitrootlogin)"
    # Не задано в файлах = default OpenSSH (prohibit-password), как и в выводе sshd -T
    [[ -z "${PERMIT_ROOT}" ]] && PERMIT_ROOT="prohibit-password"
    case "${PERMIT_ROOT,,}" in
        no)
            pass "PermitRootLogin no" ;;
        prohibit-password|without-password)
            warn "PermitRootLogin ${PERMIT_ROOT} (root по ключу разрешён; CIS: no)" \
                 "echo 'PermitRootLogin no' >> ${SSH_FIX_FILE} && ${SSH_APPLY}" ;;
        *)
            fail "PermitRootLogin не задан как 'no' (текущее: ${PERMIT_ROOT:-по умолчанию})" \
                 "echo 'PermitRootLogin no' >> ${SSH_FIX_FILE} && ${SSH_APPLY}" ;;
    esac

    PASS_AUTH="$(get_sshd_value passwordauthentication)"
    if [[ "${PASS_AUTH,,}" == "no" ]]; then
        pass "PasswordAuthentication no"
    else
        warn "PasswordAuthentication не отключён (текущее: ${PASS_AUTH:-по умолчанию yes})" \
             "Убедиться, что для всех пользователей настроены SSH-ключи, затем: echo 'PasswordAuthentication no' >> ${SSH_FIX_FILE} && ${SSH_APPLY}"
    fi

    PROTO="$(get_sshd_value protocol)"
    if [[ -z "${PROTO}" || "${PROTO}" == "2" ]]; then
        pass "SSH Protocol 2 / современный OpenSSH"
    else
        fail "SSH Protocol = '${PROTO}' - обнаружена конфигурация устаревшего протокола" \
             "Удалить директиву Protocol 1 из конфигурации sshd"
    fi

    EMPTY_PASS_SSH="$(get_sshd_value permitemptypasswords)"
    if [[ "${EMPTY_PASS_SSH,,}" == "no" || -z "${EMPTY_PASS_SSH}" ]]; then
        pass "PermitEmptyPasswords no / не задано (default no)"
    else
        fail "PermitEmptyPasswords = '${EMPTY_PASS_SSH}'" \
             "echo 'PermitEmptyPasswords no' >> ${SSH_FIX_FILE} && ${SSH_APPLY}"
    fi

    X11_FWD="$(get_sshd_value x11forwarding)"
    if [[ "${X11_FWD,,}" == "no" ]]; then
        pass "X11Forwarding no"
    else
        warn "X11Forwarding не отключен (текущее: ${X11_FWD:-не задано}; в Debian/Ubuntu штатно yes)" \
             "echo 'X11Forwarding no' >> ${SSH_FIX_FILE} && ${SSH_APPLY}"
    fi

    MAX_AUTH_TRIES="$(get_sshd_value maxauthtries)"
    if [[ "${MAX_AUTH_TRIES}" =~ ^[0-9]+$ && "${MAX_AUTH_TRIES}" -le 4 ]]; then
        pass "MaxAuthTries = ${MAX_AUTH_TRIES} (<=4)"
    else
        warn "MaxAuthTries = '${MAX_AUTH_TRIES:-не задано (default 6)}'" \
             "echo 'MaxAuthTries 4' >> ${SSH_FIX_FILE} && ${SSH_APPLY}"
    fi

    CIPHERS="$(get_sshd_value ciphers)"
    if [[ -n "${CIPHERS}" ]]; then
        if echo "${CIPHERS}" | grep -qiE 'arcfour|3des|blowfish|cbc'; then
            fail "Разрешены слабые шифры SSH: ${CIPHERS}" \
                 "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> ${SSH_FIX_FILE} && ${SSH_APPLY}"
        else
            pass "Ciphers: слабых алгоритмов (arcfour/3des/blowfish/cbc) не обнаружено"
        fi
    else
        info "Директива Ciphers не задана явно - используется набор по умолчанию OpenSSH"
    fi

    if [[ -f "${SSHD_CONFIG}" ]]; then
        SSHD_PERM="$(stat -c '%a' "${SSHD_CONFIG}" 2>/dev/null)"
        if [[ "${SSHD_PERM}" =~ ^[0-7]+$ ]] && (( (8#${SSHD_PERM} & ~8#644) == 0 )); then
            pass "${SSHD_CONFIG}: права доступа ${SSHD_PERM}"
        else
            warn "${SSHD_CONFIG}: права доступа ${SSHD_PERM} (рекомендуется 0600)" \
                 "chmod 600 ${SSHD_CONFIG}"
        fi
    fi
else
    fail "Файл ${SSHD_CONFIG} не найден и sshd недоступен" "apt install openssh-server"
fi

# ============================================================================
# 5. СЛУЖБЫ, ПАКЕТЫ (dpkg/apt) И ОБНОВЛЕНИЯ
# ============================================================================

log_section "5. СЛУЖБЫ, ПАКЕТЫ (dpkg/apt) И ОБНОВЛЕНИЯ"

INSECURE_SERVICES=(telnet.socket telnet.service telnetd.service inetutils-telnetd.service \
                    rsh.socket rsh.service rlogin.socket rexec.socket \
                    vsftpd.service proftpd.service pure-ftpd.service \
                    tftp.service tftp.socket tftpd-hpa.service atftpd.service \
                    ypserv.service ypbind.service nis.service \
                    xinetd.service openbsd-inetd.service inetutils-inetd.service)

if have_cmd systemctl; then
    FOUND_INSECURE=0
    for svc in "${INSECURE_SERVICES[@]}"; do
        if svc_loaded "${svc}"; then
            state="$(systemctl is-active "${svc}" 2>/dev/null)"
            enabled="$(systemctl is-enabled "${svc}" 2>/dev/null)"
            if [[ "${state}" == "active" || "${enabled}" == "enabled" ]]; then
                fail "Небезопасная служба активна/включена: ${svc} (active=${state}, enabled=${enabled})" \
                     "systemctl disable --now ${svc} && apt purge <пакет-службы>"
                FOUND_INSECURE=1
            else
                info "Небезопасная служба ${svc} установлена, но неактивна и не в автозагрузке"
            fi
        fi
    done
    [[ "${FOUND_INSECURE}" -eq 0 ]] && pass "Активных небезопасных служб (telnet/rsh/ftp/tftp/NIS/inetd) не обнаружено"

    ACTIVE_SVC_COUNT="$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c '\.service' || true)"
    info "Всего запущенных служб (systemctl --state=running): ${ACTIVE_SVC_COUNT}"
else
    warn "systemctl недоступен - проверка небезопасных служб пропущена"
fi

if have_cmd dpkg-query; then
    INSECURE_PKGS=(telnetd inetutils-telnetd rsh-server rsh-client talk talkd nis xinetd tftpd tftpd-hpa)
    FOUND_PKGS=()
    for pkg in "${INSECURE_PKGS[@]}"; do
        pkg_installed "${pkg}" && FOUND_PKGS+=("${pkg}")
    done
    if [[ "${#FOUND_PKGS[@]}" -eq 0 ]]; then
        pass "Небезопасные пакеты (telnetd/rsh/nis/xinetd/tftpd/talk) не установлены"
    else
        warn "Установлены небезопасные/устаревшие пакеты: ${FOUND_PKGS[*]}" \
             "apt purge ${FOUND_PKGS[*]}"
    fi
fi

# --- Целостность пакетов (аналог rpm -Va): dpkg -V, формат вывода как у rpm -V
#     (позиции: S M 5 D L U G T P). Значимы: контрольная сумма (3), права (2),
#     владелец (6), группа (7) для файлов в bin/sbin.
if have_cmd dpkg; then
    info "Запуск проверки целостности пакетов (dpkg -V)..."
    DPKG_V_OUTPUT="$(dpkg -V 2>/dev/null)"
    CRITICAL_BIN_CHANGES="$(echo "${DPKG_V_OUTPUT}" | grep -E ' /(s?bin|usr/s?bin|usr/local/s?bin)/' | grep -E '^(..5|.M|.{5}U|.{6}G)' || true)"

    if [[ -z "${CRITICAL_BIN_CHANGES}" ]]; then
        pass "Изменённых бинарных файлов в /bin,/sbin,/usr/bin,/usr/sbin не обнаружено"
    else
        CHANGE_COUNT="$(echo "${CRITICAL_BIN_CHANGES}" | grep -cv '^$' || true)"
        fail "Обнаружены изменения в системных бинарных файлах, затронуто объектов: ${CHANGE_COUNT}" \
             "Сверить с эталонным пакетом: dpkg -S <файл> && dpkg -V <пакет> (или debsums -c); при подозрении на компрометацию - переустановить: apt install --reinstall <пакет>"
        echo "${CRITICAL_BIN_CHANGES}" | head -20 | while IFS= read -r line; do
            log_raw "         ${line}"
        done
        [[ "${CHANGE_COUNT}" -gt 20 ]] && log_raw "         ... (показаны первые 20 из ${CHANGE_COUNT})"
    fi

    # Документация/man/locale часто исключаются через dpkg path-exclude
    # (минимизированные образы, контейнеры) - это не признак компрометации.
    info "dpkg -V сверяет только контрольные суммы (права/владельцы файлов dpkg не хранит) - для контроля атрибутов и новых SUID-файлов используйте FIM (Wazuh syscheck / AIDE)"

    MISSING_FILES="$(echo "${DPKG_V_OUTPUT}" | grep '^missing' | grep -cvE ' /usr/share/(doc|man|info|locale|lintian|groff|help)/' || true)"
    if [[ "${MISSING_FILES}" -gt 0 ]]; then
        warn "dpkg -V: отсутствующих файлов пакетов (кроме doc/man/locale): ${MISSING_FILES}" \
             "dpkg -V | grep '^missing' | grep -vE ' /usr/share/(doc|man|info|locale)/'"
    fi

    DPKG_AUDIT="$(dpkg --audit 2>/dev/null)"
    if [[ -z "${DPKG_AUDIT}" ]]; then
        pass "dpkg --audit: сломанных/недоустановленных пакетов нет"
    else
        warn "dpkg --audit: обнаружены пакеты в некорректном состоянии" \
             "dpkg --configure -a && apt -f install"
        echo "${DPKG_AUDIT}" | head -10 | while IFS= read -r line; do log_raw "         ${line}"; done
    fi
else
    warn "Утилита dpkg не найдена"
fi

# --- Обновления. apt update НЕ выполняется (скрипт read-only), поэтому
#     результат основан на локальном индексе пакетов; проверяем его свежесть.
if have_cmd apt-get; then
    APT_STAMP=0
    if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
        APT_STAMP="$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || echo 0)"
    elif [[ -d /var/lib/apt/lists ]]; then
        APT_STAMP="$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Packages*' -printf '%T@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1)"
        APT_STAMP="${APT_STAMP:-0}"
    fi
    if [[ "${APT_STAMP}" -gt 0 ]]; then
        APT_AGE_DAYS=$(( ( $(date +%s) - APT_STAMP ) / 86400 ))
        if [[ "${APT_AGE_DAYS}" -le 7 ]]; then
            info "Индекс пакетов apt обновлялся ${APT_AGE_DAYS} дн. назад"
        else
            warn "Индекс пакетов apt устарел (${APT_AGE_DAYS} дн.) - список доступных обновлений может быть неточным" \
                 "apt update (затем повторить аудит)"
        fi
    else
        warn "Не удалось определить дату последнего apt update - список доступных обновлений может быть неточным" "apt update"
    fi

    info "Проверка доступных обновлений через apt-get -s upgrade (по локальному индексу)..."
    UPDATE_OUTPUT="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null)"; UPDATE_RC=$?
    if [[ ${UPDATE_RC} -ne 0 ]]; then
        warn "Не удалось проверить обновления через apt-get (rc=${UPDATE_RC})"
    else
        UPDATE_COUNT="$(echo "${UPDATE_OUTPUT}" | grep -c '^Inst ' || true)"
        SEC_COUNT="$(echo "${UPDATE_OUTPUT}" | grep '^Inst ' | grep -ci 'security' || true)"
        if [[ "${UPDATE_COUNT}" -gt 0 ]]; then
            warn "Доступны обновления пакетов: ${UPDATE_COUNT} (из них из security-репозиториев: ${SEC_COUNT})" \
                 "apt update && apt upgrade (протестировать в стейджинге перед прод-раскаткой; только безопасность: unattended-upgrade -d)"
        else
            pass "Система полностью обновлена (по локальному индексу apt)"
        fi
    fi
elif have_cmd apt; then
    warn "apt-get не найден, но найден apt - проверка обновлений пропущена"
else
    warn "apt не найден"
fi

# Автоматическое применение обновлений безопасности
if have_cmd dpkg-query; then
    if pkg_installed unattended-upgrades; then
        UU_VAL="$(apt-config dump 2>/dev/null | grep -i 'APT::Periodic::Unattended-Upgrade' | grep -oP '"\K[0-9]+' | head -1)"
        if [[ "${UU_VAL:-0}" -ge 1 ]]; then
            pass "unattended-upgrades установлен и включён (APT::Periodic::Unattended-Upgrade=${UU_VAL})"
        else
            warn "unattended-upgrades установлен, но не включён (APT::Periodic::Unattended-Upgrade=${UU_VAL:-не задан})" \
                 "dpkg-reconfigure -plow unattended-upgrades"
        fi
    else
        warn "unattended-upgrades не установлен - автоматическая установка security-обновлений не настроена (если патчинг выполняется централизованно, например Ansible, замечание можно принять)" \
             "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
    fi
fi

if [[ -f /var/run/reboot-required ]]; then
    RB_PKGS="$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
    warn "Требуется перезагрузка для применения обновлений${RB_PKGS:+ (пакеты: ${RB_PKGS})}" \
         "Запланировать окно обслуживания и перезагрузить хост"
else
    pass "Перезагрузка после обновлений не требуется (/var/run/reboot-required отсутствует)"
fi

# Мандатный контроль доступа
if have_cmd aa-status && aa-status --enabled >/dev/null 2>&1; then
    pass "AppArmor включён в ядре"
    AA_ENFORCE="$(aa-status 2>/dev/null | grep -m1 'profiles are in enforce mode' | sed 's/^ *//')"
    [[ -n "${AA_ENFORCE}" ]] && info "AppArmor: ${AA_ENFORCE}"
elif have_cmd getenforce && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
    pass "SELinux в режиме Enforcing"
else
    warn "Ни AppArmor, ни SELinux (Enforcing) не активны (CIS 1.6, ISO 27001 A.8.3)" \
         "apt install apparmor apparmor-utils && systemctl enable --now apparmor (для AppArmor может потребоваться параметр ядра apparmor=1 security=apparmor)"
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
    echo " Security Audit Report (CIS / ISO 27001) - Debian/Ubuntu"
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
<title>Аудит безопасности - $(html_escape "${HOSTNAME_FQDN}")</title>
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
.msg{flex:1;color:var(--text);word-break:break-word}
.fix{margin-top:4px;font-size:12px;color:var(--muted)}
.fix b{color:#c6d0e0}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px}
@media (max-width:600px){header,.wrap{padding-left:16px;padding-right:16px}}
</style>
</head>
<body>
<header>
  <h1>Аудит безопасности - CIS Benchmark / ISO 27001 (Debian/Ubuntu)</h1>
  <div class="meta">Хост: $(html_escape "${HOSTNAME_FQDN}") &nbsp;•&nbsp; ОС: $(html_escape "${OS_INFO}") &nbsp;•&nbsp; Дата: ${RUN_TS} &nbsp;•&nbsp; Скрипт v${SCRIPT_VERSION}</div>
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
<footer>${AUDITOR_NAME} &bull; debian_cis_audit.sh v${SCRIPT_VERSION} &bull; ${RUN_TS} &bull; Только для внутреннего использования</footer>
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
