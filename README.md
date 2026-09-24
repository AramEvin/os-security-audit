# Multi-Platform OS Security Audit & Hardening Compliance

Professional, **read-only** infrastructure-as-code automation scripts designed to audit, verify compliance, and report on the security posture of enterprise operating systems. 

This toolkit aligns with **ISO/IEC 27001 (Annex A)** and **CIS Benchmarks (Level 1 & Level 2)** controls.

## 📋 Features & Vectors Audited

- **Log & Event Auditing:** Verifies `auditd`, `rsyslog`, advanced audit policies, and SIEM (`Wazuh`/`Sysmon`) status.
- **Network & Firewall Hardening:** Scans open ports, implicit deny rule sets (`MpsSvc`, `firewalld`, `ufw`, `nftables`), and core kernel parameters (`sysctl`).
- **Access Control & Identity:** Analyzes weak files/folders ACLs, UID 0 accounts, password complexity policies, and secure OpenSSH/RDP settings.
- **Integrity Check:** Monitors system binaries tampering (`rpm -Va`, `dpkg -V`, `Authenticode`) and pending patches.

---

## 📂 Project Structure

```text
├── linux/
│   ├── debian_cis_audit.sh   # Read-only audit for Debian / Ubuntu
│   └── rhel_cis_audit.sh     # Read-only audit for Red Hat / Rocky Linux / CentOS
├── windows/
│   └── windows_cis_audit.ps1 # Read-only PowerShell audit for Windows 10/11 & Server 2016+
└── README.md
```

---

## 🛠️ Step-by-Step Guide

### Step 1: Installation & Delivery

Clone this repository directly to the target node or distribute the required script via your automation engine (Ansible, SaltStack, GitLab runner, etc.):

```bash
# Clone the repository
git clone https://github.com
cd os-security-audit
```

### Step 2: Configuration (Optional)

The scripts are ready to run out of the box with optimal production configuration defaults, but they can be adjusted:

* **Linux:** By default, logs are accumulated globally inside `/var/log/*_report.log`, and HTML representations overwrite `/var/log/*_report.html`. You can modify variables `REPORT_FILE` and `HTML_REPORT_FILE` at the top of the `.sh` files if alternative locations are desired.
* **Windows:** The execution defaults to `C:\ProgramData\SecurityAudit`. You can override this using runtime parameters if needed.

### Step 3: Run / Execution

> ⚠️ **Note:** Scripts are strictly **read-only**. They do not modify configurations, alter keys, or stop core active business applications. Elevated administrative rights are required to pull underlying low-level metrics.

#### 🔹 Running on Windows & Windows Server (PowerShell)
1. Откройте **PowerShell от имени Администратора** (Пуск -> Наберите "PowerShell" -> Правый клик -> **Запуск от имени администратора**).
2. Перейдите в папку со скриптом и выполните следующую команду:

```powershell
cd .\windows\
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows_cis_audit.ps1 -SkipUpdateSearch
```
*Вы также можете добавить флаг `-DeepScan` в конец команды, если хотите запустить глубокую проверку целостности системы (занимает дополнительные 5–20 минут).*

#### 🔹 Running on Debian / Ubuntu (Linux)
```bash
cd linux/
chmod +x debian_cis_audit.sh
sudo ./debian_cis_audit.sh
```

#### 🔹 Running on Red Hat / Rocky / CentOS (Linux)
```bash
cd linux/
chmod +x rhel_cis_audit.sh
sudo ./rhel_cis_audit.sh
```

---

## 📊 Viewing the Results

Every execution generates dual output types for different evaluation scopes:

### 1. Terminal Console & Logs (Raw Technical Breakdown)
The terminal will display instant color-coded outcomes (`[PASS]`, `[WARN]`, `[FAIL]`) accompanied by precise terminal commands needed to resolve the detected gaps (`Remediation` lines).
* Combined logs are stored at: `/var/log/*_report.log` (Linux) or `C:\ProgramData\SecurityAudit\windows_cis_audit_report.log` (Windows).

### 2. Interactive HTML Web Reports (Auditor / Executive View)
The tools dynamically inject charts and statistics into a standalone HTML webpage. To inspect the structured charts and drill-down results:

* **On Windows:** Open the path `C:\ProgramData\SecurityAudit\windows_cis_audit_report.html` inside any browser.
* **On Linux:** Download or view the file `/var/log/debian_cis_audit_report.html` (or `rhel_*`).

#### Web Interface Highlights:
- **Donut Graph:** Visualizes your overall `PASS` percentage ratio instantly.
- **Filters by Severity:** Helps target high-risk infrastructure flaws directly.
- **Built-in Blueprints:** Click on any warning to reveal the ready-made `Remediation` snippet to pass the control next time.

---

## ⚖️ Exit Codes & Automations

Integrate these scripts into your active CI/CD regression or server initialization loops. The execution flags return standard numeric statuses:
* `0` — Success: Perfect compliance score, all rules passed.
* `1` — Notice: Level 2 suggestions or warnings discovered (`[WARN]`).
* `2` — Alert: Critical misconfiguration or compliance gaps uncovered (`[FAIL]`).
* `3` — Access Denied: Script started without root/administrator elevation privileges.
