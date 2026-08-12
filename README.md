# SecureGuard — Linux Security Scanning & Hardening Tool

SecureGuard is a Python/PyQt6 desktop application for assessing and hardening Ubuntu 22.04 systems using CIS-inspired security policies. It combines automated security checks, privileged remediation, weighted security scoring, audit logging, security-level selection, and PDF reporting in a local desktop workflow.

> **Status:** Academic cybersecurity project / prototype.
>
> **Important:** SecureGuard can modify system configuration using `sudo`. Run it only on a test machine or virtual machine and take a snapshot/backup before applying remediation.

## Features

- Low / Medium / High security profiles
- 20 implemented security policies
- Automated compliance checks
- One-click remediation for non-compliant policies
- Weighted security score
- Background scan and remediation workers using PyQt6 `QThread`
- Audit logging to `logs/audit.log`
- PDF security/compliance reports
- Policy filtering by compliant / non-compliant status
- Security-level policy manager
- Dark-themed desktop GUI

## Implemented Policy Areas

| Category | Examples |
|---|---|
| Network | UFW enabled, default-deny incoming, Fail2Ban |
| SSH | Root SSH disabled, SSH Protocol 2, MaxAuthTries ≤ 4 |
| Patch | Unattended upgrades, APT automatic updates |
| Services | Cron enabled, Avahi disabled |
| Files | `/etc/shadow` permissions, `/etc/passwd` permissions |
| Kernel | IP forwarding disabled, ASLR level 2 |
| Logging | Rsyslog installed, UFW logging enabled |
| Accounts | No empty passwords, 90-day password expiry |
| Hardening | Core dump restriction, NTP/Chrony |
| Authentication | PAM password-quality minimum length |

## Security Levels

- **Low:** core security controls
- **Medium:** Low controls plus additional network, SSH, brute-force protection, and patch-management controls
- **High:** full configured policy set including kernel, account, service, logging, and hardening controls

The policy configuration is represented in code and can be adjusted through the application's **Manage Levels** interface.

## Architecture

```text
+-----------------------------+
|        SecureGuard GUI      |
|          PyQt6              |
+--------------+--------------+
               |
       Security Level Manager
               |
        +------+------+
        | Policy      |
        | Engine      |
        +------+------+
               |
       +-------+--------+
       |                |
   Check Functions   Fix Functions
       |                |
       +-------+--------+
               |
        Ubuntu 22.04 Host
               |
   +-----------+-----------+
   |                       |
Audit Logging         PDF Reporting
```

## Requirements

- Ubuntu 22.04 or a compatible Debian-based Linux environment
- Python 3
- `sudo` privileges for remediation
- PyQt6
- ReportLab

## Installation

Clone the repository:

```bash
git clone https://github.com/KD33-droid/linux-security-hardening-tool.git
cd linux-security-hardening-tool
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run SecureGuard:

```bash
python3 secureguard.py
```

## How It Works

1. Select a security level.
2. SecureGuard loads the policies associated with that level.
3. Run a security scan.
4. Each policy executes its check function.
5. The application calculates a weighted security score.
6. Non-compliant policies expose a **Fix** action.
7. Remediation runs through `sudo` and the policy is checked again.
8. Audit activity is recorded locally.
9. A PDF report can be exported after a scan.

## Example Output

Add screenshots of the application to the `screenshots/` directory and reference them here. Recommended screenshots:

- Main dashboard / security-level selection
- Scan results showing compliant and non-compliant controls
- Security score and audit log
- Exported PDF report

## Limitations

This project is a security-hardening prototype intended for controlled environments. The implemented checks are **CIS-inspired** and should not be represented as official CIS Benchmark certification or complete CIS compliance.

Some remediation actions modify system configuration, install packages, enable/disable services, or change permissions. Test changes in a VM before applying them to a production system.

## Project Structure

```text
SecureGuard/
├── secureguard.py
├── requirements.txt
├── README.md
├── .gitignore
├── LICENSE
├── screenshots/
├── logs/
└── reports/
```

## Author

**Kuldeep Muddamsetty**

M.Tech — Computer Science & Engineering (Cybersecurity)
Manipal Institute of Technology

## License

MIT License. See `LICENSE`.
