# VibeAnalyst
an ai driven  powerfull cyber security analyst 


# 🛡️ Security Audit & Dashboard Toolkit

A two-part toolkit for **collecting system & log data**, analyzing it with **AI models (OpenAI or Google Gemini)**, and turning the results into a **beautiful interactive dashboard**.  

This project is designed for **SOC analysts, security students, and sysadmins** who want automated security posture checks and easy-to-read reports.

---

## 🚀 Components

### 1️⃣ Analyzer (`sys_audit_agent.py` / `AgentDualModel.py`)
- Collects **system info** (CPU, RAM, processes, network, users, uptime).
- Reads **Sysmon logs** from Windows Event Viewer (`.evtx`).
- Sends the data to an **AI model** (OpenAI or Gemini) to:
  - Detect vulnerabilities
  - Map findings to **CVE references**
  - Suggest remediation steps
  - **Grade security posture** (1–100)

Output:
- `.md` (Markdown) report with detailed findings
- `.json` snapshot of raw data

---

### 2️⃣ Dashboard (`AuditDash.py`)
- Scans the folder for `.md` reports
- Converts them into a **responsive HTML dashboard**
- Features:
  - 📊 Security score (1–100)
  - 📂 Sidebar navigation with filters & search
  - 📱 Responsive UI (desktop & mobile)
  - 🔎 Expandable/collapsible report sections
  - 100% offline (just open in browser)

Output:
- `audit_dashboard.html`

---

## 📦 Installation

Clone the repo:
```bash
git clone https://github.com/ariel1arus/VibeAnalyst.git
cd security-audit-dashboard
