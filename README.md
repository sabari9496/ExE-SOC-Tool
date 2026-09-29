# 🛡️ EXE-SOC

**EXE-SOC** is a lightweight Security Operations Center (SOC) monitoring platform built with **Python, Flask, and SQLite**. It collects security events from servers and endpoints, analyzes activity using rule-based detection, and provides security analysts with a live dashboard for monitoring, investigation, and response.

The platform is designed as a practical SOC project for learning, security monitoring, incident investigation, and small-scale security operations.

---

## 🚀 Features

### 📊 SOC Dashboard

* Real-time alert monitoring
* Alert severity breakdown
* 24-hour activity timeline
* Top attacking/source IPs
* Threat map
* Endpoint health monitoring
* System resource monitoring
* Live event updates

### 🔍 Security Detection

EXE-SOC includes rule-based detection for common suspicious activities:

* SQL Injection
* Cross-Site Scripting (XSS)
* Path Traversal
* Brute Force Attacks
* Malware-related keywords
* Privilege Escalation indicators
* Port Scanning
* DNS anomalies
* IOC and blocklist matches

### 🚨 Alert Management

* Automatic alert severity escalation
* Repeated failed-login detection
* IOC/blocklist escalation
* Alert deduplication
* Alert occurrence counting
* Analyst investigation workflow

### 🔎 Investigation

Analysts can investigate alerts and IP addresses through the investigation interface.

Information includes:

* Triggering events
* Surrounding activity
* Source and destination information
* MITRE ATT&CK technique mapping
* Recommended actions
* Endpoint context
* Analyst notes
* IP risk information
* First and last seen timestamps
* Targeted hosts and ports
* 24-hour IP activity

### 📋 SOC Management

* Cases
* IOCs
* IP blocklist
* Audit trail
* Security reports
* CSV report export
* Playbooks
* Role-based access control

### 🤖 Endpoint Agent

The project includes an endpoint agent capable of:

* Sending heartbeat information
* Forwarding logs
* Monitoring endpoint activity

---

## 🏗️ Architecture

```text
                ┌─────────────────────┐
                │     Endpoints       │
                │  Servers / Agents   │
                └──────────┬──────────┘
                           │
                           │ Logs / Events
                           ▼
                ┌─────────────────────┐
                │    Ingest API       │
                │    Flask Server     │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Detection Engine    │
                │                     │
                │ Rules / IOC /       │
                │ Brute Force / etc.  │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │      SQLite DB      │
                │       soc.db        │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    SOC Dashboard    │
                │                     │
                │ Alerts / Cases      │
                │ Investigation       │
                │ Reports / Playbooks │
                └─────────────────────┘
```

---

## 📁 Project Structure

```text
EXE-SOC/
│
├── app.py
├── db.py
├── engine.py
├── investigate.py
├── requirements.txt
├── run.sh
├── README.md
│
├── static/
│   ├── css/
│   ├── js/
│   └── ...
│
├── templates/
│   ├── dashboard.html
│   ├── login.html
│   └── ...
│
└── tools/
    ├── agent.py
    ├── simulate.py
    └── selftest.py
```

---

# ⚙️ Requirements

* Python **3.9+**
* Flask
* SQLite
* `pip`
* Linux or Windows environment

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

# 📥 Installation

Clone the repository:

```bash
git clone https://github.com/sabari9496/ExE-SOC-Tool.git
```

Move into the project directory:

```bash
cd ExE-SOC-Tool
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
./run.sh
```

The dashboard will normally be available at:

```text
http://127.0.0.1:5000
```

### Windows

If `run.sh` is not suitable for your Windows environment, start the Flask application directly:

```powershell
python app.py
```

---

# 🔐 Default Login

The development environment includes default accounts:

| Username  | Password      | Role                             |
| --------- | ------------- | -------------------------------- |
| `admin`   | `Admin@123`   | Full access                      |
| `analyst` | `Analyst@123` | Alert investigation and response |
| `viewer`  | `Viewer@123`  | Read-only                        |

> ⚠️ **Important:** Change the default credentials before deploying the platform in a real environment.

You can configure passwords using:

```text
SOC_ADMIN_PASSWORD
SOC_ANALYST_PASSWORD
SOC_VIEWER_PASSWORD
```

Other supported environment variables include:

```text
SOC_HOST
SOC_PORT
SOC_DB
SOC_SECRET
```

---

# 📡 Event Ingestion

EXE-SOC supports event ingestion through an API.

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/ingest \
-H "X-API-Key: YOUR_API_KEY" \
-H "Content-Type: application/json" \
-d '{"source_ip":"1.2.3.4","message":"Failed password for root"}'
```

Supported event fields include:

```json
{
  "source_ip": "1.2.3.4",
  "message": "Failed password for root",
  "dest_ip": "10.0.0.5",
  "host": "server01"
}
```

---

# 🤖 Endpoint Agent

The included endpoint agent can forward system logs and heartbeat information to the SOC server.

Example:

```bash
python tools/agent.py --server URL --key KEY
```

For Linux authentication logs:

```bash
python tools/agent.py --server URL --key KEY --follow /var/log/auth.log
```

The agent requires additional packages such as:

```bash
pip install psutil requests
```

---

# 🧪 Demo Mode

EXE-SOC includes a simulation tool for generating sample security events.

```bash
python tools/simulate.py --key KEY
```

This can be used to demonstrate:

* Failed login alerts
* Attack detection
* Alert escalation
* IP investigation
* Dashboard activity
* SOC response workflows

---

# 🔎 SPL-Style Search

EXE-SOC provides an SPL-style search interface for investigating events.

Example:

```text
index=events "failed password" | stats count by source_ip | sort -count | head 10
```

Supported operations include:

```text
=
!=
>
<
*
NOT
```

Example searches:

```text
index=events source_ip=1.2.3.4
```

```text
index=alerts severity=Critical
```

---

# 🚨 Detection & Response

The detection engine uses pattern-based rules to identify suspicious activity.

Example detection categories:

```text
SQL Injection
XSS
Path Traversal
Brute Force
Malware Indicators
Privilege Escalation
Port Scanning
DNS Anomalies
IOC Matches
```

Repeated failed login attempts can automatically increase alert severity.

The platform also supports response actions such as:

* Blocking IP addresses
* Creating cases
* Notifying analysts
* Isolating endpoints
* Running configured playbooks

> ⚠️ Automatic network enforcement such as `iptables` requires appropriate privileges and should be tested carefully before use.

---

# 👥 Role-Based Access Control

EXE-SOC provides three main roles:

### Viewer

Read-only access to SOC information.

### Analyst

Can:

* Investigate alerts
* Investigate IP addresses
* Manage cases
* Manage IOCs
* Block IPs
* Investigate endpoints
* Add analyst notes

### Administrator

Can additionally:

* Manage users
* Configure settings
* Manage playbooks
* Manage system configuration
* Perform administrative operations

---

# 🧪 Testing

The project includes automated security and functionality tests.

Run the application using an empty test database and execute:

```bash
python tools/selftest.py
```

The test suite covers areas such as:

* Authentication
* RBAC
* Detection rules
* Alert deduplication
* Alert escalation
* Playbooks
* IOCs
* Investigation
* SPL search
* Cases
* Reports
* Login protection

> ⚠️ Never run automated tests against production SOC data.

---

# 🔒 Security

EXE-SOC includes several security protections:

* Password hashing using **scrypt**
* Login lockout after repeated failures
* HttpOnly session cookies
* SameSite cookie protection
* HTML output escaping
* CSV formula-injection protection
* CSRF protection for state-changing browser requests
* API-key authentication for ingestion

---

# 🌐 Deployment

For server deployment:

```text
Internet
   │
   ▼
Nginx / Caddy
   │
   │ HTTPS
   ▼
EXE-SOC Flask Application
   │
   ▼
SQLite Database
```

Recommended deployment practices:

* Use HTTPS
* Keep the Flask application behind a reverse proxy
* Use strong passwords
* Change default credentials
* Use `--no-demo`
* Restrict database access
* Back up the database
* Protect API keys
* Run the service using a dedicated user
* Avoid exposing the Flask development server directly to the Internet

---

# ⚠️ Limitations

EXE-SOC is a lightweight SOC monitoring platform and has some limitations.

* Detection is primarily rule/pattern based
* It does not replace a commercial SIEM
* SQLite is intended for small-to-medium workloads
* Windows Event Log collection is not currently implemented
* Native network packet inspection is not included
* Advanced behavioral analytics are not implemented
* Production deployments should use additional security controls

For network monitoring, technologies such as **Zeek** or **Suricata** can be integrated to provide additional network security telemetry.

---

# 📸 Screenshots

Add screenshots of the project here:

```text
docs/
├── dashboard.png
├── alerts.png
├── investigation.png
└── threat-map.png
```

Example:

```markdown
![EXE-SOC Dashboard](docs/dashboard.png)
```

---

# 🔮 Future Improvements

Planned improvements may include:

* Windows Event Log integration
* Syslog support
* Zeek integration
* Suricata integration
* Advanced threat intelligence
* Machine-learning-based anomaly detection
* Improved endpoint monitoring
* Docker deployment
* PostgreSQL support
* Email/Telegram/Slack notifications
* Advanced MITRE ATT&CK mapping
* Multi-tenant SOC support

---

# ⚖️ Legal Notice

EXE-SOC is intended for **authorized security monitoring and defensive security purposes only**.

Only monitor systems, networks, endpoints, and users when you have appropriate authorization.

The developers and contributors are not responsible for unauthorized use of this software.

---

# 📄 License

This project is released under the **MIT License**.

See the `LICENSE` file for details.

---

# 👨‍💻 Author

**Sabareesh**

Cybersecurity | VAPT | SOC | Web & API Security

---

## ⭐ Project

If you find EXE-SOC useful for learning or security research, consider giving the repository a ⭐ on GitHub.

**Repository:**
https://github.com/sabari9496/ExE-SOC-Tool
