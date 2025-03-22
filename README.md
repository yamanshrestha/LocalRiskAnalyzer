# 🛡️ LocalRiskAnalyzer

**LocalRiskAnalyzer** is a command-line tool for Windows that scans all local services and running processes, retrieves their executable paths and versions, and checks them for known vulnerabilities using the NVD CVE API. It provides both TXT and JSON logs and includes risk scoring based on CVSS.

---

## 📦 Features

- 🔍 Scan all Windows services (running, stopped, suspended)
- ⚙️ Scan all active processes
- 🔐 Check for CVEs using:
  - Keyword search (fallback)
  - ✅ CPE-based matching (version-aware)
- ⚠️ Assign risk level based on CVSS score
- 📝 Export logs to JSON and readable TXT files
- 📂 Logs organized by timestamped folders
- 🧪 CLI flags for fast testing

---

## 🛠️ Requirements

- Python 3.8+
- Windows OS (Linux support planned)

```
LocalRiskAnalyzer/
├── main.py                     # 🔁 Entry point (runs the whole scan)
├── .env                        # 🔐 Your NVD API key (not committed)
├── requirements.txt            # 📦 Python dependencies
├── README.md                   # 📖 Documentation
├── logs/                       # 📝 Timestamped output folders
│   └── 2025-03-22_15-20-01/
│       ├── services.json
│       ├── services.txt
│       ├── processes.json
│       └── processes.txt
├── scanner/                    # 🔍 Core scanning modules
│   ├── service_scanner.py      # Service info & version
│   ├── process_scanner.py      # Process info & linked service
│   └── utils.py                # Helpers (e.g. version extraction)
├── logger/                     # 📤 Logging & report generation
│   └── log_writer.py           # Writes logs to JSON/TXT
├── cve/                        # 🛡️ CVE API logic
│   └── cve_checker.py          # Search CVEs via NVD API (CPE + fallback)

```

## 🚀 Setup

1. Clone the repo or download the files
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory:

```
NVD_API_KEY=your-nvd-api-key-here
```

> 🔑 You can get a free API key from: https://nvd.nist.gov/developers/request-an-api-key

---

## 🧠 Usage Syntax

```bash
python main.py [-cve] [-stop N]
```

### Arguments:

| Flag        | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `-cve`      | Enable CVE scanning for all services & processes                            |
| `-stop N`   | Stop CVE scanning after N services and N processes (useful for testing)     |

---

## ✅ Examples

### Basic scan (no CVE check):
```bash
python main.py
```

### Full scan with CVE matching:
```bash
python main.py -cve
```

### Scan with CVE but limit to 3 services & 3 processes:
```bash
python main.py -cve -stop 3
```

---

## 📁 Output

Each run generates a folder like:

```
logs/
└── 2025-03-22_14-35-12/
    ├── services.json
    ├── services.txt
    ├── processes.json
    └── processes.txt
```

---

## 📊 Risk Scoring

- **High**: CVSS ≥ 7.0
- **Medium**: Any CVE found, but below 7.0
- **Low**: No known CVEs found

---

## 🧩 Coming Soon

- Linux support
- VirusTotal & HybridAnalysis integrations
- CPE caching for offline mode
- GUI / HTML export

---
