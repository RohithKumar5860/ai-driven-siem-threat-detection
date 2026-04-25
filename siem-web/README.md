# 🛡️ AI-Based SIEM Threat Detection System

A production-quality, end-to-end **Security Information and Event Management (SIEM)** system featuring a hybrid threat detection engine (rule-based + Isolation Forest ML), a FastAPI backend, a real-time Vanilla JS dashboard, and automatic IP blocking.

---

## 📋 Table of Contents

1. [Features](#-features)
2. [Project Structure](#-project-structure)
3. [Requirements](#-requirements)
4. [Installation](#-installation)
5. [Usage](#-usage)
6. [API Reference](#-api-reference)
7. [Detection Logic](#-detection-logic)
8. [Dashboard](#-dashboard)
9. [Data Models](#-data-models)
10. [Tech Stack](#-tech-stack)
11. [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- **Hybrid Detection Engine** — combines deterministic rule checks with an Isolation Forest ML model
- **Real-time Dashboard** — single-page app with Submit Log, All Logs, Threats, and Blocked IPs views
- **Automatic IP Blocking** — IPs that score ≥ 70 are added to `blocked_ips.json` automatically
- **ML Hot-Reload** — retrain the model and reload it without restarting the server (`POST /reload-model`)
- **Thread-safe Storage** — atomic JSON writes with per-file locks prevent data corruption
- **Graceful Degradation** — if `model.pkl` is missing, the system skips ML scoring and keeps operating
- **Interactive API Docs** — Swagger UI available at `/docs`
- **Health Endpoint** — `/health` reports server status and whether the ML model is loaded

---

## 📁 Project Structure

```
siem-web/
├── backend/
│   ├── __init__.py       # Python package marker
│   ├── main.py           # FastAPI app, lifespan, all route handlers
│   ├── models.py         # Pydantic v2 models (LogEntry, ProcessedLog, LogResponse, BlockedIPEntry)
│   ├── ml_model.py       # Isolation Forest inference (lazy-loaded, cached)
│   ├── rule_engine.py    # Deterministic rule checks → score contribution
│   ├── scorer.py         # Combines rule + ML scores; severity classification; block threshold
│   ├── storage.py        # Thread-safe atomic JSON read/write for logs and blocked IPs
│   └── utils.py          # Logger factory, clamp(), classify_severity(), current_utc_iso()
├── frontend/
│   ├── index.html        # Single-page dashboard (Submit Log / Dashboard / Threats / Blocked IPs)
│   ├── style.css         # Dark cybersecurity theme (glassmorphism, Google Fonts)
│   └── script.js         # Fetch API calls, DOM rendering, toast notifications
├── data/
│   ├── logs.json         # Persisted processed log entries (auto-created on first run)
│   └── blocked_ips.json  # Auto-blocked IP records (auto-created on first run)
├── ml/
│   ├── train_model.py    # Synthetic data generation, model training, evaluation, and saving
│   └── model.pkl         # Trained scikit-learn Pipeline (StandardScaler + IsolationForest)
└── requirements.txt
```

---

## 📦 Requirements

- **Python 3.10+**
- pip packages (see `requirements.txt`):

| Package | Min Version | Purpose |
|---|---|---|
| `fastapi` | 0.100.0 | Web framework |
| `uvicorn[standard]` | 0.22.0 | ASGI server |
| `pydantic` | 2.0.0 | Data validation (v2 API) |
| `scikit-learn` | 1.2.0 | Isolation Forest |
| `numpy` | 1.24.0 | Feature arrays for ML |
| `pandas` | 2.0.0 | Synthetic data generation |
| `python-multipart` | 0.0.6 | Form/multipart support |
| `aiofiles` | 23.1.0 | Async file serving |

---

## 🚀 Installation

### 1. Navigate to the project root

```bash
cd siem-web
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Train the ML model

This generates `ml/model.pkl` (a scikit-learn Pipeline of StandardScaler + IsolationForest trained on 4,400 synthetic samples).

```bash
python ml/train_model.py
```

Expected output:

```
[train_model] Generating synthetic dataset ...
[train_model] Dataset: 4,400 rows  |  normal=4,000  anomaly=400
[train_model] Training Isolation Forest ...

==================================================
  Isolation Forest — Training Evaluation
==================================================
  Total samples : 4,400
  Accuracy      : XX.XX%
  True  Positives (anomaly correctly flagged) : ...
  ...
==================================================

[train_model] Saving model ...
  Model saved -> ...\ml\model.pkl
[train_model] Training complete.
```

### 4. Start the server

Run from the `siem-web/` directory (not from inside `backend/`):

```bash
python -m uvicorn backend.main:app --reload
```

> **Note (Windows):** Use `python -m uvicorn` rather than `uvicorn` directly if the command is not found in your PATH.

### 5. Open the dashboard

```
http://127.0.0.1:8000
```

The interactive Swagger API docs are available at:

```
http://127.0.0.1:8000/docs
```

---

## 🖥️ Usage

### Submitting a log via the dashboard

1. Open `http://127.0.0.1:8000` in your browser.
2. Fill in the **Submit Log** form:
   - **Source IP Address** — IPv4 address (validated by both frontend pattern and backend Pydantic validator)
   - **Destination Port** — integer 1–65535
   - **Payload Size (bytes)** — non-negative integer
   - **Action Type** — `Normal` or `Login Failed`
3. Click **Analyse & Submit**.
4. An **Analysis Result** card appears with threat score, severity badge, score bar, and detection flags.

### Submitting a log via curl

```bash
# High-severity threat (suspicious port + large payload + login_failed → score 70, AUTO-BLOCKED)
curl -X POST http://127.0.0.1:8000/log \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "10.0.0.1", "port": 4444, "payload_size": 12000, "action": "login_failed"}'

# Normal traffic (score 0, severity LOW)
curl -X POST http://127.0.0.1:8000/log \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "192.168.1.50", "port": 443, "payload_size": 512, "action": "normal"}'

# Medium-threat example
curl -X POST http://127.0.0.1:8000/log \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "172.16.0.99", "port": 31337, "payload_size": 5000, "action": "login_failed"}'
```

### Reloading the ML model after retraining

```bash
# 1. Retrain
python ml/train_model.py

# 2. Hot-reload (no server restart required)
curl -X POST http://127.0.0.1:8000/reload-model
```

---

## ⚙️ API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves the dashboard (`frontend/index.html`) |
| `POST` | `/log` | Submit a log entry for analysis |
| `GET` | `/logs` | Retrieve all stored log entries |
| `GET` | `/threats` | Retrieve entries flagged as threats (`is_threat: true`) |
| `GET` | `/blocked-ips` | Retrieve all auto-blocked IP records |
| `POST` | `/reload-model` | Hot-reload `ml/model.pkl` without server restart |
| `GET` | `/health` | Server health check (status + model_loaded flag + timestamp) |
| `GET` | `/docs` | Interactive Swagger UI |

### `POST /log` — Request Body

```json
{
  "source_ip": "10.0.0.1",
  "port": 4444,
  "payload_size": 12000,
  "action": "login_failed"
}
```

| Field | Type | Constraints | Description |
|---|---|---|---|
| `source_ip` | string | Valid IPv4 | Source IP of the network event |
| `port` | integer | 1–65535 | Destination port number |
| `payload_size` | integer | ≥ 0 | Payload size in bytes |
| `action` | string | `"login_failed"` \| `"normal"` | Type of action observed |

### `POST /log` — Response Body

```json
{
  "message": "Log processed successfully.",
  "log": {
    "id": "uuid-v4",
    "source_ip": "10.0.0.1",
    "port": 4444,
    "payload_size": 12000,
    "action": "login_failed",
    "timestamp": "2026-04-21T09:00:00.000000+00:00",
    "rule_score": 45,
    "ml_score": 25,
    "total_score": 70,
    "severity": "HIGH",
    "is_threat": true,
    "ml_anomaly": true,
    "blocked": true
  }
}
```

---

## 🧠 Detection Logic

### Pipeline Overview

```
LogEntry (source_ip, port, payload_size, action)
      │
      ├─→ Rule Engine ──────────────────→ rule_score (0–45)
      │
      ├─→ ML Model (Isolation Forest) ──→ ml_score (0 or 25)
      │
      └─→ Scorer ─────────────────────→ total_score (clamped 0–100)
                                              │
                                         severity + is_threat
                                              │
                                    ≥ 70? → Auto-block IP
```

### Rule Engine (`backend/rule_engine.py`)

| Rule | Condition | Score Awarded |
|------|-----------|---------------|
| Suspicious port | Port in `{4444, 31337, 1337, 9001, 6666}` | +20 |
| Large payload | `payload_size > 10,000` bytes | +15 |
| Failed login | `action == "login_failed"` | +10 |

Maximum possible rule score: **45** (all three rules triggered simultaneously).

### ML Engine (`backend/ml_model.py` + `ml/train_model.py`)

- **Algorithm:** scikit-learn `IsolationForest` wrapped in a `Pipeline` with `StandardScaler`
- **Features:** `port`, `payload_size`
- **Training data:** 4,400 synthetic samples — 4,000 normal + 400 anomalous
- **Contamination:** 9% (`contamination=0.09`)
- **Estimators:** 200 trees (`n_estimators=200`)
- **Result:** anomaly detected → **+25** to score; otherwise **+0**
- **Graceful fallback:** if `ml/model.pkl` is missing, ML score is 0 and a warning is logged

### Scorer (`backend/scorer.py`)

| Computation | Detail |
|---|---|
| `total_score = clamp(rule_score + ml_score, 0, 100)` | Sum, clamped to [0, 100] |
| `is_threat = total_score > 0` | Any positive score is a threat |
| `auto_block = total_score >= 70` | IP is added to `blocked_ips.json` |

### Severity Classification (`backend/utils.py`)

| Score Range | Severity |
|-------------|----------|
| 0 – 30 | 🟢 LOW |
| 31 – 60 | 🟡 MEDIUM |
| 61 – 100 | 🔴 HIGH |

---

## 🖼️ Dashboard

The frontend is a single-page application served at `/` with four views, controlled by a sidebar nav:

| View | Description |
|------|-------------|
| **Submit Log** | Form to ingest a new network event; shows analysis result card with score bar and detected flags |
| **Dashboard** | Sortable table of all stored log entries (timestamp, IP, port, payload, action, rule score, ML score, total score, severity) |
| **Threats** | Filtered view showing only entries where `is_threat = true`, plus ML anomaly and blocked status columns |
| **Blocked IPs** | Card grid of all auto-blocked IPs with blocking timestamp and reason |

A **Live** status indicator in the header polls the `/health` endpoint and shows a pulsing dot when the server is active.

**Sidebar quick-stats** (Total Logs · Threats · Blocked IPs) are refreshed on every page navigation.

---

## 🗄️ Data Models

### `LogEntry` (input via `POST /log`)

```python
source_ip:    str    # validated IPv4
port:         int    # 1–65535
payload_size: int    # ≥ 0
action:       Literal["login_failed", "normal"]
```

### `ProcessedLog` (stored in `data/logs.json`)

```python
id:           str    # UUID v4, auto-generated
source_ip:    str
port:         int
payload_size: int
action:       str
timestamp:    str    # UTC ISO 8601, auto-generated
rule_score:   int    # contribution from rule engine
ml_score:     int    # contribution from ML model (0 or 25)
total_score:  int    # clamped sum, 0–100
severity:     str    # "LOW" | "MEDIUM" | "HIGH"
is_threat:    bool
ml_anomaly:   bool
blocked:      bool
```

### `BlockedIPEntry` (stored in `data/blocked_ips.json`)

```python
ip:         str   # blocked source IP
blocked_at: str   # UTC ISO 8601 timestamp
reason:     str   # e.g. "Threat score 70 >= 70 (severity=HIGH)"
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2 |
| **ML** | scikit-learn (IsolationForest, StandardScaler, Pipeline), NumPy, pandas |
| **Frontend** | Vanilla HTML5 / CSS3 / JavaScript (ES6+), Google Fonts (Inter, JetBrains Mono) |
| **Storage** | JSON flat files with threading locks and atomic `.tmp` → rename writes |

---

## 🔧 Troubleshooting

### `uvicorn: command not found`
Use the module form instead:
```bash
python -m uvicorn backend.main:app --reload
```

### `ModuleNotFoundError: No module named 'backend'`
You must run the server from the **`siem-web/` directory**, not from inside `backend/`:
```bash
cd siem-web
python -m uvicorn backend.main:app --reload
```

### `model.pkl not found` (warning in logs, ML scoring disabled)
The server will still run, but with ML scoring disabled (all `ml_score = 0`). Generate the model first:
```bash
python ml/train_model.py
```

### Port already in use
```bash
python -m uvicorn backend.main:app --reload --port 8001
```

### Corrupt or invalid `logs.json` / `blocked_ips.json`
The storage layer handles `JSONDecodeError` and empty files gracefully, returning empty lists. If you need a full reset, delete both files — they will be re-created automatically on next server startup:
```bash
del data\logs.json data\blocked_ips.json
```

### Dashboard shows stale data
Click the **↻ Refresh** button on any page, or navigate away and back — each page navigation re-fetches data from the server.

### `pydantic` validation error on `POST /log`
Ensure:
- `source_ip` is a valid IPv4 address (e.g. `"192.168.1.1"`, not a hostname)
- `port` is between 1 and 65535
- `action` is exactly `"login_failed"` or `"normal"` (case-sensitive)
