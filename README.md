# IIS Log Reader

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/zx90316/IIS-LogReader/actions/workflows/ci.yml/badge.svg)](https://github.com/zx90316/IIS-LogReader/actions/workflows/ci.yml)

Desktop tool for analyzing **IIS W3C Extended Log** files at scale.

Built with **Python + PySide6 + SQLite**, it streams multi-day / multi-GB logs into a persistent cache, provides DB Browser–style filtering, and generates statistics / anomaly reports (Markdown, HTML, PDF).

> UI language: Traditional Chinese (繁體中文)

---

## Features

- **Large log friendly** — streaming parse, SQLite cache, fingerprint-based reuse (second open is fast)
- **Multi-file / folder load** — browse several days of logs together
- **DB Browser–style table filters** — operators such as `=`, `<>`, `>`, `LIKE`, `NULL`
- **Lazy loading** — no full-table `COUNT(*)` before showing rows; scroll to fetch more
- **Blacklist filter rules** — exclude noise (static assets, health checks, etc.) before analysis
- **Statistics & anomalies** — Top IP/URL, hourly distribution, status codes, high-frequency IPs, bursts, suspicious User-Agents, slow requests, 4xx/5xx
- **Configurable thresholds** — stored in `app.config`
- **Report export** — Markdown / HTML / PDF (HTML with page-break hints → PDF)
- **Stats result cache** — recompute only when filter rules or thresholds change

---

## Requirements

- Windows 10/11 (primary target; Qt desktop app)
- Python **3.10+**
- Dependencies: see [`requirements.txt`](requirements.txt)

---

## Quick start

```powershell
# Clone
git clone https://github.com/zx90316/IIS-LogReader.git
cd IIS-LogReader

# Virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install
pip install -r requirements.txt

# Optional: copy example config
Copy-Item app.config.example app.config

# Run
python main.py
# or
python -m iis_log_reader
```

Sample logs for smoke testing are under [`_smoke_sample/`](_smoke_sample/).

---

## Configuration

Settings are stored in `app.config` (INI style) next to the project root.

| Section | Purpose |
|---------|---------|
| `[General]` | page size, last directory, timezone, window geometry |
| `[VisibleFields]` | table column visibility |
| `[FilterRules]` | blacklist rules (JSON) |
| `[AnomalyThresholds]` | anomaly detection thresholds |

Use [`app.config.example`](app.config.example) as a template. Local `app.config` and `cache/` are git-ignored.

---

## Project layout

```
IIS-LogReader/
├── main.py                 # GUI entry point
├── app.config.example      # Config template
├── requirements.txt
├── pyproject.toml
├── iis_log_reader/         # Application package
│   ├── parser.py           # W3C log streaming parser
│   ├── database.py         # SQLite backend
│   ├── cache_store.py      # Fingerprint cache
│   ├── filter_expr.py      # DB Browser filter expressions
│   ├── stats.py            # Statistics & anomalies
│   ├── report.py           # Markdown / HTML / PDF export
│   └── gui/                # PySide6 UI
├── tests/                  # Unit tests
└── _smoke_sample/          # Tiny sample logs
```

---

## Development

```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

Please do not open issues that include production log snippets containing secrets or personal data. See [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
