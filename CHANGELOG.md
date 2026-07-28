# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-28

### Added

- CSV export for filtered log rows and statistics tables
- Clipboard copy helpers for table selections
- Background worker support for CSV export

### Improved

- Log parser and SQLite import performance / reliability
- Database constants and batch handling during multi-file import
- Table and stats tab interactions (selection, export entry points)

## [1.0.1] - 2026-07-21

### Fixed

- Release packaging workflow and asset publishing for tagged builds

## [1.0.0] - 2026-07-21

### Added

- Desktop GUI (PySide6) for IIS W3C Extended Log analysis
- Streaming parse into SQLite with fingerprint-based persistent cache
- DB Browser–style column filters and lazy-loaded table view
- Blacklist filter rules with config persistence (`app.config`)
- Statistics and anomaly detection with configurable thresholds
- Report export: Markdown, HTML, and PDF
- Stats result caching keyed by filter rules + thresholds
- Sample logs under `_smoke_sample/`
- MIT license and GitHub project scaffolding
- Nuitka packaging scripts for Windows release (`build.bat`, `scripts/build_nuitka.ps1`)
- GitHub Actions Release workflow: tag `v*.*.*` → build standalone ZIP → GitHub Release assets

[1.1.0]: https://github.com/zx90316/IIS-LogReader/releases/tag/v1.1.0
[1.0.1]: https://github.com/zx90316/IIS-LogReader/releases/tag/v1.0.1
[1.0.0]: https://github.com/zx90316/IIS-LogReader/releases/tag/v1.0.0
