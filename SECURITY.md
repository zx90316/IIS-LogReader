# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a vulnerability

If you discover a security issue:

1. **Do not** open a public GitHub issue with exploit details.
2. Contact the repository maintainers privately (GitHub Security Advisory preferred).
3. Include steps to reproduce and impact assessment if possible.

## Handling log data

This tool is designed to read IIS access logs, which may contain IP addresses, usernames, query strings, or other sensitive data.

- Prefer analyzing logs on a machine you control.
- Do not upload production logs to public issues, PRs, or CI artifacts.
- Clear the local `cache/` directory when finished with sensitive datasets.
