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

## Antivirus / corporate EDR false positives

Packaged Python GUIs (especially **onefile** builds that extract to `%TEMP%`) are frequently flagged by heuristic engines even when the source is benign.

### What this project does to reduce risk

1. **Default release mode is Nuitka `standalone`** (folder distribution), not onefile self-extracting EXE.
2. Embeds normal Windows version resources (product/company/file description).
3. Uses `asInvoker` (no admin elevation) application manifest.
4. Does **not** use UPX or other third-party packers.
5. Build script supports **Authenticode signing** via `-CertThumbprint`.

### Recommended for company deployment

1. Build with:

   ```powershell
   .\scripts\build_nuitka.ps1 -Mode standalone -CertThumbprint "<your-cert-sha1>"
   ```

2. Distribute the **whole** `release\IIS-LogReader\` folder (or the generated ZIP).
3. Prefer an **EV/OV code-signing certificate** issued to your organization.
4. If still blocked, ask IT to allowlist by **publisher** or **file hash**, and submit a false-positive report to the AV vendor (for Defender: [Microsoft submission](https://www.microsoft.com/wdsi/filesubmission)).

> No packaging method can *guarantee* zero detections on every AV product without signing and reputation. Standalone + Authenticode is the practical enterprise path.
