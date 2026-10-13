# CLI guide

The `white` command runs the scanner locally. It does not need the GUI, a server or Supabase.

## Commands

```text
white --help                      Show all commands
white --version                   Print the version (also: white version)
white checks                      List all checks with their category and mode
white doctor [--online]           Verify installation and configuration (--online also pings Supabase Auth)
white config                      Show effective configuration (secrets masked)
white scan URL [options]          Scan a website you are authorized to assess
white report FILE.json [options]  Show a saved JSON report or convert it to HTML/PDF
white serve [--host --port]       Start the web GUI (default http://127.0.0.1:8000)
```

## Scanning

```bash
white scan https://example.com --authorized
white scan https://example.com --authorized --format json --output report.json
white scan https://example.com --authorized --format pdf --output report.pdf
white scan https://example.com --authorized --format html --output report.html
white scan https://example.com/search?q=test --authorized --active-checks
white scan http://127.0.0.1:8443 --authorized --allow-private-network   # your own dev server
```

Options:

| Option | Meaning |
| --- | --- |
| `--authorized` | Confirms you own the site or have permission. Without it, WHITE asks interactively, or exits with code 2 when not interactive. |
| `-f, --format text\|json\|html\|pdf` | Output format (default text). PDF requires `--output`. |
| `-o, --output FILE` | Write the report to a file. Existing files are not overwritten unless `--force` is given. |
| `--active-checks` | Also run the opt-in XSS-reflection and SQL-error indicators. |
| `--allow-private-network` | Permit localhost/private IPs, and any web port (cloud metadata IPs remain blocked). Only for your own machines. |
| `--timeout SECONDS` | Per-request timeout (1-60, default 10). |
| `--max-seconds SECONDS` | Overall scan time limit (10-900, default 120). |
| `--fail-on SEVERITY` | Exit with code 1 when findings at or above `info/low/medium/high/critical` exist (useful in CI). |
| `-v, --verbose` | Show technical details and evidence. |
| `-q, --quiet` | Minimal output. |

Plain hostnames are accepted (`white scan example.com --authorized` scans `https://example.com/`).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed (findings may exist unless `--fail-on` is used) |
| 1 | Findings at or above `--fail-on` |
| 2 | Invalid input, refused target or missing authorization |
| 3 | Scan failed (website unreachable) |
| 4 | Scan cancelled (Ctrl+C) |
| 5 | Report could not be written or read |

## Reports

```bash
white report report.json                              # readable summary in the terminal
white report report.json --verbose                    # include evidence
white report report.json --format pdf -o report.pdf   # convert to PDF
white report report.json --format html -o report.html # standalone HTML (no scripts)
```

JSON reports follow schema version `1.0` (see `src/white/scanner/models.py`) and include
`findings_flat` for convenience.
