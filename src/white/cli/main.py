"""The `white` command-line interface. Runs the shared scanner locally; no GUI or cloud needed."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import sys
import threading
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from white import __version__
from white.reporting import analytics
from white.reporting.html_report import build_html
from white.reporting.json_report import ReportLoadError, load_report, to_json
from white.reporting.pdf_report import build_pdf
from white.scanner.engine import Progress, Scanner
from white.scanner.models import (
    SEVERITY_ORDER,
    STATUS_LABELS,
    ScanConfig,
    ScanReport,
    ScanState,
    Severity,
)
from white.scanner.netsafety import (
    TargetValidationError,
    normalize_user_url,
    validate_target_url,
)
from white.scanner.registry import all_checks

app = typer.Typer(
    name="white",
    help="WHITE - evidence-based website security assessment. Only scan websites you own or "
    "are explicitly authorized to assess.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True)


class ExitCode:
    OK = 0
    FINDINGS = 1  # findings at or above --fail-on
    USAGE = 2  # invalid input, refused target, missing authorization
    SCAN_FAILED = 3  # target unreachable or scan failed
    CANCELLED = 4
    OUTPUT = 5  # report could not be written / read


class OutputFormat(StrEnum):
    text = "text"
    json = "json"
    html = "html"
    pdf = "pdf"


class FailOn(StrEnum):
    none = "none"
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_STYLE = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
STATUS_STYLE = {
    "PASS": "green",
    "FINDING": "red",
    "POTENTIAL": "yellow",
    "INCONCLUSIVE": "magenta",
    "NOT_APPLICABLE": "dim",
    "NOT_TESTED": "dim",
    "ERROR": "bold magenta",
}
AUTH_TEXT = (
    "WHITE must only be used on websites you own or have explicit written permission to assess. "
    "Scanning other websites may be illegal."
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"WHITE {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", "-V", callback=_version_callback, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """WHITE website security assessment tool."""


@app.command()
def version() -> None:
    """Show the WHITE version."""
    console.print(f"WHITE {__version__}")


@app.command("checks")
def list_checks() -> None:
    """List every check WHITE can run."""
    table = Table(title="WHITE checks", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Mode")
    table.add_column("Description")
    for check in all_checks():
        table.add_row(
            check.id,
            check.name,
            check.category.label,
            "active (opt-in)" if check.active else "passive",
            check.description,
        )
    console.print(table)


def _write_output(path: Path, data: bytes, force: bool) -> None:
    path = path.expanduser()
    if path.exists() and path.is_dir():
        raise OSError(f"{path} is a directory")
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists (use --force to overwrite)")
    if not path.resolve().parent.is_dir():
        raise FileNotFoundError(f"The folder {path.resolve().parent} does not exist")
    path.write_bytes(data)


def _render(report: ScanReport, fmt: OutputFormat) -> bytes:
    if fmt is OutputFormat.json:
        return to_json(report).encode("utf-8")
    if fmt is OutputFormat.html:
        return build_html(report).encode("utf-8")
    if fmt is OutputFormat.pdf:
        return build_pdf(report)
    raise ValueError("text output is printed, not written")


def print_report(report: ScanReport, verbose: bool = False) -> None:
    label, _tone = analytics.overall_assessment(report)
    s = report.summary
    console.rule(f"[bold]WHITE report - {escape(report.hostname)}")
    console.print(f"Target: {escape(report.target_url)}")
    if report.final_url and report.final_url != report.target_url:
        console.print(f"Final URL: {escape(report.final_url)}")
    console.print(
        f"Status: {report.state.value}   Duration: {report.duration_seconds or 0:.1f}s   "
        f"Scan ID: {report.scan_id}"
    )
    console.print(f"\n[bold]{escape(label)}[/bold]")
    console.print(escape(analytics.executive_summary(report)))
    sev = s.severity_counts
    console.print(
        f"\nFindings: [bold red]{sev.CRITICAL} critical[/]  [red]{sev.HIGH} high[/]  "
        f"[yellow]{sev.MEDIUM} medium[/]  [blue]{sev.LOW} low[/]  [dim]{sev.INFO} informational[/]"
    )
    for severity in SEVERITY_ORDER:
        group = [f for f in report.findings if f.severity == severity]
        if not group:
            continue
        console.print(f"\n[{SEVERITY_STYLE[severity.value]}]== {severity.label} ({len(group)}) ==[/]")
        for f in group:
            tag = "" if f.status.value == "FINDING" else " [yellow](possible - confirm manually)[/]"
            console.print(
                f"  - [bold]{escape(f.title)}[/]{tag}  [dim]confidence {f.confidence.value.lower()}[/]"
            )
            console.print(f"    {escape(f.summary)}")
            console.print(f"    [green]Next step:[/] {escape(f.recommendation)}")
            if verbose:
                console.print(f"    [dim]Technical:[/] {escape(f.technical_details)}")
                for e in f.evidence:
                    console.print(f"    [dim]{escape(e.label)}:[/] {escape(e.value)}")
                if f.affected_url:
                    console.print(f"    [dim]URL:[/] {escape(f.affected_url)}")
    table = Table(title="\nCheck coverage", show_header=True)
    table.add_column("Check")
    table.add_column("Outcome")
    table.add_column("Details", overflow="fold")
    for check in report.checks:
        details = check.message + (
            ("  Errors: " + "; ".join(check.errors)) if check.errors and verbose else ""
        )
        table.add_row(
            check.name,
            f"[{STATUS_STYLE[check.status.value]}]{STATUS_LABELS[check.status]}[/]",
            escape(details),
        )
    console.print(table)
    for e in report.errors:
        console.print(f"[magenta]Scan error:[/] {escape(e)}")
    console.print(
        "\n[dim]A 'Passed' check means only that the specific issue was not detected. "
        "WHITE does not guarantee that a website is secure.[/]"
    )


def _exit_code(report: ScanReport, fail_on: FailOn) -> int:
    if report.state == ScanState.CANCELLED:
        return ExitCode.CANCELLED
    if report.state == ScanState.FAILED:
        return ExitCode.SCAN_FAILED
    if fail_on is not FailOn.none:
        threshold = Severity(fail_on.value.upper())
        if any(f.severity.rank <= threshold.rank for f in report.findings):
            return ExitCode.FINDINGS
    return ExitCode.OK


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="Website to assess, e.g. https://example.com")],
    authorized: Annotated[
        bool, typer.Option("--authorized", help="Confirm you own or are authorized to assess this website.")
    ] = False,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.text,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to this file.")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite the output file if it exists.")] = False,
    active_checks: Annotated[
        bool,
        typer.Option(
            "--active-checks", help="Also run opt-in input-handling indicators (harmless GET probes)."
        ),
    ] = False,
    allow_private_network: Annotated[
        bool,
        typer.Option(
            "--allow-private-network",
            help="Allow localhost/private addresses (for your own development servers only).",
        ),
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", min=1, max=60, help="Per-request timeout in seconds.")
    ] = 10.0,
    max_seconds: Annotated[
        float, typer.Option("--max-seconds", min=10, max=900, help="Overall scan time limit.")
    ] = 120.0,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit with code 1 if findings at or above this severity exist."),
    ] = FailOn.none,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show technical details and evidence.")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Only print errors and the output path.")
    ] = False,
) -> None:
    """Scan a website you are authorized to assess."""
    if fmt is OutputFormat.pdf and output is None:
        err.print("[red]PDF output requires --output FILE.[/]")
        raise typer.Exit(ExitCode.USAGE)
    target = normalize_user_url(url)
    config = ScanConfig(
        request_timeout=timeout,
        max_scan_seconds=max_seconds,
        active_checks=active_checks,
        allow_private_targets=allow_private_network,
    )
    scanner = Scanner(config)
    try:
        validated = validate_target_url(target, config)
    except TargetValidationError as exc:
        err.print(f"[red]Target refused:[/] {escape(str(exc))}")
        raise typer.Exit(ExitCode.USAGE) from None

    if not authorized:
        err.print(f"[yellow]Authorization required.[/] {AUTH_TEXT}")
        if sys.stdin.isatty() and not quiet:
            if not typer.confirm(
                f"Do you own {validated.host} or have explicit permission to assess it?", default=False
            ):
                err.print("Scan not started.")
                raise typer.Exit(ExitCode.USAGE)
        else:
            err.print("Re-run with --authorized to confirm.")
            raise typer.Exit(ExitCode.USAGE)

    if not quiet:
        mode = "including opt-in active input checks" if active_checks else "passive checks only"
        console.print(
            f"Scanning [bold]{escape(validated.url)}[/] with {len(scanner.checks)} checks ({mode})."
        )
        console.print(
            "[dim]WHITE sends a limited number of GET/HEAD requests. It does not submit forms, "
            "guess passwords or attempt exploitation.[/]"
        )

    cancel = threading.Event()
    state = {"stage": "Starting"}

    def on_progress(p: Progress) -> None:
        state["stage"] = f"[{p.completed}/{p.total}] {p.stage}"
        if status is not None:
            status.update(escape(state["stage"]))
        elif verbose:
            err.print(escape(state["stage"]))

    status = None
    try:
        if quiet or not console.is_terminal:
            report = scanner.run(target, progress=on_progress, cancel_event=cancel)
        else:
            with console.status("Starting scan...") as status:
                report = scanner.run(target, progress=on_progress, cancel_event=cancel)
    except KeyboardInterrupt:
        err.print("[yellow]Scan interrupted.[/]")
        raise typer.Exit(ExitCode.CANCELLED) from None

    if output is not None:
        out_fmt = fmt if fmt is not OutputFormat.text else OutputFormat.json
        try:
            _write_output(output, _render(report, out_fmt), force)
        except (OSError, ValueError) as exc:
            err.print(f"[red]Could not write report:[/] {escape(str(exc))}")
            raise typer.Exit(ExitCode.OUTPUT) from None
        if not quiet:
            print_report(report, verbose)
        console.print(f"Report saved to {escape(str(output))} ({out_fmt.value}).")
    elif fmt is OutputFormat.json:
        sys.stdout.write(to_json(report) + "\n")
    elif fmt is OutputFormat.html:
        sys.stdout.write(build_html(report))
    elif not quiet:
        print_report(report, verbose)
    raise typer.Exit(_exit_code(report, fail_on))


@app.command()
def report(
    path: Annotated[Path, typer.Argument(help="A JSON report produced by 'white scan --format json'.")],
    fmt: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Convert to this format.")
    ] = OutputFormat.text,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the converted report here.")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite the output file if it exists.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show technical details.")] = False,
) -> None:
    """Display a saved JSON report or convert it to HTML or PDF."""
    try:
        loaded = load_report(path)
    except ReportLoadError as exc:
        err.print(f"[red]Cannot read report:[/] {escape(str(exc))}")
        raise typer.Exit(ExitCode.OUTPUT) from None
    if fmt is OutputFormat.text:
        print_report(loaded, verbose)
        return
    if output is None:
        if fmt is OutputFormat.pdf:
            err.print("[red]PDF output requires --output FILE.[/]")
            raise typer.Exit(ExitCode.USAGE)
        sys.stdout.write(_render(loaded, fmt).decode("utf-8"))
        return
    try:
        _write_output(output, _render(loaded, fmt), force)
    except (OSError, ValueError) as exc:
        err.print(f"[red]Could not write report:[/] {escape(str(exc))}")
        raise typer.Exit(ExitCode.OUTPUT) from None
    console.print(f"Report saved to {escape(str(output))} ({fmt.value}).")


def _settings():
    from white.config import Settings

    return Settings()


@app.command()
def config() -> None:
    """Show the effective configuration (secrets are masked)."""
    try:
        settings = _settings()
    except ValidationError as exc:
        err.print(f"[red]Invalid configuration:[/] {escape(str(exc))}")
        raise typer.Exit(ExitCode.USAGE) from None
    table = Table(title="WHITE configuration")
    table.add_column("Setting")
    table.add_column("Value", overflow="fold")
    table.add_column("Source variable")
    key = settings.supabase_publishable_key
    rows = [
        ("Mode", "Supabase accounts" if settings.supabase_enabled else "Local single-user", "-"),
        ("Supabase URL", settings.supabase_url or "(not set)", "SUPABASE_URL"),
        ("Supabase publishable key", (key[:14] + "...") if key else "(not set)", "SUPABASE_PUBLISHABLE_KEY"),
        (
            "Session secret",
            "set" if settings.secret_key else "(not set - temporary secret used)",
            "WHITE_SECRET_KEY",
        ),
        ("Site URL", settings.site_url, "WHITE_SITE_URL"),
        ("Data directory", str(settings.data_dir), "WHITE_DATA_DIR"),
        (
            "Domain verification required",
            str(settings.domain_verification_required),
            "WHITE_REQUIRE_DOMAIN_VERIFICATION",
        ),
        (
            "Allow private targets (GUI/API)",
            str(settings.allow_private_targets),
            "WHITE_ALLOW_PRIVATE_TARGETS",
        ),
        ("Request timeout (s)", str(settings.request_timeout), "WHITE_REQUEST_TIMEOUT"),
        ("Max scan time (s)", str(settings.max_scan_seconds), "WHITE_MAX_SCAN_SECONDS"),
        ("Max response bytes", str(settings.max_response_bytes), "WHITE_MAX_RESPONSE_BYTES"),
        ("Max concurrent scans", str(settings.max_concurrent_scans), "WHITE_MAX_CONCURRENT_SCANS"),
        ("Scans per user per hour", str(settings.scans_per_user_per_hour), "WHITE_SCANS_PER_USER_PER_HOUR"),
    ]
    for row in rows:
        table.add_row(*row)
    console.print(table)
    console.print("[dim]The CLI 'scan' command uses its own options and does not require any of these.[/]")


@app.command()
def doctor(
    online: Annotated[
        bool, typer.Option("--online", help="Also test the connection to Supabase Auth.")
    ] = False,
) -> None:
    """Check that WHITE is installed and configured correctly."""
    problems = 0

    def line(ok: bool | None, text: str) -> None:
        nonlocal problems
        mark = "[green]OK[/]" if ok else ("[yellow]--[/]" if ok is None else "[red]FAIL[/]")
        if ok is False:
            problems += 1
        console.print(f"{mark}  {text}")

    py_ok = sys.version_info >= (3, 11)
    line(py_ok, f"Python {platform.python_version()} ({'3.11+ required' if not py_ok else 'supported'})")
    for dist in ("httpx", "fastapi", "typer", "beautifulsoup4", "pydantic", "reportlab", "jinja2", "uvicorn"):
        try:
            line(True, f"{dist} {importlib.metadata.version(dist)}")
        except importlib.metadata.PackageNotFoundError:
            line(False, f"{dist} is not installed")
    try:
        settings = _settings()
        line(True, "Configuration is valid")
    except ValidationError as exc:
        line(False, f"Configuration is invalid: {escape(str(exc))}")
        raise typer.Exit(ExitCode.USAGE) from None
    data_dir = settings.data_dir
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".write-test"
        probe.write_text("ok")
        probe.unlink()
        line(True, f"Data directory is writable: {data_dir}")
    except OSError as exc:
        line(False, f"Data directory {data_dir} is not writable: {exc}")
    line(
        None if not settings.secret_key else True,
        "WHITE_SECRET_KEY is set"
        if settings.secret_key
        else "WHITE_SECRET_KEY not set: GUI sessions will reset when the server restarts",
    )
    if settings.supabase_enabled:
        line(True, "Supabase is configured (accounts and cloud history enabled in the GUI)")
        if online:
            import httpx

            try:
                r = httpx.get(
                    f"{settings.supabase_url}/auth/v1/health",
                    headers={"apikey": settings.supabase_publishable_key or ""},
                    timeout=10,
                )
                line(r.status_code == 200, f"Supabase Auth health endpoint returned {r.status_code}")
            except httpx.HTTPError as exc:
                line(False, f"Could not reach Supabase: {exc.__class__.__name__}")
    else:
        line(None, "Supabase not configured: the GUI runs in local single-user mode (CLI unaffected)")
    if os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"):
        line(None, "Proxy environment variables are ignored by the scanner by design")
    console.print("\nNo problems found." if problems == 0 else f"\n{problems} problem(s) found.")
    raise typer.Exit(ExitCode.OK if problems == 0 else ExitCode.USAGE)


@app.command()
def serve(
    host: Annotated[
        str, typer.Option(help="Interface to bind. Keep 127.0.0.1 unless you know you need otherwise.")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8000,
    reload: Annotated[bool, typer.Option(help="Auto-reload on code changes (development).")] = False,
) -> None:
    """Start the web GUI (open http://127.0.0.1:8000 in your browser)."""
    import uvicorn

    if host not in {"127.0.0.1", "localhost", "::1"}:
        err.print(
            "[yellow]Warning:[/] binding to a non-loopback address exposes WHITE to your network. "
            "Use Supabase accounts, HTTPS and domain verification before doing this."
        )
    console.print(f"WHITE GUI starting on http://{host}:{port}  (Ctrl+C to stop)")
    uvicorn.run(
        "white.api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
