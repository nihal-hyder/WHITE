"""CLI commands, exit codes and file handling (scans use a mocked website)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from tests.conftest import MockSite, good_site
from white import __version__
from white.cli import main as cli
from white.scanner.engine import Scanner

runner = CliRunner()


@pytest.fixture
def mock_scanner(monkeypatch):
    site = good_site()

    def factory(config, **kwargs):
        return Scanner(config.model_copy(update={"min_request_interval": 0}), transport=site.transport)

    monkeypatch.setattr(cli, "Scanner", factory)
    return site


def test_version():
    assert __version__ in runner.invoke(cli.app, ["--version"]).output
    assert __version__ in runner.invoke(cli.app, ["version"]).output


def test_checks_lists_all():
    result = runner.invoke(cli.app, ["checks"], env={"COLUMNS": "250"})
    assert result.exit_code == 0
    assert "https-availability" in result.output and "sql-error-indicator" in result.output


def test_scan_requires_authorization(mock_scanner):
    result = runner.invoke(cli.app, ["scan", "https://shop.example.com"])
    assert result.exit_code == cli.ExitCode.USAGE
    assert "Authorization required" in result.output
    assert mock_scanner.requests == []


def test_scan_refuses_private_target():
    result = runner.invoke(cli.app, ["scan", "http://192.168.0.1", "--authorized"])
    assert result.exit_code == cli.ExitCode.USAGE and "Target refused" in result.output


def test_scan_text_output(mock_scanner):
    result = runner.invoke(cli.app, ["scan", "shop.example.com", "--authorized"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    assert "WHITE report - shop.example.com" in result.output
    assert "does not guarantee" in result.output


def test_scan_json_and_pdf_files(mock_scanner, tmp_path):
    out = tmp_path / "report.json"
    result = runner.invoke(
        cli.app, ["scan", "https://shop.example.com", "--authorized", "-f", "json", "-o", str(out), "-q"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["target_url"] == "https://shop.example.com/"
    # overwrite protection
    again = runner.invoke(
        cli.app, ["scan", "https://shop.example.com", "--authorized", "-f", "json", "-o", str(out), "-q"]
    )
    assert again.exit_code == cli.ExitCode.OUTPUT and "already exists" in again.output
    pdf = tmp_path / "report.pdf"
    result = runner.invoke(cli.app, ["report", str(out), "-f", "pdf", "-o", str(pdf)])
    assert result.exit_code == 0 and pdf.read_bytes().startswith(b"%PDF")
    html = tmp_path / "report.html"
    assert runner.invoke(cli.app, ["report", str(out), "-f", "html", "-o", str(html)]).exit_code == 0
    shown = runner.invoke(cli.app, ["report", str(out)], env={"COLUMNS": "200"})
    assert shown.exit_code == 0 and "shop.example.com" in shown.output


def test_pdf_requires_output(mock_scanner):
    result = runner.invoke(cli.app, ["scan", "https://shop.example.com", "--authorized", "-f", "pdf"])
    assert result.exit_code == cli.ExitCode.USAGE


def test_json_to_stdout(mock_scanner):
    result = runner.invoke(cli.app, ["scan", "https://shop.example.com", "--authorized", "-f", "json", "-q"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["tool"] == "WHITE"


def test_fail_on_threshold(monkeypatch):
    site = MockSite(
        {
            "https://shop.example.com/": (200, {"content-type": "text/html"}, "<html></html>"),
            "http://shop.example.com/": (301, {"location": "https://shop.example.com/"}, b""),
        }
    )
    monkeypatch.setattr(
        cli,
        "Scanner",
        lambda c, **k: Scanner(c.model_copy(update={"min_request_interval": 0}), transport=site.transport),
    )
    result = runner.invoke(
        cli.app, ["scan", "https://shop.example.com", "--authorized", "-q", "--fail-on", "medium"]
    )
    assert result.exit_code == cli.ExitCode.FINDINGS


def test_unreachable_exit_code(monkeypatch):
    import httpx

    site = MockSite()
    site.errors["https://down.example.com/"] = httpx.ConnectError("refused")
    site.errors["http://down.example.com/"] = httpx.ConnectError("refused")
    monkeypatch.setattr(
        cli,
        "Scanner",
        lambda c, **k: Scanner(c.model_copy(update={"min_request_interval": 0}), transport=site.transport),
    )
    result = runner.invoke(cli.app, ["scan", "https://down.example.com", "--authorized", "-q"])
    assert result.exit_code == cli.ExitCode.SCAN_FAILED


def test_report_rejects_bad_file(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("{}", encoding="utf-8")
    assert runner.invoke(cli.app, ["report", str(bad)]).exit_code == cli.ExitCode.OUTPUT
    assert runner.invoke(cli.app, ["report", str(tmp_path / "missing.json")]).exit_code == cli.ExitCode.OUTPUT


def test_output_into_missing_folder_fails_cleanly(mock_scanner, tmp_path):
    result = runner.invoke(
        cli.app,
        [
            "scan",
            "https://shop.example.com",
            "--authorized",
            "-f",
            "json",
            "-o",
            str(tmp_path / "nope" / "r.json"),
            "-q",
        ],
    )
    assert result.exit_code == cli.ExitCode.OUTPUT


def test_config_masks_secrets(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://abc.supabase.co")
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", "sb_publishable_ABCDEFGHIJKLMNOPQRSTUV")
    monkeypatch.setenv("WHITE_SECRET_KEY", "my-very-secret-value")
    result = runner.invoke(cli.app, ["config"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert "my-very-secret-value" not in result.output
    assert "ABCDEFGHIJKLMNOPQRSTUV" not in result.output


def test_doctor_runs(monkeypatch, tmp_path):
    monkeypatch.setenv("WHITE_DATA_DIR", str(tmp_path / "d"))
    result = runner.invoke(cli.app, ["doctor"], env={"COLUMNS": "200"})
    assert "Configuration is valid" in result.output
    assert result.exit_code == 0
