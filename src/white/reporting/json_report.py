"""JSON report serialisation and safe loading."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from white.scanner.models import ScanReport

MAX_REPORT_BYTES = 20_000_000


class ReportLoadError(ValueError):
    pass


def to_json(report: ScanReport) -> str:
    data = report.model_dump(mode="json")
    data["findings_flat"] = [f.model_dump(mode="json") for f in report.findings]
    return json.dumps(data, indent=2, ensure_ascii=False)


def load_report_text(text: str) -> ScanReport:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportLoadError(f"Not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise ReportLoadError("The file is not a WHITE report.")
    data.pop("findings_flat", None)
    if data.get("tool") != "WHITE" or "schema_version" not in data:
        raise ReportLoadError("The file is not a WHITE report.")
    major = str(data["schema_version"]).split(".")[0]
    if major != "1":
        raise ReportLoadError(f"Unsupported report schema version {data['schema_version']}.")
    try:
        report = ScanReport.model_validate(data)
    except ValidationError as exc:
        raise ReportLoadError(f"The report failed validation: {exc.error_count()} error(s).") from exc
    report.compute_summary()
    return report


def load_report(path: Path) -> ScanReport:
    if not path.is_file():
        raise ReportLoadError(f"File not found: {path}")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ReportLoadError("The report file is too large.")
    return load_report_text(path.read_text(encoding="utf-8"))
