"""Ownership in the local repository, sessions, and output-safety helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from tests.conftest import good_site, run_scan
from white.api.routes_auth import safe_next
from white.api.routes_web import _json_for_script
from white.api.scans import download_name
from white.api.security import csrf_token_for, csrf_valid
from white.auth.sessions import SessionStore
from white.auth.supabase_auth import AuthSession
from white.database.base import ScanRecord
from white.database.sqlite import SQLiteDatabase, SQLiteScanRepository
from white.scanner.models import ScanState


def _record(owner, scan_id):
    return ScanRecord(
        id=scan_id,
        owner_id=owner,
        target_url="https://shop.example.com/",
        hostname="shop.example.com",
        state=ScanState.QUEUED,
        created_at=datetime.now(UTC),
    )


def test_sqlite_repository_scopes_everything_by_owner(tmp_path):
    repo = SQLiteScanRepository(SQLiteDatabase(tmp_path / "w.db"))
    report = run_scan(good_site())
    repo.create_scan("alice", _record("alice", report.scan_id))
    repo.save_report("alice", report.scan_id, report)
    assert repo.get_scan("bob", report.scan_id) is None
    assert repo.list_scans("bob") == [] and repo.list_reports("bob") == []
    assert repo.delete_scan("bob", report.scan_id) is False
    import pytest

    from white.database.base import RepositoryError

    with pytest.raises(RepositoryError):
        repo.save_report("bob", report.scan_id, report)
    assert repo.get_scan("alice", report.scan_id).report.scan_id == report.scan_id


def test_interrupted_scans_marked_on_startup(tmp_path):
    repo = SQLiteScanRepository(SQLiteDatabase(tmp_path / "w.db"))
    repo.create_scan("local", _record("local", "11111111-1111-1111-1111-111111111111"))
    assert repo.mark_interrupted() == 1
    assert repo.get_scan("local", "11111111-1111-1111-1111-111111111111").state == ScanState.INTERRUPTED


def test_session_tokens_encrypted_at_rest(tmp_path):
    db = SQLiteDatabase(tmp_path / "w.db")
    store = SessionStore(db, "secret-one")
    auth = AuthSession("ACCESS-TOKEN-VALUE", "REFRESH-TOKEN-VALUE", 2_000_000_000, "uid", "a@example.com")
    raw = store.create(auth)
    blob = (tmp_path / "w.db").read_bytes()
    assert b"ACCESS-TOKEN-VALUE" not in blob and raw.encode() not in blob  # only a hash of the cookie
    assert store.get(raw).access_token == "ACCESS-TOKEN-VALUE"
    assert SessionStore(db, "different-secret").get(raw) is None  # key rotation invalidates sessions
    assert store.get("forged-token") is None


def test_safe_next_blocks_open_redirects():
    assert safe_next("/history") == "/history"
    for bad in ["https://evil.example", "//evil.example", "/\\evil.example", "", None, "javascript:alert(1)"]:
        assert safe_next(bad) == "/dashboard"


def test_json_for_script_cannot_break_out():
    payload = _json_for_script({"x": "</script><script>alert(1)</script>&"})
    assert "</script>" not in payload and "<" not in payload
    assert json.loads(payload)["x"].startswith("</script>")


def test_download_filename_is_sanitised():
    report = run_scan(good_site())
    report.hostname = '../../evil"; rm -rf /'
    name = download_name(report, "pdf")
    assert "/" not in name and '"' not in name and " " not in name and name.endswith(".pdf")


def test_csrf_tokens_bound_to_cookie():
    token = csrf_token_for("s", "cookie-a")
    assert csrf_valid("s", "cookie-a", token)
    assert not csrf_valid("s", "cookie-b", token)
    assert not csrf_valid("other", "cookie-a", token)
    assert not csrf_valid("s", None, token)
