"""Data for the operator admin console: registered users and everyone's scans.

Two sources, chosen automatically:

* **Supabase + service key** (``admin_cross_user``): lists every registered user (Auth admin API)
  and every scan (PostgREST with the service role, bypassing row-level security). This is the only
  way to see other users' emails, so it needs the privileged service key. That key is read from the
  environment, used only here, server-side, and never sent to the browser.
* **Local fallback**: when no service key is configured, shows the scans stored in the local
  database. Registered-user data is not available in this mode.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from white.api.deps import Services

log = logging.getLogger("white.admin")

SCAN_COLUMNS = "id,user_id,target_url,hostname,state,created_at,finished_at,findings_total,high_priority"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class AdminData:
    def __init__(self, svc: Services) -> None:
        self.svc = svc
        self.settings = svc.settings

    # -- Supabase (privileged) ---------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        key = self.settings.supabase_service_key or ""
        return {"apikey": key, "Authorization": f"Bearer {key}", "Accept": "application/json"}

    def _get(self, path: str, params: dict | None = None) -> Any:
        url = f"{self.settings.supabase_url}/{path}"
        timeout = httpx.Timeout(30.0, connect=10.0)
        with httpx.Client(timeout=timeout, transport=self.svc.supabase_transport, trust_env=False) as client:
            response = client.get(url, params=params, headers=self._headers())
        if response.status_code >= 400:
            raise RuntimeError(f"Supabase admin request failed (HTTP {response.status_code}).")
        return response.json()

    def _supabase_users(self) -> list[dict]:
        data = self._get("auth/v1/admin/users", {"per_page": "200"})
        rows = data.get("users", data) if isinstance(data, dict) else data
        users = []
        for u in rows or []:
            users.append(
                {
                    "id": u.get("id"),
                    "email": u.get("email") or "(no email)",
                    "created_at": _parse_dt(u.get("created_at")),
                    "last_sign_in_at": _parse_dt(u.get("last_sign_in_at")),
                    "confirmed": bool(u.get("email_confirmed_at") or u.get("confirmed_at")),
                }
            )
        return users

    def _supabase_scans(self) -> list[dict]:
        rows = self._get(
            "rest/v1/scans",
            {"select": SCAN_COLUMNS, "order": "created_at.desc", "limit": "500"},
        )
        return [self._scan_row(r) for r in rows or []]

    @staticmethod
    def _scan_row(r: dict) -> dict:
        return {
            "id": r.get("id"),
            "user_id": r.get("user_id"),
            "target_url": r.get("target_url"),
            "hostname": r.get("hostname"),
            "state": r.get("state"),
            "created_at": _parse_dt(r.get("created_at")),
            "findings_total": r.get("findings_total") or 0,
            "high_priority": r.get("high_priority") or 0,
        }

    def _local_scans(self) -> list[dict]:
        from white.api.deps import LOCAL_USER_ID

        records = self.svc.local_repo.list_scans(LOCAL_USER_ID, limit=500)
        return [
            {
                "id": r.id,
                "user_id": LOCAL_USER_ID,
                "target_url": r.target_url,
                "hostname": r.hostname,
                "state": r.state.value,
                "created_at": r.created_at,
                "findings_total": r.findings_total,
                "high_priority": r.high_priority,
            }
            for r in records
        ]

    # -- Public API --------------------------------------------------------------------------
    def overview(self) -> dict:
        source = "supabase" if self.settings.admin_cross_user else "local"
        errors: list[str] = []
        users: list[dict] = []
        scans: list[dict] = []
        if source == "supabase":
            # Fetch users and scans independently, so one transient failure never hides the other.
            try:
                users = self._supabase_users()
            except (RuntimeError, httpx.HTTPError) as exc:
                log.warning("admin users fetch failed: %s", exc)
                errors.append("the user list")
            try:
                scans = self._supabase_scans()
            except (RuntimeError, httpx.HTTPError) as exc:
                log.warning("admin scans fetch failed: %s", exc)
                errors.append("the scan list")
        else:
            scans = self._local_scans()
        error = (
            "Could not load " + " and ".join(errors) + " from Supabase. Try reloading the page."
            if errors
            else None
        )

        emails = {u["id"]: u["email"] for u in users}
        for s in scans:
            s["email"] = emails.get(s["user_id"], "Local user" if source == "local" else "(unknown user)")

        now = datetime.now(UTC)
        week_ago = now - timedelta(days=7)

        def recent(items: list[dict]) -> int:
            return sum(1 for i in items if i.get("created_at") and i["created_at"] >= week_ago)

        scans_by_user: dict[str, int] = {}
        last_scan_by_user: dict[str, datetime] = {}
        for s in scans:
            uid = s["user_id"]
            scans_by_user[uid] = scans_by_user.get(uid, 0) + 1
            if s["created_at"] and (uid not in last_scan_by_user or s["created_at"] > last_scan_by_user[uid]):
                last_scan_by_user[uid] = s["created_at"]
        for u in users:
            u["scan_count"] = scans_by_user.get(u["id"], 0)
            u["last_scan"] = last_scan_by_user.get(u["id"])

        states = [
            "completed",
            "completed_with_errors",
            "running",
            "queued",
            "failed",
            "cancelled",
            "interrupted",
        ]
        state_counts = {st: sum(1 for s in scans if s["state"] == st) for st in states}

        return {
            "source": source,
            "error": error,
            "cross_user": self.settings.admin_cross_user,
            "default_password": self.settings.admin_uses_default_password,
            "metrics": {
                "users_total": len(users),
                "users_confirmed": sum(1 for u in users if u["confirmed"]),
                "users_new_7d": recent(users),
                "scans_total": len(scans),
                "scans_7d": recent(scans),
                "findings_total": sum(s["findings_total"] for s in scans),
                "high_priority_total": sum(s["high_priority"] for s in scans),
            },
            "state_counts": {k: v for k, v in state_counts.items() if v},
            "users": sorted(users, key=lambda u: u["created_at"] or now, reverse=True),
            "scans": scans[:200],
        }
