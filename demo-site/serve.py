"""Serve the VELOUR demo storefront on your own computer.

Two ways to run it:

* Single site (switch workflow):
      python serve.py
  Serves on http://127.0.0.1:8443/ using whichever configuration switch.py last applied
  (active-config.json). Change it with `python switch.py weak|hardened` and restart.

* Side by side (show both at once):
      python serve.py weak 8443        # vulnerable version
      python serve.py hardened 8444    # fixed version
  Run those in two terminals to compare the two configurations live, no switching needed.

It listens only on 127.0.0.1, so nothing is exposed to your network. Everything it serves is static
and harmless; the "weak" differences are real misconfigurations (not exploitable code) that the
WHITE scanner detects.
"""

from __future__ import annotations

import json
import mimetypes
import re
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
PUBLIC = HERE / "public"
EXTRAS = HERE / "weak-extras"
CONFIGS = HERE / "configs"
DEFAULT_PORT = 8443
HOST = "127.0.0.1"

# Well-known sensitive paths WHITE probes, served only when the config enables expose_files.
EXPOSED = {
    "/.env": ("text/plain; charset=utf-8", "dotenv"),
    "/.git/HEAD": ("text/plain; charset=utf-8", "git-head"),
    "/.DS_Store": ("application/octet-stream", "ds_store"),
    "/server-status": ("text/html; charset=utf-8", "server-status.html"),
    "/phpinfo.php": ("text/html; charset=utf-8", "phpinfo.html"),
}

DEBUG_404 = """<!doctype html><html><head><title>Application Error</title>
<style>body{{font-family:Menlo,Consolas,monospace;background:#1b1b1b;color:#eee;padding:28px}}
h1{{color:#e06c5a}}pre{{background:#111;padding:16px;border-radius:6px;overflow:auto;color:#d7d0c8}}</style>
</head><body>
<h1>RuntimeError at {path}</h1>
<p>The requested page could not be rendered. Debug mode is enabled.</p>
<pre>Traceback (most recent call last):
  File "/var/www/velour/app.py", line 142, in dispatch
    response = view(request)
  File "/var/www/velour/views/catalog.py", line 88, in render
    product = db.fetch_one(query, (slug,))
  File "/var/www/velour/db.py", line 37, in fetch_one
    cursor.execute(query, params)
RuntimeError: template '{path}' not found (DEBUG=True)</pre>
<p>Demonstration debug page &mdash; it imitates a misconfigured development server so WHITE can
detect information disclosure. No real application or database is involved.</p>
</body></html>"""

CLEAN_404 = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Page not found &mdash; VELOUR</title>
<link rel="stylesheet" href="/assets/css/store.css"></head>
<body><div class="wrap" style="text-align:center;padding:120px 20px">
<div class="brand" style="font-size:2rem">VEL<b>O</b>UR</div>
<h1 style="font-size:2.4rem;margin-top:20px">Page not found</h1>
<p class="muted">We couldn't find that page. It may have moved.</p>
<p style="margin-top:24px"><a class="btn" href="/">Back to home</a></p>
</div></body></html>"""


def compile_source(source: str) -> re.Pattern:
    # "/" matches only the root; "/(.*)" matches every path.
    pattern = "^" + re.escape(source).replace(re.escape("(.*)"), ".*") + "$"
    return re.compile(pattern)


class DemoHandler(BaseHTTPRequestHandler):
    config: dict = {}
    rules: list[tuple[re.Pattern, list]] = []
    # Files served instead of public/ for the configuration-specific pages (side-by-side mode).
    overrides: dict[str, tuple[str, Path]] = {}

    def configured_headers(self, path: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for pattern, pairs in self.rules:
            if pattern.match(path):
                out.extend((k, v) for k, v in pairs)
        return out

    def _send(self, status: int, body: bytes, content_type: str, path: str, *, head: bool = False) -> None:
        self.send_response_only(status)
        self.send_header("Server", self.config.get("server_header", "web"))
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in self.configured_headers(path):
            self.send_header(key, value)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _safe_target(self, path: str) -> Path | None:
        rel = unquote(path).lstrip("/")
        target = (PUBLIC / rel).resolve()
        try:
            target.relative_to(PUBLIC.resolve())
        except ValueError:
            return None  # path traversal attempt
        return target

    def not_found(self, path: str, head: bool) -> None:
        body = (DEBUG_404.format(path=path) if self.config.get("verbose_errors") else CLEAN_404).encode()
        self._send(HTTPStatus.NOT_FOUND, body, "text/html; charset=utf-8", path, head=head)

    def directory_listing(self, target: Path, path: str, head: bool) -> None:
        entries = sorted(p.name + ("/" if p.is_dir() else "") for p in target.iterdir())
        rows = "\n".join(f'<li><a href="{path.rstrip("/")}/{e}">{e}</a></li>' for e in entries)
        body = (
            f"<!doctype html><html><head><title>Index of {path}</title></head><body>"
            f"<h1>Index of {path}</h1><ul>{rows}</ul>"
            f"<hr><em>{self.config.get('server_header', 'web')}</em></body></html>"
        ).encode()
        self._send(HTTPStatus.OK, body, "text/html; charset=utf-8", path, head=head)

    def handle_path(self, head: bool) -> None:
        path = urlsplit(self.path).path or "/"

        if path in self.overrides:
            content_type, file = self.overrides[path]
            self._send(HTTPStatus.OK, file.read_bytes(), content_type, path, head=head)
            return

        if self.config.get("expose_files") and path in EXPOSED:
            content_type, name = EXPOSED[path]
            self._send(HTTPStatus.OK, (EXTRAS / name).read_bytes(), content_type, path, head=head)
            return

        target = self._safe_target(path)
        if target is None:
            self.not_found(path, head)
            return

        if target.is_dir():
            index = target / "index.html"
            if index.is_file():
                self._send(HTTPStatus.OK, index.read_bytes(), "text/html; charset=utf-8", path, head=head)
            elif self.config.get("directory_listing"):
                self.directory_listing(target, path if path.endswith("/") else path + "/", head)
            else:
                self.not_found(path, head)
            return

        if target.is_file():
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                ctype += "" if "charset" in ctype else "; charset=utf-8"
            self._send(HTTPStatus.OK, target.read_bytes(), ctype, path, head=head)
            return

        self.not_found(path, head)

    def do_GET(self) -> None:  # noqa: N802
        self.handle_path(head=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self.handle_path(head=True)

    def log_message(self, fmt: str, *args) -> None:
        print("  " + (fmt % args))


def parse_args(argv: list[str]) -> tuple[str | None, int]:
    mode, port = None, DEFAULT_PORT
    for token in argv:
        if token in {"weak", "hardened"}:
            mode = token
        elif token.isdigit():
            port = int(token)
        else:
            raise SystemExit(f"Unexpected argument: {token!r}\nUsage: python serve.py [weak|hardened] [port]")
    return mode, port


def build(mode: str | None) -> tuple[dict, dict[str, tuple[str, Path]]]:
    """Return (config, overrides) for a mode, or the switch-managed active config when mode is None."""
    if mode is None:
        path = HERE / "active-config.json"
        if not path.exists():
            raise SystemExit("active-config.json is missing. Run: python switch.py weak")
        return json.loads(path.read_text(encoding="utf-8")), {}
    config = json.loads((CONFIGS / f"config.{mode}.json").read_text(encoding="utf-8"))
    index = ("text/html; charset=utf-8", CONFIGS / f"index.{mode}.html")
    overrides = {
        "/": index,
        "/index.html": index,
        "/robots.txt": ("text/plain; charset=utf-8", CONFIGS / f"robots.{mode}.txt"),
        "/sitemap.xml": ("application/xml; charset=utf-8", CONFIGS / f"sitemap.{mode}.xml"),
    }
    return config, overrides


def main() -> None:
    mode, port = parse_args(sys.argv[1:])
    config, overrides = build(mode)
    DemoHandler.config = config
    DemoHandler.rules = [(compile_source(r["source"]), r.get("set", [])) for r in config.get("headers", [])]
    DemoHandler.overrides = overrides
    mimetypes.add_type("image/svg+xml", ".svg")
    mimetypes.add_type("text/javascript", ".js")
    url = f"http://{HOST}:{port}/"
    print(f"VELOUR demo store ({config.get('mode', '?')} configuration) at {url}")
    print(f"  Scan it with:  white scan {url} --authorized --allow-private-network")
    print("  Ctrl+C to stop.")
    with ThreadingHTTPServer((HOST, port), DemoHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
