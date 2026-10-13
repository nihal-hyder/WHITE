"""Serve the WHITE demo site on your own computer (http://127.0.0.1:8443/).

It applies the response headers from active-headers.json, so it behaves like a hosted site with
that configuration. Only listens on 127.0.0.1, so nothing is exposed to your network.

Usage:  python serve.py            (Ctrl+C to stop)
"""

import json
import re
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = 8443  # one of the ports WHITE allows; 8080 is often taken on Windows


def load_config() -> dict:
    return json.loads((HERE / "active-headers.json").read_text(encoding="utf-8"))


class DemoHandler(SimpleHTTPRequestHandler):
    config: dict = {}

    def version_string(self) -> str:
        return self.config.get("server_header", "demo")

    def end_headers(self) -> None:
        path = self.path.split("?")[0]
        for rule in self.config.get("headers", []):
            source = rule["source"]
            pattern = "^" + re.escape(source).replace(re.escape("(.*)"), ".*") + "$"
            if re.match(pattern, path):
                for header in rule["headers"]:
                    self.send_header(header["key"], header["value"])
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


def main() -> None:
    DemoHandler.config = load_config()
    handler = partial(DemoHandler, directory=str(HERE / "public"))
    mode = "hardened" if DemoHandler.config.get("server_header") == "demo" else "weak"
    print(f"WHITE demo site ({mode} configuration) at http://127.0.0.1:{PORT}/  - Ctrl+C to stop")
    with ThreadingHTTPServer(("127.0.0.1", PORT), handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
