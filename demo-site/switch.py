"""Switch the VELOUR demo store between its 'weak' and 'hardened' configurations.

Usage:  python switch.py weak   |   python switch.py hardened

Then restart serve.py and scan the site again with WHITE to see the findings change.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COPIES = {
    "configs/config.{mode}.json": "active-config.json",
    "configs/index.{mode}.html": "public/index.html",
    "configs/robots.{mode}.txt": "public/robots.txt",
    "configs/sitemap.{mode}.xml": "public/sitemap.xml",
}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"weak", "hardened"}:
        sys.exit("Usage: python switch.py weak|hardened")
    mode = sys.argv[1]
    for src, dst in COPIES.items():
        shutil.copyfile(HERE / src.format(mode=mode), HERE / dst)
    print(f"Demo store switched to '{mode}'.")
    print("Restart serve.py, then scan http://127.0.0.1:8443/ with WHITE again.")


if __name__ == "__main__":
    main()
