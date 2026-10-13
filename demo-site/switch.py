"""Switch the demo site between its 'weak' and 'hardened' configurations.

Usage:  python switch.py weak   |   python switch.py hardened
Restart serve.py afterwards, then scan again with WHITE to see what changed.
"""

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

if len(sys.argv) != 2 or sys.argv[1] not in {"weak", "hardened"}:
    sys.exit("Usage: python switch.py weak|hardened")
mode = sys.argv[1]
shutil.copyfile(HERE / "configs" / f"headers.{mode}.json", HERE / "active-headers.json")
shutil.copyfile(HERE / "configs" / f"index.{mode}.html", HERE / "public" / "index.html")
print(f"Demo site switched to '{mode}'. Restart serve.py, then scan it again with WHITE.")
