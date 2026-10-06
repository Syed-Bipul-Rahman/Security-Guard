"""install.sh must ship every module the watcher imports at startup.

The source installer copies APP_FILES into $GUARD_HOME/app and the service runs
`watcher.py` from that directory alone. A missing import crash-loops the service
(Restart=always / KeepAlive) before it scans anything.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

from conftest import ROOT


def app_files() -> list[str]:
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    match = re.search(r'^APP_FILES="([^"]+)"', text, re.M)
    assert match, "install.sh has no APP_FILES list"
    return match.group(1).split()


def test_app_files_exist():
    missing = [name for name in app_files() if not (ROOT / name).is_file()]
    assert missing == []


def test_installed_app_can_import_watcher(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    for name in app_files():
        shutil.copy(ROOT / name, app / name)

    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Import from the installed copy only — cwd and PYTHONPATH must not leak the repo.
    proc = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); import watcher",
         str(app)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
