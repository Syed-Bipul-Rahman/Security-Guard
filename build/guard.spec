# PyInstaller spec: build the single `guard` binary.
# Build per-OS (PyInstaller does not cross-compile):
#     pip install pyinstaller
#     pyinstaller build/guard.spec --distpath build/dist --workpath build/work
# Produces one self-contained executable: build/dist/guard  (guard.exe on Windows)
#
# guard.py loads the other modules/scripts from the bundle at runtime (resource_path),
# so they are shipped as `datas`. hiddenimports lists the stdlib those bundled
# scripts pull in dynamically, so PyInstaller includes them.

import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent   # security-guard/

datas = [
    # python modules the entrypoint runs via resource_path
    (str(ROOT / "scanner.py"), "."),
    (str(ROOT / "watcher.py"), "."),
    (str(ROOT / "magic_bytes.py"), "."),
    (str(ROOT / "vscode_guard.py"), "."),
    (str(ROOT / "fingerprint_matcher.py"), "."),
    (str(ROOT / "workflow_baseline.py"), "."),
    (str(ROOT / "snapshot_store.py"), "."),
    (str(ROOT / "memguard.py"), "."),
    (str(ROOT / "dep_blocklist.py"), "."),
    # signatures + config
    (str(ROOT / "signatures.json"), "."),
    (str(ROOT / "signatures.yaml"), "."),
    # installers / hooks / OS-native IR
    (str(ROOT / "install.sh"), "."),
    (str(ROOT / "hooks" / "guard-scan-hook.sh"), "hooks"),
    (str(ROOT / "linux" / "guard-triage-linux.sh"), "linux"),
    (str(ROOT / "windows" / "guard-triage.ps1"), "windows"),
    (str(ROOT / "windows" / "reboot-forensics.ps1"), "windows"),
    (str(ROOT / "windows" / "reboot-cause.ps1"), "windows"),
    (str(ROOT / "windows" / "temp-registry-forensics.ps1"), "windows"),
    (str(ROOT / "windows" / "windows_sensor.py"), "windows"),
    (str(ROOT / "windows" / "sysmon-config.xml"), "windows"),
    # malware feed
    (str(ROOT / "malware-feed" / "collect_malware_advisories.py"), "malware-feed"),
    (str(ROOT / "malware-feed" / "check_deps.py"), "malware-feed"),
]
# optional: bundle a blocklist snapshot so `guard deps check` works before first `deps update`
_bl = ROOT / "malware-feed" / "malware-blocklist.json"
if _bl.exists():
    datas.append((str(_bl), "malware-feed"))

hiddenimports = [
    "argparse", "json", "csv", "re", "hashlib", "sqlite3", "subprocess", "signal",
    "pathlib", "dataclasses", "datetime", "binascii", "gc", "ntpath", "stat",
    "tempfile", "runpy", "shutil", "urllib", "urllib.request", "urllib.error",
    "urllib.parse", "xml", "xml.etree", "xml.etree.ElementTree",
    "ssl", "certifi",   # certifi provides the CA bundle so HTTPS works in the frozen binary
]
if sys.platform != "win32":
    hiddenimports.append("resource")

a = Analysis(
    [str(ROOT / "guard.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[], runtime_hooks=[], excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
# Everything in EXE + no COLLECT step == one self-contained file.
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="guard",
    console=True,
    strip=False, upx=True,
)
