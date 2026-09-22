#!/usr/bin/env python3
"""
permissions.py - macOS access check + interactive "just click Allow" request.

Guard can only detect what it can READ. On macOS the OS (TCC) blocks access to a
user's Desktop / Documents / Downloads folders and to removable/external volumes
unless the user has allowed it. A background root daemon gets NO dialog and simply
fails silently - which is how a malicious repo on the Desktop went unseen. This
module makes the access explicit:

  * check()   - reports, per protected location, whether Guard can read it.
  * request() - touches each blocked location so macOS shows its native
                "Guard would like to access ..." dialog. The user clicks
                Allow. This ONLY works from the logged-in user's GUI session
                (a LaunchAgent) - a system-context root LaunchDaemon never
                receives the prompt.

Coverage the "Allow" prompt gives you: Desktop, Documents, Downloads (internal
disk) and Removable Volumes. Full Disk Access - the single grant that covers
*every* internal + external disk at once - is the ONE macOS permission with no
"Allow" prompt; Apple only lets the user add it by hand in System Settings.
request() opens that exact pane as a fallback when a location is still blocked
(the user clicked Don't Allow, or Guard is running headless).

Persistence note: the grant is keyed on the guard BINARY's code identity. If the
binary is unsigned, every OTA self-update changes that identity and the user
must click Allow again. Sign guard with a stable Developer ID so the grant sticks.

Non-macOS: Linux/Windows have no TCC, so every location is "readable" and these
functions are safe no-ops.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Exact System Settings pane for Full Disk Access (works on macOS 13+ System
# Settings and older System Preferences).
FDA_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"


def _user_home() -> Path:
    """The human user's home, even when invoked via sudo (so a root installer
    still probes /Users/<user>, not /var/root)."""
    u = os.environ.get("SUDO_USER")
    if u and u != "root":
        try:
            import pwd
            return Path(pwd.getpwnam(u).pw_dir)
        except Exception:
            pass
    return Path.home()


def internal_targets() -> list[Path]:
    """TCC-protected folders on the internal disk that Guard watches."""
    h = _user_home()
    return [h / "Desktop", h / "Documents", h / "Downloads"]


def removable_targets() -> list[Path]:
    """Mounted volumes under /Volumes, excluding the boot volume symlink."""
    out: list[Path] = []
    try:
        for v in Path("/Volumes").iterdir():
            try:
                if v.is_symlink() or v.resolve() == Path("/"):
                    continue  # /Volumes/Macintosh HD -> /
            except OSError:
                pass
            out.append(v)
    except OSError:
        pass
    return out


def _can_read(p: Path) -> bool:
    """Try to read one entry of a directory. In a GUI session this call BLOCKS on
    the native TCC dialog the first time and returns the user's answer; denied ->
    PermissionError. A non-existent path is not a permission problem."""
    try:
        with os.scandir(p) as it:
            for _ in it:
                break
        return True
    except PermissionError:
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


def check(targets: list[Path] | None = None) -> dict:
    """Report readability per protected location. On non-macOS, always ok."""
    if sys.platform != "darwin":
        return {"ok": True, "blocked": [], "readable": [], "checked": []}
    tg = targets if targets is not None else (internal_targets() + removable_targets())
    tg = [p for p in tg if p.exists()]
    blocked, readable = [], []
    for p in tg:
        (readable if _can_read(p) else blocked).append(str(p))
    return {"ok": not blocked, "blocked": blocked, "readable": readable,
            "checked": [str(p) for p in tg]}


def open_fda_settings(log=print) -> None:
    """Open the Full Disk Access pane so the user can add guard for full internal +
    removable coverage (the one grant with no Allow prompt)."""
    try:
        subprocess.Popen(["open", FDA_SETTINGS_URL])
        log("guard: opened System Settings -> Privacy & Security -> Full Disk Access. "
            "Add and enable 'guard' to allow scanning all internal and removable disks.")
    except Exception as e:
        log(f"guard: could not open settings ({e}); enable Full Disk Access for 'guard' manually.")


def request(open_settings_if_blocked: bool = True, log=print) -> dict:
    """Raise the native Allow prompts for every blocked location, then re-check.
    Must run in the user's GUI session (LaunchAgent) for the dialogs to appear."""
    if sys.platform != "darwin":
        return {"ok": True, "prompted": [], "still_blocked": []}
    targets = [p for p in (internal_targets() + removable_targets()) if p.exists()]
    prompted: list[str] = []
    for p in targets:
        # This access triggers macOS's "guard would like to access ..." dialog and
        # blocks until the user answers (Allow -> readable, Don't Allow -> stays
        # blocked). TCC only prompts once per location; after that it just answers.
        if not _can_read(p):
            prompted.append(str(p))
    res = check(targets)
    still = res["blocked"]
    if still:
        log(f"guard: still blocked after prompt: {still}")
        if open_settings_if_blocked:
            open_fda_settings(log)
    else:
        log("guard: all watched locations are now readable.")
    return {"ok": not still, "prompted": prompted, "still_blocked": still}


def has_full_disk_access() -> bool:
    """FDA lets a process read the protected TCC database; use that as the probe."""
    if sys.platform != "darwin":
        return True
    try:
        with open("/Library/Application Support/com.apple.TCC/TCC.db", "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    action = (argv[0] if argv else "check").lower()

    if action in ("request", "ask", "fix", "allow"):
        r = request()
        print(json.dumps(r, indent=2))
        return 0 if r["ok"] else 1
    if action in ("open-settings", "settings", "fda"):
        open_fda_settings()
        return 0

    # default: check + report
    r = check()
    print(json.dumps(r, indent=2))
    if sys.platform == "darwin":
        print(f"full_disk_access: {'yes' if has_full_disk_access() else 'no'}")
        if r["blocked"]:
            print("hint: run 'guard permissions request' in your login session to get the Allow prompts.")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
