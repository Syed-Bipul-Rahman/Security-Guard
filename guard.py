#!/usr/bin/env python3
"""
guard.py - the single Guard entrypoint. Everything is one command: `guard <cmd>`.

This is what gets packaged into the single binary (see build/). The other .py/.sh
files are internal modules the binary carries - you never run them directly.

Commands:
  guard scan <path>        full repo/tree scan (fingerprints, droppers, vscode, workflows, malware deps)
  guard scan-git <path>    scan working tree AND every added line across git history
  guard open <path>        pre-open check: safe to open this folder in VS Code?
  guard watch              start the always-on filesystem watcher (the service runs this)
  guard triage             host IR triage (reboots/persistence/recon/flood) - OS-native
  guard deps update        refresh the malware-package blocklist from GitHub advisories
  guard deps check <path>  check a project's dependencies against the malware blocklist
  guard install            install Guard as an auto-start service on this machine
  guard uninstall          remove the Guard service + hooks
  guard version            print version

Run `guard <cmd> -h` for command options.
"""

from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = "1.0.2"


# ---------------------------------------------------------------------------
# resource resolution: works in dev (files on disk) and in the PyInstaller binary
# ---------------------------------------------------------------------------
def resource_path(rel: str) -> Path:
    base = getattr(sys, "_MEIPASS", None)   # set inside a PyInstaller bundle
    if base:
        return Path(base) / rel
    return Path(__file__).resolve().parent / rel


def app_dir() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def _run_module(module_file: str, argv: list[str]) -> int:
    """Invoke a bundled module's main() by faking argv (reuses tested code paths)."""
    old = sys.argv
    sys.argv = [module_file] + argv
    try:
        # ensure app dir is importable (for cross-module imports like scanner->dep_blocklist)
        ad = str(app_dir())
        if ad not in sys.path:
            sys.path.insert(0, ad)
        g = runpy.run_path(str(resource_path(module_file)), run_name="__main__")
        return 0
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else (0 if e.code in (None, "") else 1)
    finally:
        sys.argv = old


# ---------------------------------------------------------------------------
# triage: extract the OS-native IR script from the bundle and run it
# ---------------------------------------------------------------------------
def cmd_triage(args: list[str]) -> int:
    plat = sys.platform
    if plat.startswith("linux") or plat == "darwin":
        script = resource_path("linux/guard-triage-linux.sh")
        if not script.exists():
            print("triage script not bundled", file=sys.stderr); return 2
        # copy out so it's executable even from a read-only bundle
        tmp = Path(tempfile.mkdtemp(prefix="guard_")) / "triage.sh"
        tmp.write_bytes(script.read_bytes())
        tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC)
        return subprocess.call(["bash", str(tmp)] + args)
    if plat.startswith("win"):
        print("On Windows, host triage uses the Sysmon-based sensor + IR scripts.")
        print("Run:  guard-triage.ps1 / reboot-forensics.ps1 (bundled under windows/),")
        print("and install Sysmon with windows/sysmon-config.xml. See windows/README-windows-sensor.md.")
        return 0
    print(f"unsupported platform for triage: {plat}", file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# deps: malware blocklist update + dependency check
# ---------------------------------------------------------------------------
def cmd_deps(args: list[str]) -> int:
    if not args or args[0] in ("-h", "--help"):
        print("usage: guard deps {update|check} ...")
        return 0
    sub, rest = args[0], args[1:]
    home = Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))
    feed = home / "feed"
    feed.mkdir(parents=True, exist_ok=True)
    if sub == "update":
        # write blocklist into GUARD_HOME/feed so the binary needn't embed it
        return _run_module("malware-feed/collect_malware_advisories.py",
                           ["--out", str(feed), "--resume"] + rest)
    if sub == "check":
        bl = feed / "malware-blocklist.json"
        # fall back to a bundled snapshot if the user hasn't run `deps update` yet
        if not bl.exists():
            bundled = resource_path("malware-feed/malware-blocklist.json")
            bl = bundled if bundled.exists() else bl
        target = rest[0] if rest and not rest[0].startswith("-") else "."
        return _run_module("malware-feed/check_deps.py", [target, "--blocklist", str(bl)])
    print(f"unknown deps subcommand: {sub}", file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# install / uninstall: reuse the bundled installer for this OS
# ---------------------------------------------------------------------------
def _write_install_stamp() -> None:
    """Record who installed Guard + when (attribution/scoping for IR, not blame)."""
    import getpass
    home = Path(os.environ.get("GUARD_HOME", "/var/lib/guard"))
    try:
        home.mkdir(parents=True, exist_ok=True)
        who = os.environ.get("SUDO_USER") or _safe_user(getpass.getuser)
        from datetime import datetime, timezone
        (home / "install.json").write_text(json.dumps({
            "installed_by": who,
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "version": VERSION,
        }, indent=2), encoding="utf-8")
    except OSError:
        pass


def _safe_user(fn):
    try:
        return fn()
    except Exception:
        return None


def _write_watch_config() -> None:
    """When installed via sudo, the daemon runs as root — point its watch roots at
    the REAL user's home so it sees the developer's projects, not root's empty dirs."""
    user = os.environ.get("SUDO_USER")
    if not user or user == "root":
        return  # not a sudo install; watcher defaults are fine
    home = Path(os.environ.get("GUARD_HOME", "/var/lib/guard"))
    cfg_path = home / "watcher.config.json"
    if cfg_path.exists():
        return  # don't clobber an existing/tuned config
    try:
        import pwd
        userhome = pwd.getpwnam(user).pw_dir
    except Exception:
        userhome = f"/Users/{user}" if sys.platform == "darwin" else f"/home/{user}"
    roots = [f"{userhome}/{d}" for d in ("Projects", "code", "src", "Desktop", "Downloads", "Documents")]
    try:
        home.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps({"watch_roots": roots}, indent=2), encoding="utf-8")
    except OSError:
        pass


def _self_exe() -> str:
    """Path used to launch this agent in a service unit."""
    if getattr(sys, "frozen", False):
        return sys.executable                      # the installed `guard` binary
    return f"{sys.executable} {Path(__file__).resolve()}"   # dev fallback


LAUNCHD_LABEL = "me.syedbipul.guard"
LAUNCHD_PLIST = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
SYSTEMD_UNIT = "/etc/systemd/system/guard.service"


def _install_macos(uninstall: bool) -> int:
    if uninstall:
        subprocess.call(["launchctl", "bootout", "system", LAUNCHD_PLIST])
        try: os.remove(LAUNCHD_PLIST)
        except OSError: pass
        print("guard: launchd daemon removed"); return 0
    home = os.environ.get("GUARD_HOME", "/var/lib/guard")
    Path(home).mkdir(parents=True, exist_ok=True)
    exe = _self_exe()
    plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array>{"".join(f"<string>{a}</string>" for a in exe.split())}<string>watch</string></array>
  <key>EnvironmentVariables</key><dict><key>GUARD_HOME</key><string>{home}</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{home}/watcher.out.log</string>
  <key>StandardErrorPath</key><string>{home}/watcher.err.log</string>
</dict></plist>'''
    try:
        Path(LAUNCHD_PLIST).write_text(plist)
    except PermissionError:
        print("guard install needs root (run with sudo)", file=sys.stderr); return 1
    subprocess.call(["launchctl", "bootout", "system", LAUNCHD_PLIST])  # ignore if not loaded
    rc = subprocess.call(["launchctl", "bootstrap", "system", LAUNCHD_PLIST])
    print(f"guard: launchd daemon installed ({LAUNCHD_PLIST}); runs '{exe} watch' at boot")
    return 0 if rc == 0 else rc


def _install_linux(uninstall: bool) -> int:
    if uninstall:
        subprocess.call(["systemctl", "disable", "--now", "guard.service"])
        try: os.remove(SYSTEMD_UNIT)
        except OSError: pass
        subprocess.call(["systemctl", "daemon-reload"])
        print("guard: systemd service removed"); return 0
    home = os.environ.get("GUARD_HOME", "/var/lib/guard")
    Path(home).mkdir(parents=True, exist_ok=True)
    exe = _self_exe()
    unit = f'''[Unit]
Description=Guard supply-chain watcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=GUARD_HOME={home}
ExecStart={exe} watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
'''
    try:
        Path(SYSTEMD_UNIT).write_text(unit)
    except PermissionError:
        print("guard install needs root (run with sudo)", file=sys.stderr); return 1
    subprocess.call(["systemctl", "daemon-reload"])
    rc = subprocess.call(["systemctl", "enable", "--now", "guard.service"])
    print(f"guard: systemd service installed ({SYSTEMD_UNIT}); runs '{exe} watch' at boot")
    return 0 if rc == 0 else rc


def cmd_install(uninstall: bool) -> int:
    plat = sys.platform
    if not uninstall:
        _write_install_stamp()
        _write_watch_config()
    if plat == "darwin":
        return _install_macos(uninstall)
    if plat.startswith("linux"):
        return _install_linux(uninstall)
    if plat.startswith("win"):
        print("Windows: install via guard.ps1 (it registers the GuardWatcher scheduled task).")
        return 0
    print(f"unsupported platform: {plat}", file=sys.stderr); return 2


USAGE = __doc__


def _harden_ssl() -> None:
    """Point HTTPS at a real CA bundle. A PyInstaller binary has no system certs,
    so urllib fails with CERTIFICATE_VERIFY_FAILED (breaks OTA/telemetry). certifi
    (bundled at build time) provides the trust store."""
    try:
        import ssl
        import certifi
        os.environ.setdefault("SSL_CERT_FILE", certifi.where())
        ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    _harden_ssl()
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE); return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "version":
        print(f"guard {VERSION}"); return 0
    if cmd == "scan":
        return _run_module("scanner.py", ["scan-tree"] + (rest or ["."]))
    if cmd == "scan-git":
        return _run_module("scanner.py", ["scan-git"] + (rest or ["."]))
    if cmd == "open":
        return _run_module("scanner.py", ["guard-open"] + (rest or ["."]))
    if cmd == "watch":
        return _run_module("watcher.py", rest)
    if cmd == "triage":
        return cmd_triage(rest)
    if cmd == "deps":
        return cmd_deps(rest)
    if cmd == "telemetry":
        try:
            from telemetry import run_once
            print(run_once())
            return 0
        except Exception as e:
            print(f"telemetry failed: {e}", file=sys.stderr)
            return 1
    if cmd == "update":
        # manual OTA check (the service also does this periodically)
        try:
            from updater import Updater
            res = Updater(current_version=VERSION).check_and_apply()
            print(res)
            return 0
        except Exception as e:
            print(f"update failed: {e}", file=sys.stderr)
            return 1
    if cmd == "install":
        return cmd_install(uninstall=False)
    if cmd == "uninstall":
        return cmd_install(uninstall=True)

    print(f"unknown command: {cmd}\n", file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
