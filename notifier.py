#!/usr/bin/env python3
"""
notifier.py - pop a visual desktop alert when Guard finds a critical threat,
the way a consumer antivirus does. Dependency-free (stdlib + OS-native only, so
it survives PyInstaller packaging with no extra wheels).

Why this isn't just "show a toast":
  * Windows: the watcher runs as SYSTEM in SESSION 0, which is isolated from the
    interactive desktop — a toast/MessageBox created here is INVISIBLE to the
    logged-in user. We use WTSSendMessage (ctypes) to render a native alert box
    IN the active user session, which is the supported way for a SYSTEM service
    to reach the user. Falls back to msg.exe if that ever fails.
  * macOS: the watcher runs as a per-user LaunchAgent (already in the user's GUI
    session), so a real Notification Center banner via osascript works.
  * Linux: best-effort notify-send when a desktop/bus is present.

notify() never raises — a failed alert must never take down the watcher.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

DEFAULT_TITLE = "Guard - Threat detected"


def notify(title: str, message: str) -> bool:
    """Show a desktop alert. Returns True if a mechanism was invoked."""
    try:
        if sys.platform.startswith("win"):
            return _notify_windows(title, message)
        if sys.platform == "darwin":
            return _notify_macos(title, message)
        return _notify_linux(title, message)
    except Exception:
        return False


def _notify_macos(title: str, message: str) -> bool:
    t = title.replace('"', "'")
    m = message.replace('"', "'").replace("\n", " ")
    script = f'display notification "{m}" with title "{t}" sound name "Basso"'
    subprocess.run(["osascript", "-e", script], check=False, timeout=10)
    return True


def _notify_linux(title: str, message: str) -> bool:
    exe = shutil.which("notify-send")
    if not exe:
        return False
    subprocess.run([exe, "-u", "critical", "-a", "Guard", title, message],
                   check=False, timeout=10)
    return True


def _notify_windows(title: str, message: str) -> bool:
    """Native alert box in the ACTIVE console session, callable from SYSTEM."""
    import ctypes
    from ctypes import wintypes, byref, c_ulong

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

    kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    session_id = kernel32.WTSGetActiveConsoleSessionId()
    if session_id == 0xFFFFFFFF:      # no one logged in at the console
        return _notify_windows_msg(title, message)

    MB_ICONWARNING = 0x00000030
    MB_SETFOREGROUND = 0x00010000
    MB_TOPMOST = 0x00040000
    style = MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST

    title_w = ctypes.create_unicode_buffer(title)
    msg_w = ctypes.create_unicode_buffer(message)
    response = c_ulong(0)

    wtsapi32.WTSSendMessageW.restype = wintypes.BOOL
    ok = wtsapi32.WTSSendMessageW(
        wintypes.HANDLE(0),              # WTS_CURRENT_SERVER_HANDLE
        wintypes.DWORD(session_id),
        title_w, wintypes.DWORD(len(title) * 2),      # length in BYTES, excl. null
        msg_w, wintypes.DWORD(len(message) * 2),
        wintypes.DWORD(style),
        wintypes.DWORD(0),               # no auto-timeout
        byref(response),
        wintypes.BOOL(False),            # bWait=False: don't block the watcher
    )
    if not ok:
        return _notify_windows_msg(title, message)
    return True


def _notify_windows_msg(title: str, message: str) -> bool:
    exe = shutil.which("msg") or r"C:\Windows\System32\msg.exe"
    try:
        subprocess.run([exe, "*", f"{title}: {message}"], check=False, timeout=10)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TITLE
    m = sys.argv[2] if len(sys.argv) > 2 else "Test alert - Guard notifications are working."
    print("notified" if notify(t, m) else "notify failed / no mechanism")
