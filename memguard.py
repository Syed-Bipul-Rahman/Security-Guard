#!/usr/bin/env python3
"""
memguard.py — keep the watcher under a memory budget (default 10% of system RAM).

Pure stdlib. Two jobs:
  1. Compute the budget from total physical RAM.
  2. Report current RSS and let callers throttle (pause + gc) when near the budget.

Also can install a hard ceiling via resource.setrlimit(RLIMIT_AS) as a backstop,
so a runaway allocation gets a MemoryError instead of eating the machine. The
soft check is preferred (a hard AS limit can crash the interpreter on macOS), so
the ceiling is opt-in.

RSS sources (no psutil dependency):
  * Linux : /proc/self/statm  (current RSS in pages)  — accurate, current
  * macOS : resource.getrusage(...).ru_maxrss (bytes) — PEAK, used as a proxy
  * other : ru_maxrss with kb/bytes autodetect
"""

from __future__ import annotations

import gc
import os
import sys
import time

try:
    import resource  # Unix-only; absent on Windows (that's fine — see below)
except ImportError:
    resource = None  # type: ignore


def _win_total_ram() -> int:
    import ctypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return int(stat.ullTotalPhys)


def _win_rss() -> int:
    import ctypes
    from ctypes import wintypes

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    h = ctypes.windll.kernel32.GetCurrentProcess()
    if ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb):
        return int(counters.WorkingSetSize)
    return 0


def total_ram_bytes() -> int:
    if sys.platform.startswith("win"):
        try:
            return _win_total_ram()
        except Exception:
            return 4 * 1024**3
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        # Fallback: assume 4 GiB so the budget is still finite.
        return 4 * 1024**3


def _ru_maxrss_bytes() -> int:
    """ru_maxrss is kilobytes on Linux, bytes on macOS/BSD. Autodetect."""
    if resource is None:
        return 0
    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(ru)          # already bytes
    return int(ru) * 1024       # Linux: kB -> bytes


def current_rss_bytes() -> int:
    # Windows: current working set via psapi (no resource module there).
    if sys.platform.startswith("win"):
        try:
            return _win_rss()
        except Exception:
            return 0
    # Linux: read current (not peak) RSS from /proc.
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/statm", "r") as fh:
                fields = fh.read().split()
            rss_pages = int(fields[1])
            return rss_pages * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, IndexError):
            pass
    return _ru_maxrss_bytes()


class MemoryGuard:
    def __init__(self, fraction: float = 0.10, min_bytes: int = 64 * 1024**2,
                 throttle_sleep: float = 0.25, log=print) -> None:
        self.fraction = fraction
        self.total = total_ram_bytes()
        # Budget is fraction of RAM, but never below a small floor so tiny hosts
        # (or containers with odd sysconf values) don't get an unusable budget.
        self.budget = max(int(self.total * fraction), min_bytes)
        self.throttle_sleep = throttle_sleep
        self.log = log
        self._throttles = 0

    def rss(self) -> int:
        return current_rss_bytes()

    def over_budget(self) -> bool:
        return self.rss() > self.budget

    def near_budget(self, headroom: float = 0.85) -> bool:
        return self.rss() > self.budget * headroom

    def check_and_throttle(self) -> bool:
        """If near budget, force a gc and briefly pause. Returns True if throttled."""
        if self.near_budget():
            gc.collect()
            if self.over_budget():
                self._throttles += 1
                if self._throttles <= 3 or self._throttles % 50 == 0:
                    self.log(f"memguard: RSS {self.rss()//1024//1024}MB > budget "
                             f"{self.budget//1024//1024}MB — throttling (#{self._throttles})")
                time.sleep(self.throttle_sleep)
                return True
        return False

    def install_hard_ceiling(self, multiple: float = 1.5) -> bool:
        """Optional backstop: cap address space at multiple*budget. Opt-in.
        No-op on Windows (no resource module / RLIMIT_AS)."""
        if resource is None:
            return False
        try:
            cap = int(self.budget * multiple)
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            new_hard = cap if hard == resource.RLIM_INFINITY else min(cap, hard)
            resource.setrlimit(resource.RLIMIT_AS, (cap, new_hard))
            return True
        except (ValueError, OSError, resource.error):
            return False

    def summary(self) -> str:
        return (f"total={self.total//1024//1024}MB budget={self.budget//1024//1024}MB "
                f"({self.fraction*100:.0f}%) rss={self.rss()//1024//1024}MB")


if __name__ == "__main__":
    g = MemoryGuard()
    print(g.summary())
