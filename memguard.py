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
import resource
import sys
import time


def total_ram_bytes() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        # Fallback: assume 4 GiB so the budget is still finite.
        return 4 * 1024**3


def _ru_maxrss_bytes() -> int:
    """ru_maxrss is kilobytes on Linux, bytes on macOS/BSD. Autodetect."""
    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(ru)          # already bytes
    return int(ru) * 1024       # Linux: kB -> bytes


def current_rss_bytes() -> int:
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
        """Optional backstop: cap address space at multiple*budget. Opt-in."""
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
