#!/usr/bin/env python3
"""
snapshot_store.py — disk-backed path snapshot (SQLite) for the watcher.

Replaces the old in-RAM {path: mtime} dict, which grew O(number of files) and was
persisted as one big JSON blob. With SQLite, the snapshot lives on disk and we
only ever hold one BATCH of rows in memory at a time, so memory stays flat no
matter how many files are watched.

Design:
  table paths(path PRIMARY KEY, mtime REAL, gen INTEGER)
  * each poll pass uses a new generation number (monotonic).
  * upsert_batch() writes rows and reports which paths are new/changed.
  * sweep_deleted() removes rows not seen in the latest generation.

WAL mode + a single writer keeps it fast and crash-safe across restarts.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


class SnapshotStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS paths ("
            " path TEXT PRIMARY KEY, mtime REAL NOT NULL, gen INTEGER NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER)"
        )
        self.conn.commit()

    # ---------------------------------------------------------------- meta
    def next_generation(self) -> int:
        cur = self.conn.execute("SELECT v FROM meta WHERE k='gen'")
        row = cur.fetchone()
        gen = (row[0] if row else 0) + 1
        self.conn.execute(
            "INSERT INTO meta(k,v) VALUES('gen',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (gen,))
        self.conn.commit()
        return gen

    def is_empty(self) -> bool:
        cur = self.conn.execute("SELECT 1 FROM paths LIMIT 1")
        return cur.fetchone() is None

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM paths").fetchone()[0]

    # ---------------------------------------------------------------- batch
    def upsert_batch(self, batch: list[tuple[str, float]], gen: int) -> list[tuple[str, str]]:
        """Insert/update a batch of (path, mtime). Returns [(path, status)] where
        status is 'new' or 'changed' (unchanged paths are not returned).

        Memory: holds only this batch + the matching existing rows for it.
        """
        if not batch:
            return []
        paths = [p for p, _ in batch]
        # Fetch existing mtimes for just this batch (chunked IN query).
        existing: dict[str, float] = {}
        CHUNK = 500
        for i in range(0, len(paths), CHUNK):
            chunk = paths[i:i + CHUNK]
            q = "SELECT path, mtime FROM paths WHERE path IN (%s)" % ",".join("?" * len(chunk))
            for row in self.conn.execute(q, chunk):
                existing[row[0]] = row[1]

        changes: list[tuple[str, str]] = []
        rows = []
        for path, mtime in batch:
            prev = existing.get(path)
            if prev is None:
                changes.append((path, "new"))
            elif mtime > prev:
                changes.append((path, "changed"))
            rows.append((path, mtime, gen))

        self.conn.executemany(
            "INSERT INTO paths(path,mtime,gen) VALUES(?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime, gen=excluded.gen",
            rows,
        )
        self.conn.commit()
        existing.clear()
        return changes

    def touch_batch(self, batch: list[tuple[str, float]], gen: int) -> None:
        """Prime mode: record rows WITHOUT computing/returning changes (first run)."""
        rows = [(p, m, gen) for p, m in batch]
        self.conn.executemany(
            "INSERT INTO paths(path,mtime,gen) VALUES(?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime, gen=excluded.gen",
            rows,
        )
        self.conn.commit()

    def sweep_deleted(self, gen: int) -> int:
        """Remove rows not seen in the latest generation (files deleted)."""
        cur = self.conn.execute("DELETE FROM paths WHERE gen < ?", (gen,))
        self.conn.commit()
        return cur.rowcount

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass
