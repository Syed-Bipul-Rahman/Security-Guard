"""The Rust `guard` binary (cli/) against the Python code it replaces.

Each update scenario publishes a channel with release/sign_manifest.py (the real
release signer), then runs updater.py in-process and the Rust binary as a
subprocess against it. Both must log the same lines, print the same result and
leave the same files behind. That is what lets an installed Python build update
itself to the Rust binary, and the Rust binary keep updating, through one channel.

The binary comes from $GUARD_RS_BIN, else cli/target/{release,debug}/guard. The
tests skip without one locally, and fail without one in CI.
"""

from __future__ import annotations

import ast
import functools
import http.server
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ed25519_pure
import updater

ROOT = Path(__file__).resolve().parent.parent
EXE = ".exe" if sys.platform.startswith("win") else ""
VERSION = re.search(r'^VERSION = "([^"]+)"', (ROOT / "guard.py").read_text(), re.M).group(1)
SEED = bytes(range(32))
PUBKEY = ed25519_pure.publickey(SEED).hex()
OTHER_KEY = ed25519_pure.publickey(bytes(range(1, 33))).hex()
OLD_BIN = b"OLD-GUARD-BINARY"
NEW_BIN = b"NEW-GUARD-BINARY"


@pytest.fixture(scope="session")
def rust_guard() -> Path:
    env = os.environ.get("GUARD_RS_BIN")
    candidates = [Path(env)] if env else [ROOT / "cli" / "target" / t / f"guard{EXE}" for t in ("release", "debug")]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    msg = f"Rust guard binary not built (looked at {', '.join(map(str, candidates))}); cargo build --manifest-path cli/Cargo.toml"
    if os.environ.get("CI"):
        pytest.fail(msg)
    pytest.skip(msg)


def run_rust(exe: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    full.update(env or {})
    return subprocess.run([str(exe), *args], capture_output=True, env=full, timeout=120)


# ---------------------------------------------------------------------------
# CLI basics
# ---------------------------------------------------------------------------
@functools.lru_cache(maxsize=None)
def binary_version(exe: Path) -> str:
    """The version the binary runs as (release builds bake GUARD_VERSION in)."""
    r = run_rust(exe, "version")
    assert r.returncode == 0
    return r.stdout.decode().strip().removeprefix("guard ")


def test_version_matches_guard_py(rust_guard):
    assert binary_version(rust_guard) == os.environ.get("GUARD_VERSION", VERSION)
    if "GUARD_VERSION" not in os.environ:  # a release build rewrites guard.py's VERSION
        cargo = re.search(r'^version = "([^"]+)"', (ROOT / "cli" / "Cargo.toml").read_text(), re.M).group(1)
        assert cargo == VERSION


def test_help_and_unknown(rust_guard):
    for args in ([], ["help"], ["-h"], ["--help"]):
        r = run_rust(rust_guard, *args)
        assert r.returncode == 0 and b"guard update" in r.stdout
    r = run_rust(rust_guard, "bogus")
    assert r.returncode == 2 and b"unknown command: bogus" in r.stderr


def test_unported_commands_say_so(rust_guard):
    r = run_rust(rust_guard, "scan", ".")
    assert r.returncode == 2 and b"not in the Rust build yet" in r.stderr


# ---------------------------------------------------------------------------
# OTA update parity
# ---------------------------------------------------------------------------
class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture
def channel(tmp_path):
    root = tmp_path / "channel"
    root.mkdir()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(_Quiet, directory=str(root)))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield root, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _signer(*args: str) -> None:
    subprocess.run([sys.executable, str(ROOT / "release" / "sign_manifest.py"), *args],
                   check=True, capture_output=True)


def publish(root: Path, base: str, *, version="9.0.0", min_version="0.0.0", plat=None,
            binary=True, blocklist=b'{"npm": ["evil-pkg"]}') -> None:
    key = root.parent / "signing.key"
    key.write_bytes(SEED)
    args = ["build-and-sign", "--version", version, "--min-version", min_version,
            "--key", str(key), "--base-url", base, "--out", str(root / "manifest.json")]
    if blocklist is not None:
        (root / "malware-blocklist.json").write_bytes(blocklist)
        args += ["--blocklist", str(root / "malware-blocklist.json")]
    if binary:
        plat = plat or updater.platform_key()
        (root / f"guard-{plat}").write_bytes(NEW_BIN)
        args += ["--binary", f"{plat}=" + str(root / f"guard-{plat}")]
    _signer(*args)


def sign_raw(root: Path, raw: bytes) -> None:
    key = root.parent / "signing.key"
    key.write_bytes(SEED)
    (root / "manifest.json").write_bytes(raw)
    _signer("sign", str(root / "manifest.json"), "--key", str(key))


class Install:
    """One installed copy: a home dir and the binary the updater replaces."""

    def __init__(self, base: Path, exe_bytes: bytes):
        self.home = base / "home"
        self.bindir = base / "bin"
        self.bindir.mkdir(parents=True)
        self.exe = self.bindir / f"guard{EXE}"
        self.exe.write_bytes(exe_bytes)
        self.exe.chmod(0o755)
        self.original = exe_bytes

    @property
    def blocklist(self) -> Path:
        return self.home / "feed" / "malware-blocklist.json"

    def state(self) -> dict:
        names = sorted(p.name for p in self.bindir.iterdir())
        return {
            "files": [n.replace(f"guard{EXE}", "guard") for n in names],
            "replaced": self.exe.read_bytes() == NEW_BIN,
            "backup_is_original": any(
                (self.bindir / n).read_bytes() == self.original
                for n in names if n in ("guard.bak", "guard.old.exe")),
            "blocklist": self.blocklist.read_bytes() if self.blocklist.exists() else None,
        }


def run_both(tmp_path, base, monkeypatch, rust_guard, pubkey=PUBKEY, readonly=False):
    current = binary_version(rust_guard)
    py = Install(tmp_path / "py", OLD_BIN)
    rs = Install(tmp_path / "rs", rust_guard.read_bytes())
    if readonly:
        for inst in (py, rs):
            inst.bindir.chmod(0o555)
    logs: list[str] = []
    with monkeypatch.context() as m:
        m.setattr(sys, "frozen", True, raising=False)
        m.setattr(sys, "executable", str(py.exe))
        py_res = updater.Updater(base_url=base, pubkey_hex=pubkey, current_version=current,
                                 guard_home=py.home, log=logs.append).check_and_apply()
    r = run_rust(rs.exe, "update", env={"GUARD_HOME": str(rs.home), "GUARD_UPDATE_URL": base,
                                        "GUARD_UPDATE_PUBKEY": pubkey})
    if readonly:
        for inst in (py, rs):
            inst.bindir.chmod(0o755)
    out = r.stdout.decode("utf-8").splitlines()
    assert r.returncode == 0, (out, r.stderr)
    rs_res = ast.literal_eval(out[-1])
    norm = lambda lines, inst: [l.replace(str(inst.bindir), "<bin>") for l in lines]  # noqa: E731
    assert norm(out[:-1], rs) == norm(logs, py)
    assert rs_res == py_res
    assert rs.state() == py.state()
    return py_res, logs, py.state()


def test_update_applies_blocklist_and_binary(channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base)
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard)
    assert res == {"status": "updated", "blocklist_updated": True, "binary_updated": True,
                   "offered_version": "9.0.0"}
    assert state["replaced"] and state["backup_is_original"]
    assert state["blocklist"] == b'{"npm": ["evil-pkg"]}'
    assert "guard.new" not in state["files"]
    assert logs[-1] == f"updater: binary updated {binary_version(rust_guard)} -> 9.0.0; restart to run it"


def test_current_blocklist_is_not_refetched(channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base, binary=False)
    py = Install(tmp_path / "py", OLD_BIN)
    rs = Install(tmp_path / "rs", rust_guard.read_bytes())
    for inst in (py, rs):
        inst.blocklist.parent.mkdir(parents=True)
        inst.blocklist.write_bytes(b'{"npm": ["evil-pkg"]}')
    res = updater.Updater(base_url=base, pubkey_hex=PUBKEY, current_version=binary_version(rust_guard),
                          guard_home=py.home, log=lambda *_: None).check_and_apply()
    r = run_rust(rs.exe, "update", env={"GUARD_HOME": str(rs.home), "GUARD_UPDATE_URL": base,
                                        "GUARD_UPDATE_PUBKEY": PUBKEY})
    assert ast.literal_eval(r.stdout.decode().splitlines()[-1]) == res
    assert res["status"] == "current" and not res["blocklist_updated"]


@pytest.mark.parametrize("case", ["tampered-manifest", "wrong-key", "no-key", "malformed-sig",
                                  "not-json", "empty-manifest"])
def test_refuses_unverified_manifests(case, channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base)
    pubkey = PUBKEY
    if case == "tampered-manifest":
        m = root / "manifest.json"
        m.write_bytes(m.read_bytes().replace(b"9.0.0", b"9.0.1"))
    elif case == "wrong-key":
        pubkey = OTHER_KEY
    elif case == "no-key":
        pubkey = ""
    elif case == "malformed-sig":
        (root / "manifest.json.sig").write_text("abc")
    elif case == "not-json":
        sign_raw(root, b"not json")
    elif case == "empty-manifest":
        sign_raw(root, b"{}")
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard, pubkey=pubkey)
    assert res == {"status": "no-op"}
    assert not state["replaced"] and state["blocklist"] is None
    expected = {
        "tampered-manifest": ["updater: SIGNATURE INVALID -> refusing update (possible tampering)"],
        "wrong-key": ["updater: SIGNATURE INVALID -> refusing update (possible tampering)"],
        "no-key": ["updater: NO public key embedded -> refusing all updates (fail closed)"],
        "malformed-sig": ["updater: malformed signature -> refusing"],
        "not-json": ["updater: manifest not valid JSON -> refusing"],
        "empty-manifest": [],
    }[case]
    assert logs == expected


def test_tampered_binary_is_discarded(channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base)
    (root / f"guard-{updater.platform_key()}").write_bytes(b"EVIL")
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard)
    assert res["blocklist_updated"] and not res["binary_updated"]
    assert not state["replaced"] and "guard.new" not in state["files"]
    assert any("SHA-256 MISMATCH" in line for line in logs)


@pytest.mark.parametrize("version", ["0.0.0", "same"])
def test_no_downgrade_or_reinstall(version, channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base, version=binary_version(rust_guard) if version == "same" else version)
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard)
    assert not res["binary_updated"] and not state["replaced"]


def test_forced_upgrade_is_logged(channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base, min_version="8.0.0")
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard)
    assert res["binary_updated"]
    assert f"updater: current {binary_version(rust_guard)} below min_version 8.0.0; forced upgrade" in logs


def test_platform_keys_agree(channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base, plat="plan9-x64")
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard)
    assert not res["binary_updated"]
    # same wording from both means both computed the same platform key
    assert logs[-1] == f"updater: no binary for platform {updater.platform_key()} in manifest"


@pytest.mark.skipif(sys.platform.startswith("win") or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs a directory this user cannot write")
def test_unwritable_install_dir_skips_binary(channel, tmp_path, monkeypatch, rust_guard):
    root, base = channel
    publish(root, base)
    res, logs, state = run_both(tmp_path, base, monkeypatch, rust_guard, readonly=True)
    assert res["blocklist_updated"] and not res["binary_updated"]
    assert "binary self-update skipped" in logs[-1]


def test_manifest_from_signer_is_what_both_verify(channel, rust_guard):
    """The signer's manifest shape is unchanged: flat URLs named after the files."""
    root, base = channel
    publish(root, base)
    m = json.loads((root / "manifest.json").read_text())
    assert m["binary"][updater.platform_key()]["url"] == f"{base}/guard-{updater.platform_key()}"
    assert m["blocklist"]["url"] == f"{base}/malware-blocklist.json"
