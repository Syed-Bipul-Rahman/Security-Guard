"""Ported guard commands, Rust binary vs the Python build, side by side.

Each test runs guard.py (or the Python tool it wraps) and the Rust binary on the
same input, with OS tools (systemctl, launchctl, bash, notify-send, osascript)
replaced by recording shims on PATH, and requires the same output, exit code and
files. tests/test_rust_binary.py covers `version` and `update`.
"""

from __future__ import annotations

import ast
import functools
import getpass
import http.server
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from rustbin import ROOT, WINDOWS, binary_version, clean_env, run_python, run_rust, rust_guard  # noqa: F401

UNIX = not WINDOWS
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
GUARD_VERSION = re.search(r'^VERSION = "([^"]+)"', (ROOT / "guard.py").read_text(), re.M).group(1)


def both(rust_guard, *args, env=None, cwd=None, py_env=None):
    """Run the same command on both builds; return (python, rust) results."""
    py = run_python(*args, env={**(env or {}), **(py_env or {})}, cwd=cwd)
    rs = run_rust(rust_guard, *args, env=env, cwd=cwd)
    return py, rs


def text(b: bytes) -> str:
    """Decoded output; Python's text-mode stdout writes CRLF on Windows."""
    return b.decode().replace("\r\n", "\n")


def same(py, rs):
    assert rs.returncode == py.returncode, (py.stdout, py.stderr, rs.stdout, rs.stderr)
    assert text(rs.stdout) == text(py.stdout)


# Lookups that would leave the machine (api.ipify.org) fail fast instead.
NO_NETWORK = {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
              "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}


# ---------------------------------------------------------------------------
# a tiny HTTP server for collectors, IP lookups and the advisory API
# ---------------------------------------------------------------------------
class Server:
    def __init__(self):
        self.routes: dict[str, tuple[int, dict, bytes]] = {}
        self.posts: list[tuple[str, dict, bytes]] = []
        self.gets: list[tuple[str, dict]] = []
        srv = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, headers, body):
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                srv.gets.append((self.path, self.headers))
                self._reply(*srv.routes.get(self.path, (404, {}, b"not found")))

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                srv.posts.append((self.path, self.headers, body))
                status = srv.routes.get("POST " + self.path, (200, {}, b"ok"))
                self._reply(*status)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.close()


def shim(bindir: Path, name: str, body: str) -> None:
    """A fake OS tool on PATH that records how it was called."""
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)


def shim_path(bindir: Path) -> str:
    return str(bindir) + os.pathsep + os.environ.get("PATH", "")


# ---------------------------------------------------------------------------
# sysmon-config, triage, notify-test, permissions
# ---------------------------------------------------------------------------
def test_sysmon_config(rust_guard, tmp_path):
    py, rs = both(rust_guard, "sysmon-config")
    same(py, rs)
    assert rs.stdout == (ROOT / "windows" / "sysmon-config.xml").read_bytes()
    for name in ("py.xml", "rs.xml"):
        exe = run_python if name == "py.xml" else functools.partial(run_rust, rust_guard)
        r = exe("sysmon-config", str(tmp_path / name))
        assert r.returncode == 0 and r.stdout.decode().strip() == f"wrote {tmp_path / name}"
    assert (tmp_path / "py.xml").read_bytes() == (tmp_path / "rs.xml").read_bytes()
    py, rs = both(rust_guard, "sysmon-config", str(tmp_path / "missing" / "x.xml"))
    assert py.returncode == rs.returncode == 1
    assert rs.stderr.decode().startswith(f"could not write {tmp_path / 'missing' / 'x.xml'}: ")


@pytest.mark.skipif(WINDOWS, reason="triage runs the bash script on Linux/macOS")
def test_triage_runs_the_bundled_script(rust_guard, tmp_path):
    shims = tmp_path / "shims"
    shims.mkdir()
    # fake bash: keep a copy of the script it was given, echo the arguments
    shim(shims, "bash", 'cp "$1" "$OUT_SCRIPT"; shift; echo "triage args: $*"; exit 3\n')
    env = {"PATH": shim_path(shims)}
    py = run_python("triage", "--days", "3", env={**env, "OUT_SCRIPT": str(tmp_path / "py.sh")})
    rs = run_rust(rust_guard, "triage", "--days", "3", env={**env, "OUT_SCRIPT": str(tmp_path / "rs.sh")})
    same(py, rs)
    assert rs.returncode == 3 and rs.stdout == b"triage args: --days 3\n"
    script = (ROOT / "linux" / "guard-triage-linux.sh").read_bytes()
    assert (tmp_path / "py.sh").read_bytes() == (tmp_path / "rs.sh").read_bytes() == script


@pytest.mark.skipif(not WINDOWS, reason="the Windows triage message")
def test_triage_on_windows(rust_guard):
    same(*both(rust_guard, "triage"))


@pytest.mark.skipif(WINDOWS, reason="would pop a real message box on the runner's console")
def test_notify_test(rust_guard, tmp_path):
    shims = tmp_path / "shims"
    shims.mkdir()
    tool = "osascript" if MACOS else "notify-send"
    shim(shims, tool, 'for a in "$@"; do printf "%s\\n" "$a"; done > "$OUT_ARGS"\n')
    env = {"PATH": shim_path(shims)}
    py = run_python("notify-test", env={**env, "OUT_ARGS": str(tmp_path / "py.args")})
    rs = run_rust(rust_guard, "notify-test", env={**env, "OUT_ARGS": str(tmp_path / "rs.args")})
    same(py, rs)
    assert rs.stdout == b"notified\n" and rs.returncode == 0
    assert (tmp_path / "py.args").read_text() == (tmp_path / "rs.args").read_text()
    assert "This is a TEST alert" in (tmp_path / "rs.args").read_text()


@pytest.mark.skipif(not LINUX, reason="needs a PATH with no notifier at all")
def test_notify_test_without_a_notifier(rust_guard, tmp_path):
    py, rs = both(rust_guard, "notify-test", env={"PATH": str(tmp_path)})
    same(py, rs)
    assert rs.returncode == 1 and b"no mechanism available" in rs.stdout


@pytest.mark.parametrize("action", [[], ["check"], ["CHECK"]])
def test_permissions_check(rust_guard, action):
    same(*both(rust_guard, "permissions", *action))
    same(*both(rust_guard, "perms", *action))


@pytest.mark.skipif(MACOS, reason="on macOS this would raise real Allow prompts")
def test_permissions_request_elsewhere_is_a_noop(rust_guard):
    same(*both(rust_guard, "permissions", "request"))


# ---------------------------------------------------------------------------
# telemetry
# ---------------------------------------------------------------------------
ALERTS = "\n".join(json.dumps(a) for a in [
    {"ts": "t1", "severity": "critical", "rule": "dropper.fonts", "kind": "file", "path": "/p/a.woff2"},
    {"ts": "t2", "severity": "high", "kind": "workflow", "summary": "évil workflow"},
    {"ts": "t3", "severity": "critical", "rule": "dropper.fonts", "kind": "file", "summary": ""},
]) + "\nnot json\n"


def telemetry_home(base: Path, server: Server, **cfg) -> Path:
    home = base
    home.mkdir(parents=True)
    (home / "alerts.jsonl").write_text(ALERTS, encoding="utf-8")
    (home / "install.json").write_text(json.dumps({"installed_by": "dev", "version": "1.9.0"}))
    conf = {"endpoint": server.url + "/api/telemetry", "ingest_token": "tok-123",
            "public_ip_lookup": server.url + "/ip", **cfg}
    (home / "telemetry.config.json").write_text(json.dumps(conf))
    return home


def strip_scope(ips):
    return sorted({i.split("%")[0] for i in ips})


def test_telemetry_report_matches(rust_guard, tmp_path, server):
    server.routes["/ip"] = (200, {}, b" 203.0.113.7\n")
    home = telemetry_home(tmp_path / "home", server)
    env = {"GUARD_HOME": str(home), **NO_NETWORK}
    py = run_python("telemetry", env=env)
    py_local = json.loads((home / "telemetry.json").read_text())
    rs = run_rust(rust_guard, "telemetry", env=env)
    rs_local = json.loads((home / "telemetry.json").read_text())
    same(py, rs)
    assert ast.literal_eval(rs.stdout.decode()) == {"status": "sent", "http": 200}

    (_, py_h, py_body), (_, rs_h, rs_body) = server.posts
    for h in (py_h, rs_h):
        assert h["X-Guard-Token"] == "tok-123" and h["Content-Type"] == "application/json"
        assert h["User-Agent"] == "guard-telemetry"
    py_rep, rs_rep = json.loads(py_body), json.loads(rs_body)
    assert rs_rep == rs_local and py_rep == py_local
    assert list(rs_rep) == list(py_rep) == ["schema", "ts", "host", "events"]
    assert rs_rep["events"] == py_rep["events"]
    assert rs_rep["events"]["how"] == ["dropper.fonts", "workflow"] and rs_rep["events"]["infected"]
    ph, rh = py_rep["host"], rs_rep["host"]
    assert list(rh) == list(ph)
    for k in ("hostname", "os", "os_version", "username", "agent_version", "public_ip", "install"):
        assert rh[k] == ph[k], k
    assert rh["public_ip"] == "203.0.113.7"
    # the Rust build keeps the id this host already reported under
    assert rh["machine_id"] == ph["machine_id"]
    assert strip_scope(rh["local_ips"]) == strip_scope(ph["local_ips"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00", rs_rep["ts"])
    # the local copy is written the same way (indent=2, ASCII-escaped)
    text = (home / "telemetry.json").read_text()
    assert "\\u00e9vil" in text and text.startswith('{\n  "schema": "guard-telemetry/1",')


def test_telemetry_failures_queue_and_local_only(rust_guard, tmp_path, server):
    server.routes["POST /api/telemetry"] = (500, {}, b"boom")
    for who in ("py", "rs"):
        home = telemetry_home(tmp_path / who, server, public_ip_lookup="")
        env = {"GUARD_HOME": str(home), **NO_NETWORK}
        r = run_python("telemetry", env=env) if who == "py" else run_rust(rust_guard, "telemetry", env=env)
        res = ast.literal_eval(r.stdout.decode())
        assert r.returncode == 0 and res["status"] == "queued" and res["error"]
        queued = (home / "telemetry-queue.jsonl").read_text().splitlines()
        assert len(queued) == 1 and json.loads(queued[0])["schema"] == "guard-telemetry/1"
        (home / "telemetry.config.json").write_text(json.dumps({"endpoint": ""}))
    py, rs = (run_python("telemetry", env={"GUARD_HOME": str(tmp_path / "py"), **NO_NETWORK}),
              run_rust(rust_guard, "telemetry", env={"GUARD_HOME": str(tmp_path / "rs"), **NO_NETWORK}))
    same(py, rs)
    assert rs.stdout == b"{'status': 'local-only'}\n"


# ---------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------
PY_INSTALL = """
import os, sys
sys.path.insert(0, os.environ["ROOT"])
import guard
p = os.environ["GUARD_INSTALL_PREFIX"]
for k in ("SYSTEMD_UNIT", "LAUNCHD_PLIST", "LAUNCHAGENT_PLIST"):
    setattr(guard, k, p + getattr(guard, k))
for d in ("/etc/systemd/system", "/Library/LaunchAgents", "/Library/LaunchDaemons"):
    os.makedirs(p + d, exist_ok=True)
guard._self_exe = lambda: os.environ["FAKE_EXE"]
sys.exit(guard.main(sys.argv[1:]))
"""


def sudo_user() -> str:
    me = getpass.getuser()
    return "nobody" if me == "root" else me


def install_both(rust_guard, tmp_path, server, *args):
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    for tool in ("systemctl", "launchctl"):
        shim(shims, tool, f'echo "{tool} $*" >> "$CALLS"\n')
    out = {}
    for who in ("py", "rs"):
        base = tmp_path / who
        (base / "prefix").mkdir(parents=True, exist_ok=True)
        env = {
            "PATH": shim_path(shims), "CALLS": str(base / "calls"),
            "GUARD_HOME": str(base / "home"), "GUARD_INSTALL_PREFIX": str(base / "prefix"),
            "SUDO_USER": sudo_user(), "FAKE_EXE": str(rust_guard), "ROOT": str(ROOT),
            "GUARD_TELEMETRY_URL": server.url + "/api/telemetry", "GUARD_INGEST_TOKEN": "tok-9",
            **NO_NETWORK,
        }
        cmd = [sys.executable, "-c", PY_INSTALL, *args] if who == "py" else [str(rust_guard), *args]
        r = subprocess.run(cmd, capture_output=True, env={**clean_env(), **env}, timeout=120)
        calls = (base / "calls").read_text() if (base / "calls").exists() else ""
        out[who] = (r, calls.replace(str(base), "<base>"), base)
    return out


def norm_paths(s: str, base: Path) -> str:
    return s.replace(str(base), "<base>")


@pytest.mark.skipif(not (LINUX or MACOS), reason="systemd / launchd installers")
def test_install_and_uninstall(rust_guard, tmp_path, server):
    res = install_both(rust_guard, tmp_path, server, "install")
    (py, py_calls, pyb), (rs, rs_calls, rsb) = res["py"], res["rs"]
    assert rs.returncode == py.returncode == 0, (py.stderr, rs.stderr)
    assert norm_paths(text(rs.stdout), rsb) == norm_paths(text(py.stdout), pyb)
    assert rs_calls == py_calls and rs_calls
    unit = "etc/systemd/system/guard.service" if LINUX else "Library/LaunchAgents/me.syedbipul.guard.plist"
    py_unit = norm_paths((pyb / "prefix" / unit).read_text(), pyb)
    assert norm_paths((rsb / "prefix" / unit).read_text(), rsb) == py_unit
    assert f"{rust_guard}" in py_unit
    if LINUX:
        # the service's state is seeded the same way
        for name in ("watcher.config.json", "telemetry.config.json"):
            assert (rsb / "home" / name).read_text() == (pyb / "home" / name).read_text(), name
        py_stamp = json.loads((pyb / "home" / "install.json").read_text())
        rs_stamp = json.loads((rsb / "home" / "install.json").read_text())
        assert list(rs_stamp) == list(py_stamp) == ["installed_by", "installed_at", "version"]
        assert rs_stamp["installed_by"] == py_stamp["installed_by"] == sudo_user()
        assert py_stamp["version"] == GUARD_VERSION and rs_stamp["version"] == binary_version(rust_guard)
        assert json.loads((rsb / "home" / "telemetry.config.json").read_text())["ingest_token"] == "tok-9"
        # and each reported in once, right away
        tokens = [h["X-Guard-Token"] for p, h, _ in server.posts if p == "/api/telemetry"]
        assert tokens == ["tok-9", "tok-9"]

    res = install_both(rust_guard, tmp_path, server, "uninstall")
    (py, py_calls, pyb), (rs, rs_calls, rsb) = res["py"], res["rs"]
    assert rs.returncode == py.returncode == 0
    assert norm_paths(text(rs.stdout), rsb) == norm_paths(text(py.stdout), pyb)
    assert rs_calls == py_calls
    assert not (rsb / "prefix" / unit).exists() and not (pyb / "prefix" / unit).exists()


@pytest.mark.skipif(not (LINUX or MACOS) or os.geteuid() == 0, reason="needs a directory this user cannot write")
def test_install_without_root(rust_guard, tmp_path, server):
    for who in ("py", "rs"):
        for d in ("etc/systemd/system", "Library/LaunchAgents", "Library/LaunchDaemons"):
            p = tmp_path / who / "prefix" / d
            p.mkdir(parents=True)
            p.chmod(0o555)
    res = install_both(rust_guard, tmp_path, server, "install")
    (py, py_calls, _), (rs, rs_calls, _) = res["py"], res["rs"]
    assert rs.returncode == py.returncode == 1
    assert rs.stderr.decode().strip() == py.stderr.decode().strip() == "guard install needs root (run with sudo)"


@pytest.mark.skipif(not WINDOWS, reason="the Windows install message")
def test_install_on_windows_points_at_guard_ps1(rust_guard, tmp_path):
    env = {"GUARD_HOME": str(tmp_path / "home"), "GUARD_TELEMETRY_URL": "", **NO_NETWORK}
    py, rs = both(rust_guard, "install", env=env)
    same(py, rs)


# ---------------------------------------------------------------------------
# deps check
# ---------------------------------------------------------------------------
BLOCKLIST = {
    "npm": {"evil-pkg": ["< 9.9.9"], "@bad/scope": [">= 0", "= 1.0.0"], "lock-only": [">= 0"],
            "yarn-evil": [">= 0"], "pnpm-evil": [">= 0"], "deep-evil": [">= 0"]},
    "pip": {"py-evil": ["< 2"], "pipfile-evil": [">= 0"], "poetry-evil": [">= 0"]},
}


def make_project(root: Path) -> None:
    files = {
        "package.json": json.dumps({"dependencies": {"evil-pkg": "^1.2.0", "left-pad": "1.0.0"},
                                    "devDependencies": {"@bad/scope": "1.0.0"}}),
        "sub/package-lock.json": json.dumps({"packages": {"": {}, "node_modules/lock-only": {"version": "2.0.0"},
                                                          "node_modules/a/node_modules/evil-pkg": {"version": "0.5"}},
                                             "dependencies": {"x": {"version": "1",
                                                                    "dependencies": {"deep-evil": {"version": "0.1"}}}}}),
        "yarn.lock": '# yarn\n\n"yarn-evil@^1.0.0", yarn-evil@~1:\n  version "1.4.0"\n\nok@1:\n  version "1"\n',
        "pnpm-lock.yaml": "packages:\n  /pnpm-evil@3.1.0:\n    resolution: x\n  /@bad/scope@1.0.0(react@18):\n",
        "requirements-dev.txt": "# dev\npy-evil == 1.5 ; python_version>'3'\n-r other.txt\nrequests\n",
        "Pipfile.lock": json.dumps({"default": {"pipfile-evil": {"version": "==0.3"}}, "develop": {}}),
        "poetry.lock": '[[package]]\nname = "poetry-evil"\nversion = "4.0"\n',
        "node_modules/evil-pkg/package.json": json.dumps({"dependencies": {"evil-pkg": "1"}}),
        "broken/package.json": "{not json",
        "notes.txt": "evil-pkg",
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (root / "crlf").mkdir()
    (root / "crlf" / "yarn.lock").write_bytes(b'yarn-evil@1:\r\n  version "9"\r\n\r\n')


def deps_home(base: Path, blocklist=BLOCKLIST) -> Path:
    (base / "feed").mkdir(parents=True)
    if blocklist is not None:
        (base / "feed" / "malware-blocklist.json").write_text(json.dumps(blocklist))
    return base


def test_deps_check_finds_the_same_packages(rust_guard, tmp_path):
    proj = tmp_path / "proj"
    make_project(proj)
    env = {"GUARD_HOME": str(deps_home(tmp_path / "home"))}
    py, rs = both(rust_guard, "deps", "check", str(proj), env=env)
    same(py, rs)
    assert rs.returncode == 1
    out = rs.stdout.decode()
    for name in ("evil-pkg", "@bad/scope", "lock-only", "yarn-evil", "pnpm-evil", "deep-evil", "py-evil",
                 "pipfile-evil", "poetry-evil"):
        assert f"] {name}  (" in out, name
    # relative target, from inside the project
    same(*both(rust_guard, "deps", "check", ".", env=env, cwd=proj))
    same(*both(rust_guard, "deps", "check", env=env, cwd=proj))
    same(*both(rust_guard, "deps", "check", "./sub/", env=env, cwd=proj))


def test_deps_check_versionless_and_versioned_hits(rust_guard, tmp_path):
    """check_deps.py crashes sorting a hit with no version next to one with a
    version (None < str); the Rust build lists the versionless one first."""
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    (proj / "package.json").write_text(json.dumps({"dependencies": {"evil-pkg": "1.0.0"}}))
    (proj / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/evil-pkg": {}}}))
    env = {"GUARD_HOME": str(deps_home(tmp_path / "home"))}
    py, rs = both(rust_guard, "deps", "check", ".", env=env, cwd=proj)
    assert py.returncode == 1 and b"TypeError" in py.stderr
    assert rs.returncode == 1
    lines = [ln for ln in rs.stdout.decode().splitlines() if ln.startswith("  [npm]")]
    assert lines == ["  [npm] evil-pkg  (your version: ?; malicious range: < 9.9.9)",
                     "  [npm] evil-pkg  (your version: 1.0.0; malicious range: < 9.9.9)"]


@pytest.mark.parametrize("target", ["testdata/fake-infected-repo", "testdata/clean-repo", "malware-feed"])
def test_deps_check_with_the_bundled_snapshot(rust_guard, tmp_path, target):
    env = {"GUARD_HOME": str(deps_home(tmp_path / "home", blocklist=None))}
    py, rs = both(rust_guard, "deps", "check", target, env=env, cwd=ROOT)
    same(py, rs)
    assert b"malicious package names across" in rs.stdout


def test_deps_usage_and_errors(rust_guard, tmp_path):
    env = {"GUARD_HOME": str(tmp_path / "home")}
    for args in (["deps"], ["deps", "-h"], ["deps", "--help"]):
        same(*both(rust_guard, *args, env=env))
    py, rs = both(rust_guard, "deps", "bogus", env=env)
    same(py, rs)
    assert text(rs.stderr) == text(py.stderr) == "unknown deps subcommand: bogus\n"


# ---------------------------------------------------------------------------
# deps update (GitHub advisory API, served locally)
# ---------------------------------------------------------------------------
def advisory(i: int, **kw) -> dict:
    a = {"ghsa_id": f"GHSA-{i:04d}", "summary": f"Malicious package {i}\nsecond line",
         "published_at": f"2026-01-{i:02d}T00:00:00Z", "withdrawn_at": None, "cvss": {"score": 9.8},
         "vulnerabilities": [{"package": {"ecosystem": "npm", "name": f"pkg-{i}"},
                              "vulnerable_version_range": ">= 0"}]}
    a.update(kw)
    return a


PAGES = [
    [advisory(1), advisory(2, summary="naïve, \"quoted\" — π", cvss={"score": 10.0}),
     advisory(3, withdrawn_at="2026-02-01T00:00:00Z")],
    [advisory(4, vulnerabilities=[
        {"package": {"ecosystem": "pip", "name": "py-a"}, "vulnerable_version_range": "< 1"},
        {"package": {"ecosystem": "pip", "name": "py-a"}, "vulnerable_version_range": "= 2"},
        {"package": {"ecosystem": "pip", "name": "py-a"}, "vulnerable_version_range": "< 1"},
        {"package": {"ecosystem": "npm", "name": ""}},
        {"package": {"ecosystem": "go", "name": "x/y"}, "vulnerable_version_range": None}]),
     advisory(1), advisory(5, summary=None, vulnerabilities=None)],
]


def serve_advisories(server: Server, ecosystem: str | None = None) -> str:
    api = server.url + "/advisories"
    first = "/advisories?type=malware&per_page=100&sort=published&direction=desc"
    if ecosystem:
        first += f"&ecosystem={ecosystem}"
    nxt = f"{api}?after=page2"
    server.routes[first] = (200, {"Link": f'<{nxt}>; rel="next", <{api}?x=1>; rel="prev"',
                                  "X-RateLimit-Remaining": "4999"}, json.dumps(PAGES[0]).encode())
    server.routes["/advisories?after=page2"] = (200, {"X-RateLimit-Remaining": "4998"},
                                                json.dumps(PAGES[1]).encode())
    return api


PY_COLLECT = """
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("collect", os.path.join(os.environ["ROOT"], "malware-feed", "collect_malware_advisories.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.API = os.environ["GUARD_ADVISORY_API"]
sys.argv = ["collect_malware_advisories.py"] + sys.argv[1:]
sys.exit(m.main())
"""


def update_both(rust_guard, tmp_path, api, *extra):
    out = {}
    for who in ("py", "rs"):
        home = tmp_path / who
        env = {"GUARD_HOME": str(home), "GUARD_ADVISORY_API": api, "GITHUB_TOKEN": "tkn", "ROOT": str(ROOT)}
        feed = home / "feed"
        if who == "py":
            feed.mkdir(parents=True, exist_ok=True)
            cmd = [sys.executable, "-c", PY_COLLECT, "--out", str(feed), "--resume", *extra]
        else:
            cmd = [str(rust_guard), "deps", "update", *extra]
        r = subprocess.run(cmd, capture_output=True, env=clean_env(env), timeout=120)
        out[who] = (r, feed)
    return out


FEED_FILES = ("malware-blocklist.json", "malware-packages.csv", "malware-advisories.json", "collect-state.json")


def test_deps_update_builds_the_same_files(rust_guard, tmp_path, server):
    api = serve_advisories(server)
    res = update_both(rust_guard, tmp_path, api)
    (py, pyf), (rs, rsf) = res["py"], res["rs"]
    assert rs.returncode == py.returncode == 0, (py.stderr, rs.stderr)
    assert text(rs.stdout).replace(str(rsf), "<feed>") == text(py.stdout).replace(str(pyf), "<feed>")
    for name in FEED_FILES:
        assert (rsf / name).read_bytes() == (pyf / name).read_bytes(), name
    assert all(h.get("Authorization") == "Bearer tkn" for _, h in server.gets)
    bl = json.loads((rsf / "malware-blocklist.json").read_text())
    assert "pkg-3" not in bl["npm"] and bl["pip"]["py-a"] == ["< 1", "= 2"]

    # a second run resumes from the saved cursor (end reached -> starts over, deduped)
    res = update_both(rust_guard, tmp_path, api, "--max-pages", "1")
    (py, pyf), (rs, rsf) = res["py"], res["rs"]
    assert text(rs.stdout).replace(str(rsf), "<feed>") == text(py.stdout).replace(str(pyf), "<feed>")
    assert "stopping at --max-pages 1" in rs.stdout.decode()
    for name in FEED_FILES:
        assert (rsf / name).read_bytes() == (pyf / name).read_bytes(), name


def test_deps_update_ecosystem_and_bad_args(rust_guard, tmp_path, server):
    api = serve_advisories(server, ecosystem="npm")
    res = update_both(rust_guard, tmp_path, api, "--eco", "npm")
    (py, pyf), (rs, rsf) = res["py"], res["rs"]
    assert rs.returncode == py.returncode == 0
    assert (rsf / "malware-blocklist.json").read_bytes() == (pyf / "malware-blocklist.json").read_bytes()
    r = run_rust(rust_guard, "deps", "update", "--max-pages", "x", env={"GUARD_HOME": str(tmp_path / "h")})
    assert r.returncode == 2 and b"invalid int value: 'x'" in r.stderr
    r = run_rust(rust_guard, "deps", "update", "--nope", env={"GUARD_HOME": str(tmp_path / "h")})
    assert r.returncode == 2 and b"unrecognized arguments: --nope" in r.stderr


def test_bundled_snapshot_is_the_committed_one(rust_guard, tmp_path):
    """`deps check` without a feed uses exactly malware-feed/malware-blocklist.json."""
    bl = json.loads((ROOT / "malware-feed" / "malware-blocklist.json").read_text())
    total = sum(len(v) for v in bl.values())
    r = run_rust(rust_guard, "deps", "check", str(tmp_path), env={"GUARD_HOME": str(tmp_path / "h")})
    assert r.stdout.decode().splitlines()[0] == \
        f"blocklist: {total} malicious package names across {len(bl)} ecosystem(s)"
