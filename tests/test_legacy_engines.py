"""Tests for the original incident-focused engines: fingerprint matcher, magic
bytes, VS Code pre-open guard, workflow baseline, dependency blocklist."""

from __future__ import annotations

import io
import json
import runpy
import sys

import pytest

from conftest import ROOT, write
import dep_blocklist as DB
import fingerprint_matcher as FM
import magic_bytes as MB
import vscode_guard as VG
import workflow_baseline as WB
from scanner import load_signatures

SIG = load_signatures()
INFECTED = ROOT / "testdata" / "fake-infected-repo"
CLEAN = ROOT / "testdata" / "clean-repo"


def run_main(path, argv, monkeypatch, stdin: str | None = None) -> int:
    monkeypatch.setattr(sys, "argv", [str(path)] + argv)
    if stdin is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    try:
        runpy.run_path(str(path), run_name="__main__")
    except SystemExit as exc:
        return exc.code
    return None


# ------------------------------------------------------- fingerprint matcher
class TestFingerprintMatcher:
    m = FM.FingerprintMatcher(SIG)

    def test_infected_injection_file(self):
        f = self.m.scan_file(INFECTED / "src" / "server.ts")
        ids = {x.sig_id for x in f}
        assert {"iife.marker.eval", "iife.marker.atob", "iife.combo"} <= ids
        assert FM.FingerprintMatcher.is_infected(f)
        assert "[CRITICAL]" in str(f[0]) and "<<" in str(f[0])

    def test_clean_file_and_unreadable(self, tmp_path):
        assert self.m.scan_file(CLEAN / "src" / "index.ts") == []
        assert self.m.scan_file(tmp_path / "missing.js") == []
        assert str(FM.Finding("w", "s", "low", "c", "d")) == "[LOW] w: s (c) — d"

    def test_env_literal_is_scoped_to_env_files(self):
        env = (INFECTED / ".env").read_text()
        assert any(x.sig_id == "env.auth.b64" for x in self.m.scan_content(".env", env))
        assert not any(x.sig_id == "env.auth.b64" for x in self.m.scan_content("notes.md", env))

    def test_skip_dirs_dropper_name_workflow_name(self):
        assert self.m.scan_content("a/node_modules/x/eval.js", "eval(proxyInfo)") == []
        ids = {x.sig_id for x in self.m.scan_content("public/fonts/fa-solid-400.woff2", "")}
        assert ids == {"drop.file.name"}
        ids = {x.sig_id for x in self.m.scan_content(".github/workflows/ci.yml", "on: push")}
        assert ids == {"wf.name"}

    def test_structural_regex_and_requires_gate(self):
        body = "(async () => {\n const p = atob(process.env.AUTH_API_KEY);\n eval(proxyInfo);\n})();"
        assert "iife.full.regex" in {x.sig_id for x in self.m.scan_content("a.js", body)}
        assert self.m.scan_content("a.js", "(async () => { other(); })();") == []

    def test_obfuscated_c2_literal_in_non_source_ext(self):
        assert self.m.scan_content("blob.txt", "var _$_1e42=['x']")

    def test_custom_flags_and_iocs(self):
        m = FM.FingerprintMatcher({"regexes": [{"id": "r", "severity": "high", "pattern": "^abc",
                                                "flags": "IGNORECASE|MULTILINE|BOGUS", "desc": "d"}],
                                   "network_iocs": [{"id": "ioc", "severity": "critical", "value": "evil.test",
                                                     "desc": "d"}]})
        hits = m.scan_content("x", "zz\nABC evil.test")
        assert {h.sig_id for h in hits} == {"r", "ioc"}

    def test_applies_to_variants(self):
        m = self.m
        assert m._applies({"applies_to": [".vscode/settings.json"]}, "repo/.vscode/settings.json")
        assert m._applies({"applies_to": [".env"]}, "x/.env")
        assert not m._applies({"applies_to": [".env"]}, "x/env.txt")
        assert m._applies({}, "anything")

    def test_snippet(self):
        assert FM._snippet("abc", "zz") == ""
        assert FM._snippet("a\nneedle\nb", "needle", span=1) == "\\nneedle\\n"

    def test_scan_diff_added_lines_only(self):
        diff = ("diff --git a/x b/x\n+++ b/.github/workflows/evil.yml\n"
                "-eval(proxyInfo)\n+const a = 1;\n+atob(process.env.AUTH_API_KEY)\n")
        ids = [x.sig_id for x in self.m.scan_diff(diff)]
        assert "iife.marker.atob" in ids and "wf.added" in ids and "iife.marker.eval" not in ids

    def test_cli(self, monkeypatch, capsys):
        path = ROOT / "fingerprint_matcher.py"
        assert run_main(path, [], monkeypatch) == 2
        assert run_main(path, [str(INFECTED / "src" / "server.ts")], monkeypatch) == 1
        assert run_main(path, [str(CLEAN / "src" / "index.ts")], monkeypatch) == 0
        assert run_main(path, ["--diff"], monkeypatch, stdin="+eval(proxyInfo)\n") == 1
        assert "iife.marker.eval" in capsys.readouterr().out


# --------------------------------------------------------------- magic bytes
class TestMagicBytes:
    c = MB.MagicByteChecker.from_signatures(SIG)

    def test_disguised_dropper(self):
        f = self.c.check_file(INFECTED / "public" / "fonts" / "fa-solid-400.woff2")
        assert f and f[0].severity == "critical" and "disguised" in str(f[0])

    def test_real_font_ok(self):
        assert self.c.check_file(INFECTED / "public" / "fonts" / "real-font.woff2") == []
        assert self.c.check_bytes("a.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 32) == []

    def test_unpoliced_extension(self):
        assert self.c.check_bytes("a.js", b"require('x')") == []

    def test_no_magic_ext_with_text(self):
        f = self.c.check_bytes("a.eot", b"module.exports = 1")
        assert f[0].severity == "high"
        assert self.c.check_bytes("a.eot", b"\x00\x01binary") == []

    def test_wrong_header_not_text(self):
        f = self.c.check_bytes("a.png", b"\xff\xfe\x00\x01\x80\x81")
        assert f[0].severity == "low"
        assert str(MB.MagicFinding("p", "low", "r")) == "[LOW] p: r"

    def test_unreadable(self, tmp_path):
        f = self.c.check_file(tmp_path / "missing.png")
        assert f[0].severity == "info"

    def test_defaults(self):
        c = MB.MagicByteChecker()
        assert c.check_bytes("x.WOFF2", b"var _$_a = function(){}")[0].severity == "critical"

    def test_cli(self, monkeypatch, capsys, tmp_path):
        path = ROOT / "magic_bytes.py"
        assert run_main(path, [], monkeypatch) == 2
        assert run_main(path, [str(INFECTED / "public" / "fonts" / "fa-solid-400.woff2")], monkeypatch) == 1
        low = write(tmp_path / "x.png", b"\xff\xfe\x00\x01")
        assert run_main(path, [str(low)], monkeypatch) == 0


# ----------------------------------------------------------------- vscode
class TestVSCodeGuard:
    g = VG.VSCodeGuard.from_signatures(SIG)

    def test_infected_repo_unsafe(self):
        safe, f = self.g.is_safe_to_open(INFECTED)
        assert not safe and {x.path for x in f} == {".vscode/settings.json", ".vscode/tasks.json"}
        assert "[CRITICAL]" in str(f[0])

    def test_clean_repo_safe(self):
        assert self.g.is_safe_to_open(CLEAN) == (True, [])

    def test_strip_jsonc(self):
        txt = '{\n // c\n "a": "http://x", /* b */ "b": [1,],\n}'
        assert json.loads(VG.strip_jsonc(txt)) == {"a": "http://x", "b": [1]}

    def test_unparseable_files_fail_closed(self, tmp_path):
        write(tmp_path / ".vscode" / "settings.json", '{"task.allowAutomaticTasks": true,, }}')
        write(tmp_path / ".vscode" / "tasks.json", '{"tasks": [{"runOn": "folderOpen", "command": "node x"')
        f = self.g.scan_repo(tmp_path)
        assert [x.severity for x in f] == ["critical", "critical"]
        assert all("raw substring" in x.detail for x in f)

    def test_unparseable_but_harmless(self, tmp_path):
        write(tmp_path / ".vscode" / "settings.json", "{oops")
        write(tmp_path / ".vscode" / "tasks.json", "{oops")
        assert self.g.scan_repo(tmp_path) == []

    def test_unreadable(self, tmp_path):
        (tmp_path / ".vscode" / "settings.json").mkdir(parents=True)
        assert self.g.scan_repo(tmp_path) == []

    def test_task_variants(self, tmp_path):
        tasks = {"tasks": [
            "not-a-dict",
            {"command": "echo hi", "runOptions": {"runOn": "folderOpen"}},          # auto, benign cmd
            {"command": "make", "args": ["curl http://x"]},                         # bad args, not auto
            {"command": "node", "args": ["build.js"]},                              # fine
            {"command": "bash", "runOn": "folderOpen", "args": None},               # top-level runOn
            {"command": "ls", "runOptions": "weird"},
        ]}
        write(tmp_path / ".vscode" / "tasks.json", json.dumps(tasks))
        write(tmp_path / ".vscode" / "settings.json", json.dumps(["not", "a", "dict"]))
        sev = [x.severity for x in self.g.scan_repo(tmp_path)]
        assert sev == ["high", "high", "critical"]

    def test_tasks_not_a_dict(self, tmp_path):
        write(tmp_path / ".vscode" / "tasks.json", "[]")
        assert self.g.scan_repo(tmp_path) == []
        g = VG.VSCodeGuard()
        assert g.danger_runon == ["folderopen"]

    def test_settings_false_is_fine(self, tmp_path):
        write(tmp_path / ".vscode" / "settings.json", '{"task.allowAutomaticTasks": false}')
        assert self.g.scan_repo(tmp_path) == []

    def test_cli(self, monkeypatch, capsys):
        path = ROOT / "vscode_guard.py"
        assert run_main(path, [str(INFECTED)], monkeypatch) == 1
        assert "DO NOT OPEN" in capsys.readouterr().out
        assert run_main(path, [str(CLEAN)], monkeypatch) == 0
        monkeypatch.chdir(CLEAN)
        assert run_main(path, [], monkeypatch) == 0


# --------------------------------------------------------- workflow baseline
class TestWorkflowBaseline:
    def make(self, tmp_path, content="on: push\n"):
        repo = tmp_path / "repo"
        write(repo / ".github" / "workflows" / "build.yml", content)
        write(repo / ".github" / "workflows" / "notes.txt", "ignored")
        return repo

    def test_no_baseline_then_record_then_diff(self, tmp_path):
        wb = WB.WorkflowBaseline(matcher=FM.FingerprintMatcher(SIG), home=tmp_path / "h")
        repo = self.make(tmp_path)
        f = wb.diff(repo)
        assert [(x.state, x.severity) for x in f] == [("added", "high")]
        data = wb.record(repo, approved_by="alice")
        assert list(data["workflows"]) == [".github/workflows/build.yml"]
        assert [x.state for x in wb.diff(repo)] == ["unchanged"]
        write(repo / ".github" / "workflows" / "build.yml", "on: push\nrun: eval(proxyInfo)\n")
        write(repo / ".github" / "workflows" / "new.yaml", "on: pull_request\n")
        f = {x.path: x for x in wb.diff(repo)}
        assert f[".github/workflows/build.yml"].severity == "critical"
        assert f[".github/workflows/new.yaml"].state == "added"
        assert WB.WorkflowBaseline.is_infected(list(f.values()))
        (repo / ".github" / "workflows" / "build.yml").unlink()
        assert "removed" in {x.state for x in wb.diff(repo)}
        assert "workflow removed" in str([x for x in wb.diff(repo) if x.state == "removed"][0])
        assert str(WB.WorkflowFinding("p", "unchanged", "ok")) == "[OK] p: workflow unchanged"

    def test_refuses_to_baseline_infected(self, tmp_path):
        wb = WB.WorkflowBaseline(matcher=FM.FingerprintMatcher(SIG), home=tmp_path / "h")
        repo = self.make(tmp_path, "run: eval(proxyInfo)\n")
        with pytest.raises(ValueError, match="refusing"):
            wb.record(repo)

    def test_without_matcher_and_bad_baseline(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GUARD_HOME", str(tmp_path / "gh"))
        wb = WB.WorkflowBaseline()
        assert wb.home == tmp_path / "gh"
        repo = self.make(tmp_path)
        wb.record(repo)
        write(repo / ".github" / "workflows" / "x.yml", "a")
        assert {x.severity for x in wb.diff(repo)} == {"high", "ok"}
        wb._baseline_path(repo.resolve()).write_text("{bad json")
        assert wb.load_baseline(repo.resolve()) is None
        assert wb.diff(tmp_path / "nothing") == []

    def test_unreadable_changed_workflow(self, tmp_path, monkeypatch):
        wb = WB.WorkflowBaseline(matcher=FM.FingerprintMatcher(SIG), home=tmp_path / "h")
        repo = self.make(tmp_path)
        from pathlib import Path
        monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: (_ for _ in ()).throw(OSError("x")))
        assert wb._assess_content(repo, ".github/workflows/build.yml", "added") == ("high", "unreadable")

    def test_repo_key_is_stable_and_safe(self, tmp_path):
        k = WB.repo_key(tmp_path / "my repo!")
        assert k.startswith("my_repo_-") and k == WB.repo_key(tmp_path / "my repo!")

    def test_cli(self, monkeypatch, capsys, tmp_path):
        path = ROOT / "workflow_baseline.py"
        repo = self.make(tmp_path)
        assert run_main(path, [], monkeypatch) == 2
        assert run_main(path, ["record", str(repo), "bob"], monkeypatch) is None
        assert "baselined 1" in capsys.readouterr().out
        assert run_main(path, ["record", str(repo)], monkeypatch) is None
        assert run_main(path, ["diff", str(repo)], monkeypatch) == 0
        write(repo / ".github" / "workflows" / "build.yml", "eval(proxyInfo)")
        assert run_main(path, ["diff", str(repo)], monkeypatch) == 1
        assert run_main(path, ["record", str(repo)], monkeypatch) == 1


# ------------------------------------------------------------- dep blocklist
BL = {"npm": {"evil-pkg": [">= 0"], "chalk": ["= 5.6.1"], "ranged": [">= 1.0.0, < 1.2"]},
      "pip": {"badpy": ["= 0.1"]}}


@pytest.fixture
def blocklist(tmp_path):
    f = write(tmp_path / "bl.json", json.dumps(BL))
    return DB.DepBlocklist(f)


class TestDepBlocklist:
    @pytest.mark.parametrize("v,want", [("1.2.3", (1, 2, 3)), ("^4.5", (4, 5, 0)), ("v7", (7, 0, 0)),
                                        ("latest", None), (None, None)])
    def test_parse_ver(self, v, want):
        assert DB._parse_ver(v) == want

    @pytest.mark.parametrize("inst,rng,want", [
        ("9.9.9", ">= 0", True), ("x", "*", True), ("", "", True),
        ("latest", "= 1.0.0", False), ("1.1.0", ">= 1.0.0, < 1.2", True),
        ("1.2.0", ">= 1.0.0, < 1.2", False), ("1.0.0", "~1.0", False), ("1.0.0", "= abc", False),
        ("2.0.0", "> 1.0.0", True), ("1.0.0", "<= 1.0.0", True), ("1.0.0", "== 1.0.0", True),
    ])
    def test_in_range(self, inst, rng, want):
        assert DB._in_range(inst, rng) is want

    def test_manifest_detection(self, blocklist):
        assert blocklist.available and blocklist.count() == 4
        for n in ("package.json", "a/package-lock.json", "npm-shrinkwrap.json", "requirements.txt",
                  "requirements-dev.txt", "Pipfile.lock"):
            assert blocklist.is_manifest(n)
        assert not blocklist.is_manifest("setup.py")
        assert blocklist.check_manifest("setup.py", "x") == []

    def test_package_json(self, blocklist):
        pj = json.dumps({"dependencies": {"evil-pkg": "^1.0.0", "chalk": "5.6.1", "left-pad": "1"},
                         "devDependencies": {"chalk": "5.6.1"}, "peerDependencies": None})
        found = blocklist.check_manifest("package.json", pj)
        assert sorted((f.name, f.version) for f in found) == [("chalk", "5.6.1"), ("evil-pkg", "^1.0.0")]
        assert "malicious dependency 'chalk'" in found[0].desc or "malicious dependency" in found[1].desc
        safe = json.dumps({"dependencies": {"chalk": "5.6.2"}})
        assert blocklist.check_manifest("package.json", safe) == []
        assert blocklist.check_manifest("package.json", "{bad") == []

    def test_lockfiles(self, blocklist):
        lock = json.dumps({"packages": {"": {}, "node_modules/ranged": {"version": "1.1.0"},
                                        "node_modules/ok": None},
                           "dependencies": {"evil-pkg": {"version": "0.0.1",
                                                         "dependencies": {"chalk": {"version": "5.6.1"}}}}})
        names = {f.name for f in blocklist.check_manifest("package-lock.json", lock)}
        assert names == {"ranged", "evil-pkg", "chalk"}
        assert blocklist.check_manifest("npm-shrinkwrap.json", "nope") == []
        pl = json.dumps({"default": {"badpy": {"version": "==0.1"}}, "develop": {"ok": None}})
        assert [f.name for f in blocklist.check_manifest("Pipfile.lock", pl)] == ["badpy"]
        assert blocklist.check_manifest("Pipfile.lock", "{") == []

    def test_requirements(self, blocklist):
        req = "# c\n\n-r other.txt\n@@@ not a requirement\nbadpy==0.1 ; python_version>'3'\nbadpy==0.1\nrequests\n"
        found = blocklist.check_manifest("requirements.txt", req)
        assert [(f.name, f.version, f.severity) for f in found] == [("badpy", "0.1", "critical")]

    def test_missing_ecosystem_and_unavailable(self, tmp_path):
        f = write(tmp_path / "bl.json", json.dumps({"npm": {"x": [">= 0"]}}))
        bl = DB.DepBlocklist(f)
        assert bl.check_manifest("requirements.txt", "x==1") == []
        empty = DB.DepBlocklist(tmp_path / "missing.json")
        assert not empty.available and empty.check_manifest("package.json", "{}") == []
        bad = DB.DepBlocklist(write(tmp_path / "bad.json", "{oops"))
        assert not bad.available

    def test_default_paths_env(self, tmp_path, monkeypatch):
        f = write(tmp_path / "env.json", json.dumps(BL))
        monkeypatch.setenv("GUARD_DEP_BLOCKLIST", str(f))
        assert DB._default_paths()[0] == f
        assert DB.DepBlocklist().loaded_from == str(f)

    def test_cli(self, monkeypatch, capsys, tmp_path):
        f = write(tmp_path / "bl.json", json.dumps(BL))
        monkeypatch.setenv("GUARD_DEP_BLOCKLIST", str(f))
        req = write(tmp_path / "requirements.txt", "badpy==0.1\n")
        monkeypatch.setattr(sys, "argv", ["dep_blocklist.py", str(req)])
        runpy.run_path(str(ROOT / "dep_blocklist.py"), run_name="__main__")
        out = capsys.readouterr().out
        assert "loaded from" in out and "badpy" in out
        monkeypatch.setenv("GUARD_DEP_BLOCKLIST", str(tmp_path / "none.json"))
        monkeypatch.setattr(DB, "__file__", str(tmp_path / "dep_blocklist.py"))
        monkeypatch.setattr(sys, "argv", ["dep_blocklist.py"])
        g = runpy.run_path(str(ROOT / "dep_blocklist.py"), run_name="__main__")
        assert g["bl"] is not None
