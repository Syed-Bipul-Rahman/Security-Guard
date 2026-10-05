"""Remediator (surgical clean-up) and Ed25519 (OTA signature) tests."""

from __future__ import annotations

import json
import runpy
import sys

import pytest

import ed25519_pure as ED
import remediator as RM
import samples
from conftest import ROOT, write

INJECTED = (
    'import { defineConfig } from "vite";\n'
    '(async () => { const proxyInfo = atob(process.env.AUTH_API_KEY); eval(proxyInfo); })();\n'
    'export default defineConfig({ plugins: [] });\n'
)


@pytest.fixture
def rem(tmp_path):
    logs = []
    r = RM.Remediator(tmp_path / "home", log=logs.append)
    r.logs = logs
    return r


# ------------------------------------------------------------ bracket matcher
@pytest.mark.parametrize("src,i,want", [
    ("(a(b)c)", 0, 6),
    ("(')' + \")\")", 0, 10),
    ("(`x ${ '}' + `y` } )`)", 0, 21),
    ("(a // )\n)", 0, 8),
    ("(a /* ) */ )", 0, 11),
    ("(unclosed", 0, -1),
    ("{a}", 0, 2),
])
def test_matching_bracket(src, i, want):
    assert RM._matching_bracket(src, i) == want


@pytest.mark.parametrize("src,ok", [
    ("f(a[1], {b: 2})", True), ("f(a]", False), (")", False), ("(", False),
    ("'(' + \"[\" + `${'{'}` // (\n /* [ */", True),
    ("`a\\`b`", True), ("'esc\\'q'", True), ("`${ \"\\}\" }`", True),
    ("`a ${ `inner ${1}` } b`", True), ("`${ a \\} }`", True), ("`${ {a: 1}.a }`", True),
])
def test_brackets_balanced(src, ok):
    assert RM._brackets_balanced(src) is ok


def test_skip_helpers_hit_end_of_input():
    assert RM._skip_string("'abc", 0, "'") == 4
    assert RM._skip_block_comment("/* x", 0) == 4
    assert RM._skip_template("`abc", 0) == 4
    assert RM._skip_template("`${ \\x", 0) == 6


# --------------------------------------------------------------- IIFE excision
def test_strip_malicious_iife_keeps_real_code():
    new, removed = RM.strip_malicious_iife(INJECTED)
    assert len(removed) == 1 and "eval(proxyInfo)" in removed[0]
    assert new == 'import { defineConfig } from "vite";\nexport default defineConfig({ plugins: [] });\n'


@pytest.mark.parametrize("src", [
    "(function(){ console.log(1) })();",                         # benign IIFE
    "(() => { eval(x) })",                                       # not invoked
    "(() => { eval(proxyInfo) }",                                # unbalanced wrapper
    "(() => { eval(proxyInfo) }) (",                             # unbalanced invocation
    "(() => { eval(proxyInfo) })",                               # wrapper ends the file
])
def test_not_excised(src):
    assert RM.strip_malicious_iife(src) == (src, [])


def test_weak_marker_combo_and_nested_spans():
    src = "x;\n  (function () { eval(require('node-fetch')) ; (a => a)(1) }) ()  \n\n\n\ny;"
    new, removed = RM.strip_malicious_iife(src)
    assert removed and new == "x;\n\ny;"
    assert RM._iife_is_malicious("eval(atob('x'))") and not RM._iife_is_malicious("eval(1)")
    src2 = "z; (async () => { eval(proxyInfo) })() ;tail"
    assert RM.strip_malicious_iife(src2)[0] == "z; ;tail"


# ------------------------------------------------------------------ JSONC
def test_strip_jsonc_is_string_aware():
    txt = '{"url": "http://x//y", /* c */ "a": [1,], // t\n "b": \'/*k*/\',}'
    assert RM._strip_jsonc(txt) == '{"url": "http://x//y",  "a": [1], \n "b": \'/*k*/\'}'


# ---------------------------------------------------------------- strategies
def test_quarantine_and_restore(rem, tmp_path):
    f = write(tmp_path / "repo" / "public" / "fonts" / "fa-solid-400.woff2", "require('x')")
    res = rem.remediate_file(f, is_dropper=True)
    assert res["action"] == "quarantine" and not f.exists()
    out = rem.restore(str(f))
    assert out["restored"] == [str(f)] and f.read_text() == "require('x')"
    by_backup = rem.restore(json.loads(rem.index.read_text().splitlines()[0])["backup"].split("/")[-1])
    assert by_backup["restored"] == [str(f)]


def test_quarantine_unlink_error(rem, tmp_path, monkeypatch):
    f = write(tmp_path / "a.bin", b"x")
    from pathlib import Path
    monkeypatch.setattr(Path, "unlink", lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("ro")))
    assert rem.quarantine_file(f)["action"] == "error"


def test_neutralize_js(rem, tmp_path):
    f = write(tmp_path / "vite.config.js", INJECTED)
    res = rem.remediate_file(f)
    assert res["action"] == "neutralize" and "eval(proxyInfo)" not in f.read_text()
    assert "defineConfig" in f.read_text()
    assert rem.neutralize_js(f) is None                         # already clean
    assert rem.neutralize_js(tmp_path / "missing.js") is None


def test_neutralize_refuses_to_unbalance(rem, tmp_path, monkeypatch):
    f = write(tmp_path / "a.js", INJECTED)
    monkeypatch.setattr(RM, "_brackets_balanced", lambda s: False)
    assert rem.neutralize_js(f)["action"] == "manual" and f.read_text() == INJECTED


def test_source_file_never_deleted(rem, tmp_path):
    f = write(tmp_path / "a.py", "print('x')")
    assert rem.remediate_file(f)["action"] == "manual" and f.exists()
    g = write(tmp_path / "b.js", "console.log(1)")
    assert rem.remediate_file(g)["action"] == "manual"
    assert rem.remediate_file(tmp_path / "gone.js")["action"] == "gone"


def test_vscode_settings_and_tasks(rem, tmp_path):
    s = write(tmp_path / ".vscode" / "settings.json", '{"task.allowAutomaticTasks": true, // x\n "a": 1}')
    assert rem.remediate_file(s)["action"] == "clean-settings"
    assert json.loads(s.read_text()) == {"a": 1}
    assert rem.remediate_file(s)["action"] == "noop"
    tasks = {"tasks": [
        {"label": "evil", "command": "node", "args": ["./public/fonts/x.woff2"], "runOptions": {"runOn": "folderOpen"}},
        {"label": "ok", "command": "npm", "args": ["test"]},
        {"label": "auto-but-benign", "runOptions": {"runOn": "folderOpen"}, "command": "echo hi"},
        "junk",
    ]}
    t = write(tmp_path / ".vscode" / "tasks.json", json.dumps(tasks))
    res = rem.remediate_file(t)
    assert res["action"] == "clean-tasks" and res["dropped"] == 1
    assert [x if isinstance(x, str) else x["label"] for x in json.loads(t.read_text())["tasks"]] == \
        ["ok", "auto-but-benign", "junk"]
    assert rem.remediate_file(t)["action"] == "noop"
    launch = write(tmp_path / ".vscode" / "launch.json", "{broken")
    assert rem.remediate_file(launch)["action"] == "noop"
    write(s, "{broken")
    assert rem.clean_vscode_settings(s) is None
    write(t, '{"tasks": "nope"}')
    assert rem.clean_vscode_tasks(t) is None


def test_task_is_malicious_variants():
    assert RM.Remediator._task_is_malicious({"runOn": "folderOpen", "command": "powershell -e AAA"})
    assert not RM.Remediator._task_is_malicious({"runOptions": "x", "command": "iex "})


def test_clean_repo_end_to_end(rem, tmp_path):
    repo = tmp_path / "repo"
    write(repo / "vite.config.js", INJECTED)
    write(repo / "public" / "fonts" / "fa-solid-400.woff2", "var _$_1e42=['x']; require('child_process')")
    write(repo / ".vscode" / "settings.json", '{"task.allowAutomaticTasks": true}')
    write(repo / ".vscode" / "tasks.json", json.dumps({"tasks": [
        {"command": "node", "args": ["./public/fonts/fa-solid-400.woff2"], "runOptions": {"runOn": "folderOpen"}}]}))
    write(repo / "tools" / "eicar.com", samples.eicar())                              # av: quarantine
    write(repo / "web" / "shell.php", samples.decoded(samples.MALICIOUS)["webshell_eval.php"][1])  # av: review
    write(repo / "img" / "logo.png", "module.exports = eval(proxyInfo)")              # fingerprint on binary ext
    s = rem.clean_repo(repo)
    assert str(repo / "vite.config.js") in s["neutralized"]
    assert str(repo / "public" / "fonts" / "fa-solid-400.woff2") in s["quarantined"]
    assert str(repo / "tools" / "eicar.com") in s["quarantined"]
    assert str(repo / "img" / "logo.png") in s["quarantined"]
    assert str(repo / "web" / "shell.php") in s["manual"]
    assert {str(repo / ".vscode" / "settings.json"), str(repo / ".vscode" / "tasks.json")} <= set(s["config_cleaned"])
    assert (repo / "web" / "shell.php").exists()                                     # source never deleted
    again = rem.clean_repo(repo)
    assert again["quarantined"] == [] and again["neutralized"] == []


def test_clean_repo_routes_noop_and_errors(rem, tmp_path, monkeypatch):
    import scanner
    repo = tmp_path / "r"
    write(repo / "a.js", "eval(proxyInfo)")

    class FakeScanner:
        def __init__(self, sig):
            self.vscode = self

        def is_safe_to_open(self, repo):
            raise RuntimeError("vscode boom")

        def scan_tree(self, repo):
            return {"magic": [{"severity": "low", "path": "x"}, {"severity": "critical", "path": None}],
                    "fingerprint": [{"severity": "low"}, {"severity": "critical", "where": "a.js"},
                                    {"severity": "critical", "where": "a.js"}],
                    "av": [{"severity": "medium", "path": "a.js"}, {"severity": "critical", "path": "a.js"},
                           {"severity": "critical", "path": None}]}
    monkeypatch.setattr(scanner, "GuardScanner", FakeScanner)
    monkeypatch.setattr(rem, "remediate_file", lambda fp, is_dropper=False: {"action": "weird", "path": fp})
    s = rem.clean_repo(repo)
    assert s["noop"] == [str(repo / "a.js")]
    assert any("vscode pass error" in m for m in rem.logs)

    class Exploding(FakeScanner):
        def scan_tree(self, repo):
            raise RuntimeError("scan boom")
    monkeypatch.setattr(scanner, "GuardScanner", Exploding)
    assert rem.clean_repo(repo)["noop"] == []


def test_vscode_finding_without_path(rem, tmp_path, monkeypatch):
    import scanner

    class F:
        severity = "critical"
        path = None
        where = None

    class S:
        def __init__(self, sig):
            self.vscode = self

        def is_safe_to_open(self, repo):
            return False, [F(), type("L", (), {"severity": "low"})()]

        def scan_tree(self, repo):
            return {}
    monkeypatch.setattr(scanner, "GuardScanner", S)
    assert rem.clean_repo(tmp_path)["config_cleaned"] == []


def test_restore_errors(rem, tmp_path):
    assert rem.restore("x")["error"] == "no quarantine index"
    f = write(tmp_path / "a.bin", b"x")
    rem.quarantine_file(f)
    assert rem.restore("nothing")["error"].startswith("no record")
    for line in rem.index.read_text().splitlines():
        (tmp_path / "home" / "quarantine" / json.loads(line)["backup"].split("/")[-1]).unlink()
    assert rem.restore(str(f))["error"] == "backup file missing"


def test_record_and_mkdir_failures(tmp_path, monkeypatch):
    from pathlib import Path
    real_mkdir = Path.mkdir
    monkeypatch.setattr(Path, "mkdir", lambda self, *a, **k: (_ for _ in ()).throw(OSError("ro")))
    r = RM.Remediator(tmp_path / "ro", log=lambda m: None)
    monkeypatch.setattr(Path, "mkdir", real_mkdir)
    r._record("x", tmp_path, None, None, None, "d")          # index dir missing -> swallowed
    assert not r.index.exists()


def test_main(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GUARD_HOME", str(tmp_path / "h"))
    assert RM._guard_home() == tmp_path / "h"
    assert RM.main([]) == 0
    assert RM.main(["restore"]) == 2
    assert RM.main(["restore", "x"]) == 0
    f = write(tmp_path / "repo" / "vite.config.js", INJECTED)
    assert RM.main(["clean", str(f)]) == 0
    assert '"neutralize"' in capsys.readouterr().out
    assert RM.main([str(tmp_path / "repo")]) == 0
    monkeypatch.chdir(tmp_path / "repo")
    assert RM.main(["clean"]) == 0
    monkeypatch.setattr(sys, "argv", ["remediator.py"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(ROOT / "remediator.py"), run_name="__main__")
    assert exc.value.code == 0


# ------------------------------------------------------------------ ed25519
# RFC 8032 section 7.1, TEST 1 and TEST 2
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("sk,pk,msg,sig", RFC)
def test_rfc8032_vectors(sk, pk, msg, sig):
    sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
    assert ED.publickey(sk) == pk
    assert ED.sign(msg, sk, pk) == sig
    assert ED.verify(sig, msg, pk)
    assert not ED.verify(sig, msg + b"x", pk)


def test_verify_rejects_malformed_and_malleable():
    sk, pk, _msg, sig = (bytes.fromhex(x) for x in RFC[0])
    assert not ED.verify(sig[:-1], b"", pk)
    assert not ED.verify(sig, b"", pk[:-1])
    assert not ED.verify((2).to_bytes(32, "little") + sig[32:], b"", pk)   # R off-curve -> exception path
    s = int.from_bytes(sig[32:], "little") + ED.L                 # same signature, S + L
    assert not ED.verify(sig[:32] + s.to_bytes(32, "little"), b"", pk)
    assert not ED.verify(sig, b"", ED.publickey(b"\x01" * 32))


def test_decodepoint_sign_bit_and_off_curve():
    pk = bytes.fromhex(RFC[0][1])
    P = ED._decodepoint(pk)
    assert ED._encodepoint(P) == pk
    flipped = pk[:-1] + bytes([pk[-1] ^ 0x80])
    assert ED._decodepoint(flipped)[0] == ED.q - P[0]
    with pytest.raises(ValueError, match="not on curve"):
        ED._decodepoint((2).to_bytes(32, "little"))


def test_self_test_main(capsys):
    runpy.run_path(str(ROOT / "ed25519_pure.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert out.count("True") == 3
