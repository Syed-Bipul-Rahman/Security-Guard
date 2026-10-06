"""`guard av` in the Rust binary against guard_av (Python), side by side.

Each test builds the same files, runs `guard.py av ...` and the Rust binary,
and requires the same output, exit code and files. Scan timings and the random
quarantine ids are the only things normalised.
"""

from __future__ import annotations

import bz2
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import samples
from conftest import EXEC, READ, WRITE, build_elf, build_pe, gz, make_tar, make_zip, random_bytes, write
from rustbin import WINDOWS, run_python, run_rust, rust_guard  # noqa: F401  (fixture)

HAVE_CORE = subprocess.run([sys.executable, "-c", "import guard_core"], capture_output=True).returncode == 0
needs_core = pytest.mark.skipif(not HAVE_CORE, reason="YARA needs guard_core in the Python build")

YARA = r"""
rule DropperMarker : dropper {
    meta:
        verdict = "malicious"
        whole_file = true
        description = "drops the second stage"
    strings:
        $url = "evil.example/stage2"
    condition:
        any of them
}

rule LooseHunt : hunting research {
    meta:
        verdict = "nonsense"
    strings:
        $a = "hunting-marker"
    condition:
        $a
}

rule Quiet { strings: $q = "quiet-marker" condition: $q }
"""

EXTRA_RULES = {"rules": [{
    "id": "test.marker", "name": "Test.Marker", "verdict": "suspicious",
    "description": "test marker", "filetypes": ["textual"], "exclude_extensions": [".md"],
    "strings": {"$m": {"text": "guard-test-marker", "nocase": True}, "$w": {"text": "wide-mark", "wide": True}},
    "condition": {"any": "them"},
}]}


def text(b: bytes) -> str:
    return b.decode("utf-8", "replace").replace("\r\n", "\n")


def evil_pe(extra: bytes = b"") -> bytes:
    return build_pe(
        sections=[(b"UPX0", EXEC | WRITE | READ, random_bytes(4096)), (b".rsrc", READ, b"\0" * 64)],
        entry=0x9000, extra=b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0" + extra)


def corpus(root: Path) -> Path:
    """Samples, clean files, archives, duplicates and odd names."""
    d = root / "corpus"
    for name, (_, data) in {**samples.decoded(samples.MALICIOUS), **samples.decoded(samples.SUSPICIOUS)}.items():
        write(d / "samples" / name, data)
    write(d / "eicar.com", samples.eicar())
    write(d / "eicar-crlf.txt", samples.eicar() + b"\r\n")
    write(d / "clean" / "README.md", "# hello\nguard-test-marker in docs is fine\n")
    write(d / "clean" / "app.py", "print('hello')\n")
    write(d / "clean" / "empty", b"")
    write(d / "clean" / "noise.bin", random_bytes(5000, seed=3))
    write(d / "clean" / "notes.txt", "guard-test-marker\n")
    write(d / "clean" / "wide.dat", "xx wide-mark".encode("utf-16-le"))
    write(d / "clean" / "drop.txt", "GET http://evil.example/stage2 HTTP/1.1 hunting-marker quiet-marker\n")
    # same content under another name and in another folder (the result cache)
    webshell = samples.decoded(samples.MALICIOUS)["webshell_eval.php"][1]
    write(d / "dup" / "a" / "webshell_eval.php", webshell)
    write(d / "dup" / "b" / "other.php", webshell)
    # heuristics
    write(d / "pe" / "svch0st.exe", evil_pe())
    write(d / "pe" / "invoice.pdf.exe", build_pe())
    write(d / "pe" / "report.pdf", build_pe())
    write(d / "pe" / "photo       .scr", build_pe())
    write(d / "pe" / "résumé‮txt.exe", build_pe())
    write(d / "pe" / "zero​width.txt", "hi\n")
    write(d / "elf" / "tool", build_elf(b"/etc/ld.so.preload" + random_bytes(8192, seed=5)))
    # archives
    rev = samples.decoded(samples.MALICIOUS)["revshell.sh"][1]
    inner = make_zip({"payload/run.sh": rev, "ok.txt": b"fine"})
    write(d / "arch" / "nested.zip", make_zip({"inner.zip": inner, "dir/": b"", "eicar.com": samples.eicar()}))
    write(d / "arch" / "enc.zip", make_zip({"secret.bin": b"x" * 100, "plain.sh": rev}, encrypt_flag={"secret.bin"}))
    bomb = zipfile.ZipFile(d / "arch" / "bomb.zip", "w", zipfile.ZIP_DEFLATED)
    bomb.writestr("zeros.bin", b"\0" * (3 * 1024 * 1024))
    bomb.writestr("eicar.com", samples.eicar())
    bomb.close()
    write(d / "arch" / "bundle.tar.gz", gz(make_tar({"a/x.sh": rev, "a/y.txt": b"ok"})))
    write(d / "arch" / "plain.tar", make_tar({"evil.php": webshell}))
    write(d / "arch" / "bundle.tar.bz2", bz2.compress(make_tar({"m.ps1": samples.decoded(samples.MALICIOUS)["amsi.ps1"][1]})))
    write(d / "arch" / "one.sh.gz", gz(rev))
    write(d / "arch" / "one.py.bz2", bz2.compress(samples.decoded(samples.MALICIOUS)["revshell.py"][1]))
    write(d / "arch" / "one.php.xz", lzma.compress(webshell))
    write(d / "arch" / "zeros.gz", gz(b"\0" * (40 * 1024 * 1024)))
    write(d / "arch" / "broken.zip", b"PK\x03\x04garbage")
    # never scanned: VCS internals, symlinks
    write(d / ".git" / "objects" / "evil.php", webshell)
    if not WINDOWS:
        os.symlink(d / "eicar.com", d / "link.com")
        os.symlink(d / "samples", d / "linkdir")
    return d


def norm_json(out: bytes) -> dict:
    data = json.loads(out)
    assert isinstance(data["summary"].pop("elapsed_sec"), float)
    return data


def both(tmp_path, rust_guard, *args, env=None, cwd=None):
    env = {"GUARD_HOME": str(tmp_path / "home"), **(env or {})}
    return run_python(*args, env=env, cwd=cwd), run_rust(rust_guard, *args, env=env, cwd=cwd)


def same(py, rs, stdout=True):
    assert rs.returncode == py.returncode, (py.stderr, rs.stderr)
    if stdout:
        assert text(rs.stdout) == text(py.stdout)


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    root = tmp_path_factory.mktemp("av")
    return corpus(root)


# -------------------------------------------------------------------- scan
@pytest.mark.parametrize("flags", [[], ["--no-archives"], ["--no-heuristics"], ["--fail-on-suspicious"]])
def test_scan_json_matches(tmp_path, rust_guard, tree, flags):
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree), "--json", *flags)
    assert rs.returncode == py.returncode == 1, (py.stderr, rs.stderr)
    assert norm_json(rs.stdout) == norm_json(py.stdout)


def test_scan_text_matches(tmp_path, rust_guard, tree):
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / "samples"), str(tree / "arch"),
                  str(tree / "eicar.com"))
    same(py, rs)
    assert "[MALICIOUS]" in text(rs.stdout)


def test_scan_relative_paths_and_dot(tmp_path, rust_guard, tree):
    py, rs = both(tmp_path, rust_guard, "av", "scan", ".", "./dup//a/", "--json", cwd=tree)
    same(py, rs, stdout=False)
    assert norm_json(rs.stdout) == norm_json(py.stdout)


@pytest.mark.parametrize("target,rc", [("clean", 0), ("samples/miner.json", 0), ("eicar.com", 1)])
def test_scan_exit_codes(tmp_path, rust_guard, tree, target, rc):
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / target))
    same(py, rs)
    assert rs.returncode == rc
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / target), "--fail-on-suspicious")
    same(py, rs)


def test_scan_missing_path(tmp_path, rust_guard, tree):
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / "eicar.com"), str(tmp_path / "nope"), "zzz")
    same(py, rs)
    assert rs.returncode == 2 and text(rs.stderr) == text(py.stderr)


@pytest.mark.skipif(WINDOWS or os.geteuid() == 0, reason="needs a POSIX non-root user to make a file unreadable")
def test_scan_unreadable_file(tmp_path, rust_guard):
    f = write(tmp_path / "t" / "locked.txt", "x")
    f.chmod(0)
    try:
        py, rs = both(tmp_path, rust_guard, "av", "scan", str(tmp_path / "t"), "--json")
    finally:
        f.chmod(0o600)
    assert norm_json(rs.stdout) == norm_json(py.stdout)
    assert "PermissionError" in text(rs.stdout)


def sig_dir(root: Path, tree: Path, yara: bool) -> Path:
    s = root / "sigs"
    write(s / "rules-extra.json", json.dumps(EXTRA_RULES))
    clean_sha = __import__("hashlib").sha256(b"print('hello')\n").hexdigest()
    write(s / "hashes-local.txt", f"# local list\n{clean_sha}  Local.Bad.App\nnot-a-hash x\n")
    write(s / "hashes-more.json", json.dumps({"entries": [{"md5": __import__("hashlib").md5(b"fine").hexdigest(),
                                                          "name": "Fine.But.Listed", "verdict": "suspicious"}]}))
    write(s / "allowlist-team.json", json.dumps({
        "paths": ["*/samples/bind.sh", "*/pe/report.pdf"],
        "rules": ["HackTool.ReverseShell.Python", "yara:community.Quiet"]}))
    if yara:
        write(s / "community.yar", YARA)
    return s


@pytest.mark.parametrize("yara", [False, pytest.param(True, marks=needs_core)])
def test_scan_with_signatures(tmp_path, rust_guard, tree, yara):
    s = sig_dir(tmp_path, tree, yara)
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree), "--json", "--signatures", str(s))
    assert rs.returncode == py.returncode
    got, want = norm_json(rs.stdout), norm_json(py.stdout)
    assert got == want
    names = {r["threat"] for r in got["results"]}
    assert "Local.Bad.App" in names and "Test.Marker" in names
    if yara:
        assert "DropperMarker" in names
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / "clean"), "--signatures", str(s))
    same(py, rs)


def test_scan_reads_guard_home_av(tmp_path, rust_guard, tree):
    write(tmp_path / "home" / "av" / "rules-extra.json", json.dumps(EXTRA_RULES))
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / "clean"))
    same(py, rs)
    assert "Test.Marker" in text(rs.stdout)


# ------------------------------------------------------------------- rules
@pytest.mark.parametrize("yara", [False, pytest.param(True, marks=needs_core)])
def test_rules_listing(tmp_path, rust_guard, tree, yara):
    py, rs = both(tmp_path, rust_guard, "av", "rules")
    same(py, rs)
    s = sig_dir(tmp_path / "home", tree, yara)
    s.rename(tmp_path / "home" / "av")
    py, rs = both(tmp_path, rust_guard, "av", "rules")
    same(py, rs)


BAD_RULES = {
    "missing": [{"id": "x", "name": "n"}],
    "verdict": [{"id": "x", "name": "n", "condition": "$a", "verdict": "bogus"}],
    "clean": [{"id": "x", "name": "n", "condition": "$a", "verdict": "clean"}],
    "strings": [{"id": "x", "name": "n", "condition": "$a", "strings": ["no"]}],
    "undefined": [{"id": "x", "name": "n", "condition": {"all": ["$a", "$b"]}, "strings": {"$a": {"text": "a"}}}],
    "wildcard": [{"id": "x", "name": "n", "condition": {"any": ["$z*"]}, "strings": {"$a": {"text": "a"}}}],
    "hex": [{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D ?Z"}}}],
    "hexgroup": [{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D | 5A"}}}],
    "jump": [{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D [x] 5A"}}}],
    "empty": [{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"text": ""}}}],
    "nostring": [{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"nope": 1}}}],
    "atleast": [{"id": "x", "name": "n", "condition": {"at_least": 0, "of": "them"}, "strings": {"$a": {"text": "a"}}}],
    "andor": [{"id": "x", "name": "n", "condition": {"and": []}, "strings": {"$a": {"text": "a"}}}],
    "at": [{"id": "x", "name": "n", "condition": {"at": "$q", "offset": 0}, "strings": {"$a": {"text": "a"}}}],
    "count": [{"id": "x", "name": "n", "condition": {"count": "$a", "min": "2"}, "strings": {"$a": {"text": "a"}}}],
    "size": [{"id": "x", "name": "n", "condition": {"filesize_max": 1.5}}],
    "op": [{"id": "x", "name": "n", "condition": {"near": "$a"}, "strings": {"$a": {"text": "a"}}}],
    "badcond": [{"id": "x", "name": "n", "condition": 5}],
    "dup": [{"id": "x", "name": "n", "condition": {"filesize_min": 1}}, {"id": "x", "name": "m", "condition": {"filesize_min": 1}}],
    "notobj": ["just a string"],
}


def test_rules_validate(tmp_path, rust_guard):
    files = []
    good = write(tmp_path / "rules-good.json", json.dumps(EXTRA_RULES))
    files.append(str(good))
    for name, body in BAD_RULES.items():
        files.append(str(write(tmp_path / f"rules-{name}.json", json.dumps({"rules": body}))))
    files.append(str(tmp_path / "missing.json"))
    py, rs = both(tmp_path, rust_guard, "av", "rules", "--validate", *files)
    same(py, rs)
    assert rs.returncode == 2
    assert text(rs.stdout).count("FAIL") == len(BAD_RULES) + 1


@needs_core
def test_rules_validate_yara(tmp_path, rust_guard):
    good = write(tmp_path / "good.yar", YARA)
    warn = write(tmp_path / "warn.yara", 'rule W { strings: $a = "ab" condition: $a }')
    bad = write(tmp_path / "bad.yar", "rule Broken { condition: nope }")
    for f in (good, warn, bad):
        py, rs = both(tmp_path, rust_guard, "av", "rules", "--validate", str(f))
        same(py, rs)


# -------------------------------------------------------------------- hash
def test_hash(tmp_path, rust_guard, tree):
    py, rs = both(tmp_path, rust_guard, "av", "hash", str(tree / "eicar.com"), str(tree / "clean" / "empty"),
                  str(tmp_path / "missing"), str(tree / "clean"))
    same(py, rs)
    if not WINDOWS:
        assert text(rs.stderr) == text(py.stderr)


# --------------------------------------------------------------- quarantine
ID = re.compile(r"[0-9a-f]{32}")


def scrub(s: str, *pairs) -> str:
    for a, b in pairs:
        s = s.replace(a, b)
    s = ID.sub("<id>", s)
    return re.sub(r'"quarantined_at": "[^"]+"', '"quarantined_at": "<t>"', s)


def test_quarantine_flow(tmp_path, rust_guard, tree):
    runs = {}
    for who in ("py", "rs"):
        work = tmp_path / who / "files"
        shutil.copytree(tree / "samples", work / "samples")
        shutil.copytree(tree / "arch", work / "arch")
        shutil.copy(tree / "eicar.com", work)
        vault = tmp_path / who / "vault"
        args = ["av", "--vault", str(vault), "scan", str(work), "--quarantine"]
        env = {"GUARD_HOME": str(tmp_path / "home")}
        r = run_python(*args, env=env) if who == "py" else run_rust(rust_guard, *args, env=env)
        runs[who] = (work, vault, r)
    (pw, pv, pr), (rw, rv, rr) = runs["py"], runs["rs"]
    assert rr.returncode == pr.returncode == 1
    sub = lambda s, work: scrub(s, (str(work.resolve()), "<work>"), (str(work), "<work>"))  # noqa: E731
    assert sub(text(rr.stdout), rw) == sub(text(pr.stdout), pw)
    assert sorted(p.name for p in rw.rglob("*")) == sorted(p.name for p in pw.rglob("*"))
    assert "quarantined" in text(rr.stdout)

    def listing(vault, work, exe=None):
        args = ["av", "--vault", str(vault), "quarantine", "list"]
        r = run_rust(exe, *args) if exe else run_python(*args)
        assert r.returncode == 0
        # scrub after parsing: in the JSON text Windows paths are escaped
        items = json.loads(text(r.stdout))
        return [json.loads(sub(json.dumps({k: sub(v, work) if isinstance(v, str) else v
                                           for k, v in e.items()}), work)) for e in items]

    py_list, rs_list = listing(pv, pw), listing(rv, rw, rust_guard)
    key = lambda e: e["original_path"]  # noqa: E731
    assert sorted(rs_list, key=key) == sorted(py_list, key=key)
    assert all("key" not in e for e in rs_list)

    # each build restores what the other quarantined
    py_ids = [e["id"] for e in json.loads(run_python("av", "--vault", str(pv), "quarantine", "list").stdout)]
    rs_ids = [e["id"] for e in json.loads(run_rust(rust_guard, "av", "--vault", str(rv), "quarantine", "list").stdout)]
    r = run_rust(rust_guard, "av", "--vault", str(pv), "quarantine", "restore", py_ids[0])
    assert r.returncode == 0 and text(r.stdout).startswith("restored ")
    r = run_python("av", "--vault", str(rv), "quarantine", "restore", rs_ids[0])
    assert r.returncode == 0 and text(r.stdout).startswith("restored ")

    # restore to a new place, refuse to overwrite, then delete
    for vault, ids, exe in ((pv, py_ids, None), (rv, rs_ids, rust_guard)):
        dest = tmp_path / ("out-rs" if exe else "out-py") / "x.bin"
        args = ["av", "--vault", str(vault), "quarantine", "restore", ids[1], "--to", str(dest)]
        r = run_rust(exe, *args) if exe else run_python(*args)
        assert r.returncode == 0 and text(r.stdout) == f"restored {dest}\n"
    py, rs = both(tmp_path, rust_guard, "av", "--vault", str(pv), "quarantine", "restore", py_ids[2], "--to", str(dest))
    same(py, rs)
    assert rs.returncode == 2 and text(rs.stderr) == text(py.stderr)
    py = run_python("av", "--vault", str(pv), "quarantine", "delete", py_ids[2])
    rs = run_rust(rust_guard, "av", "--vault", str(rv), "quarantine", "delete", rs_ids[2])
    assert (py.returncode, rs.returncode) == (0, 0)
    assert scrub(text(rs.stdout)) == scrub(text(py.stdout)) == "deleted <id>\n"


@pytest.mark.parametrize("args", [
    ["list"], ["delete", "0" * 32], ["restore", "../../etc"], ["restore", "F" * 32], ["delete", "zz"],
])
def test_quarantine_errors(tmp_path, rust_guard, args):
    py, rs = both(tmp_path, rust_guard, "av", "--vault", str(tmp_path / "v"), "quarantine", *args)
    same(py, rs)
    assert text(rs.stderr) == text(py.stderr)


def test_quarantine_integrity_check(tmp_path, rust_guard, tree):
    vault = tmp_path / "v"
    work = tmp_path / "w"
    work.mkdir()
    shutil.copy(tree / "eicar.com", work / "eicar.com")
    r = run_python("av", "--vault", str(vault), "scan", str(work), "--quarantine")
    assert r.returncode == 1
    item = next(vault.glob("*.bin"))
    item.write_bytes(b"tampered" + item.read_bytes()[8:])
    py, rs = both(tmp_path, rust_guard, "av", "--vault", str(vault), "quarantine", "restore", item.stem)
    same(py, rs)
    assert rs.returncode == 2 and text(rs.stderr) == text(py.stderr)


# ------------------------------------------------------------------- usage
@pytest.mark.parametrize("args", [
    [], ["bogus"], ["scan"], ["scan", ".", "--bogus"], ["hash"], ["quarantine"], ["quarantine", "nope"],
    ["quarantine", "restore"], ["rules", "--validate"], ["scan", "--signatures"], ["--vault"],
])
def test_usage_errors(tmp_path, rust_guard, args):
    py, rs = both(tmp_path, rust_guard, "av", *args)
    assert rs.returncode == py.returncode == 2, (args, py.stderr, rs.stderr)


@pytest.mark.parametrize("args", [["-h"], ["scan", "-h"], ["quarantine", "-h"]])
def test_help(tmp_path, rust_guard, args):
    py, rs = both(tmp_path, rust_guard, "av", *args)
    assert rs.returncode == py.returncode == 0
    assert text(rs.stdout).startswith("usage: guard av")


def test_abbreviated_options(tmp_path, rust_guard, tree):
    py, rs = both(tmp_path, rust_guard, "av", "scan", str(tree / "samples"), "--js", "--no-h", "--fail")
    assert rs.returncode == py.returncode == 1
    assert norm_json(rs.stdout) == norm_json(py.stdout)
