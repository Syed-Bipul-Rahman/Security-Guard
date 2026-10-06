"""pre-push hook: block critical commits, chain user hooks, do not clobber hooksPath."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import scanner as S
from conftest import ROOT, write

HOOK = ROOT / "hooks" / "guard-scan-hook.sh"
INSTALL = ROOT / "install.sh"
ZERO = "0" * 40


def git(repo, *args, env=None):
    base = {
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(repo),
    }
    if env:
        base.update(env)
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=base)


def commit(repo, name, text, message):
    write(repo / name, text)
    git(repo, "add", name)
    git(repo, "commit", "-qm", message)
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         check=True, capture_output=True, text=True,
                         env={"HOME": str(repo), "PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1"}).stdout.strip()
    return sha


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    git(path, "config", "user.email", "t@example.org")
    git(path, "config", "user.name", "t")
    return path


def hook_env(tmp_path: Path, repo: Path) -> dict:
    env = os.environ.copy()
    env.update({
        "HOME": str(tmp_path / "home"),
        "GUARD_HOME": str(tmp_path / "guard-home"),
        "GUARD_APP": str(ROOT),
        "GIT_CEILING_DIRECTORIES": str(repo),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": os.environ.get("PATH", ""),
    })
    (tmp_path / "home").mkdir(exist_ok=True)
    return env


def place_hook(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(HOOK, dest)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC)
    return dest


def run_hook(hook: Path, repo: Path, env: dict, stdin: str = "", args=()):
    return subprocess.run(
        [str(hook), *args], cwd=str(repo), env=env, input=stdin,
        capture_output=True, text=True,
    )


# ---------------------------------------------------------------- scanner
def test_scan_push_skips_noise_and_allows_a_clean_update(tmp_path):
    repo = init_repo(tmp_path / "repo")
    first = commit(repo, "ok.js", "console.log(1)\n", "clean")
    second = commit(repo, "also.js", "console.log(2)\n", "also")
    stdin = "\n".join([
        "not-enough tokens",
        f"refs/heads/main {ZERO} refs/heads/main {ZERO}",
        f"refs/heads/main {second} refs/heads/main {first}",
    ])
    out = S.GuardScanner(S.load_signatures()).scan_push(repo, stdin)
    assert out["updates"] == 1 and not out["infected"] and out["error"] is None
    assert out["findings"] == []


def test_scan_push_new_branch_and_update_are_infected(tmp_path):
    repo = init_repo(tmp_path / "repo")
    first = commit(repo, "ok.js", "console.log(1)\n", "clean")
    payload = 'eval(proxyInfo)\n'
    second = commit(repo, "bad.js", payload, "bad")
    write(repo / "public" / "fonts" / "fa-solid-400.woff2", 'require("x")\n')
    git(repo, "add", "public/fonts/fa-solid-400.woff2")
    git(repo, "commit", "-qm", "font")
    font = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True,
                          env={"HOME": str(repo), "PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1"}).stdout.strip()
    sc = S.GuardScanner(S.load_signatures())
    new_branch = sc.scan_push(repo, f"refs/heads/feature {second} refs/heads/feature {ZERO}\n")
    assert new_branch["infected"] and new_branch["updates"] == 1
    assert any(x.get("sig_id") == "iife.marker.eval" for x in new_branch["findings"])

    update = sc.scan_push(repo, f"refs/heads/main {font} refs/heads/main {first}\n")
    assert update["infected"]
    paths = {x.get("path") for x in update["findings"]}
    assert "public/fonts/fa-solid-400.woff2" in paths
    assert any(x.get("severity") == "critical" and "woff2" in (x.get("path") or "") for x in update["findings"])


def test_scan_push_high_only_does_not_block(tmp_path):
    repo = init_repo(tmp_path / "repo")
    first = commit(repo, "ok.js", "console.log(1)\n", "clean")
    second = commit(repo, ".github/workflows/ci.yml", "on: push\n", "wf")
    out = S.GuardScanner(S.load_signatures()).scan_push(
        repo, f"refs/heads/main {second} refs/heads/main {first}\n")
    assert out["findings"] and not out["infected"]
    assert all(x.get("severity") != "critical" for x in out["findings"])


def test_scan_push_git_error_is_infected(tmp_path):
    out = S.GuardScanner(S.load_signatures()).scan_push(
        tmp_path, f"refs/heads/main {'a' * 40} refs/heads/main {'b' * 40}\n")
    assert out["infected"] and out["error"] and "git diff" in out["error"]


def test_scan_push_skips_unreadable_blob(tmp_path, monkeypatch):
    repo = init_repo(tmp_path / "repo")
    sha = commit(repo, "ok.js", "console.log(1)\n", "clean")
    real = subprocess.run

    def fake(cmd, **kw):
        if len(cmd) > 3 and cmd[3] == "show":
            return subprocess.CompletedProcess(cmd, 128, stdout=b"", stderr=b"missing")
        return real(cmd, **kw)

    monkeypatch.setattr(S.subprocess, "run", fake)
    out = S.GuardScanner(S.load_signatures()).scan_push(
        repo, f"refs/heads/main {sha} refs/heads/main {ZERO}\n")
    assert out["updates"] == 1 and not out["infected"] and out["findings"] == []


def test_print_push_variants(capsys):
    S._print_push({"repo": "r", "error": "boom", "infected": True, "findings": [
        {"severity": "critical", "path": "a.js", "sig_id": "s", "reason": "why"},
        {"severity": "high", "where": "diff", "desc": "d"},
        {"severity": "low", "detail": "only"},
        {"severity": "info"},
    ]})
    text = capsys.readouterr().out
    assert "push scan note: boom" in text and "RESULT: INFECTED" in text and "a.js" in text and "diff" in text
    S._print_push({"repo": "r", "infected": False})
    assert "RESULT: clean" in capsys.readouterr().out


def test_main_scan_push(monkeypatch, capsys, tmp_path):
    repo = init_repo(tmp_path / "repo")
    sha = commit(repo, "bad.js", "eval(proxyInfo)\n", "bad")
    stdin_path = tmp_path / "stdin.txt"
    stdin_path.write_text(f"refs/heads/main {sha} refs/heads/main {ZERO}\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["scanner.py", "scan-push", str(repo), "--stdin-file", str(stdin_path)])
    assert S.main() == 1
    assert "RESULT: INFECTED" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["scanner.py", "scan-push", str(repo), "--json", "--stdin-file", str(stdin_path)])
    assert S.main() == 1
    body = json.loads(capsys.readouterr().out)
    assert body["infected"] is True

    monkeypatch.setattr(sys, "argv", ["scanner.py", "scan-push", str(tmp_path)])
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"refs/heads/main {ZERO} refs/heads/main {ZERO}\n"))
    assert S.main() == 0
    assert "RESULT: clean" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["scanner.py", "scan-push", str(tmp_path), "--stdin-file", str(tmp_path / "missing")])
    assert S.main() == 2
    assert "cannot read" in capsys.readouterr().err


# ---------------------------------------------------------------- hook script
def test_pre_push_blocks_and_does_not_chain(tmp_path):
    repo = init_repo(tmp_path / "repo")
    sha = commit(repo, "bad.js", "eval(proxyInfo)\n", "bad")
    hook = place_hook(tmp_path / "hooks" / "pre-push")
    marker = tmp_path / "chained"
    user = tmp_path / "hooks" / "pre-push.guard-user"
    user.write_text("#!/bin/sh\necho chained > \"$GUARD_MARKER\"\n", encoding="utf-8")
    user.chmod(0o755)
    env = hook_env(tmp_path, repo)
    env["GUARD_MARKER"] = str(marker)
    proc = run_hook(hook, repo, env, stdin=f"refs/heads/main {sha} refs/heads/main {ZERO}\n", args=("origin", "url"))
    assert proc.returncode == 1
    assert "Push blocked" in proc.stderr and "GUARD_HOOK_BYPASS=1" in proc.stderr
    assert "--no-verify" in proc.stderr
    assert "RESULT: INFECTED" in proc.stdout
    assert not marker.exists()


def test_bypass_and_missing_scanner_still_chain(tmp_path):
    repo = init_repo(tmp_path / "repo")
    sha = commit(repo, "bad.js", "eval(proxyInfo)\n", "bad")
    hook = place_hook(tmp_path / "hooks" / "pre-push")
    user = tmp_path / "hooks" / "pre-push.guard-user"
    user.write_text("#!/bin/sh\ncat > \"$GUARD_MARKER\"\n", encoding="utf-8")
    user.chmod(0o755)
    env = hook_env(tmp_path, repo)
    marker = tmp_path / "marker"
    env["GUARD_MARKER"] = str(marker)
    env["GUARD_HOOK_BYPASS"] = "1"
    line = f"refs/heads/main {sha} refs/heads/main {ZERO}\n"
    proc = run_hook(hook, repo, env, stdin=line, args=("origin", "url"))
    assert proc.returncode == 0 and marker.read_text() == line

    marker.unlink()
    env.pop("GUARD_HOOK_BYPASS")
    env["GUARD_APP"] = str(tmp_path / "no-app")
    proc = run_hook(hook, repo, env, stdin=line)
    assert proc.returncode == 0 and marker.read_text() == line


def test_clean_push_chains_user_and_repo_hooks(tmp_path):
    repo = init_repo(tmp_path / "repo")
    sha = commit(repo, "ok.js", "console.log(1)\n", "clean")
    hook = place_hook(tmp_path / "hooks" / "pre-push")
    seen = tmp_path / "seen"
    user = tmp_path / "hooks" / "pre-push.guard-user"
    user.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$GUARD_SEEN\"\ncat >> \"$GUARD_SEEN\"\n",
        encoding="utf-8")
    user.chmod(0o755)
    repo_hook = repo / ".git" / "hooks" / "pre-push"
    place_hook(repo_hook)  # contains the marker, must be skipped (would recurse / re-scan)
    repo_hook.write_text("#!/bin/sh\n# GUARD_SCAN_HOOK\necho skip-me >> \"$GUARD_SEEN\"\n", encoding="utf-8")
    repo_hook.chmod(0o755)
    env = hook_env(tmp_path, repo)
    env["GUARD_SEEN"] = str(seen)
    line = f"refs/heads/main {sha} refs/heads/main {ZERO}\n"
    proc = run_hook(hook, repo, env, stdin=line, args=("origin",))
    assert proc.returncode == 0, proc.stderr
    text = seen.read_text()
    assert text.startswith("origin\n") and sha in text and "skip-me" not in text
    user.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
    user.chmod(0o755)
    proc = run_hook(hook, repo, env, stdin=line, args=("origin",))
    assert proc.returncode == 3


def test_nonexecutable_user_hook_is_skipped(tmp_path):
    repo = init_repo(tmp_path / "repo")
    sha = commit(repo, "ok.js", "console.log(1)\n", "clean")
    hook = place_hook(tmp_path / "hooks" / "pre-push")
    user = tmp_path / "hooks" / "pre-push.guard-user"
    user.write_text("#!/bin/sh\necho no\n", encoding="utf-8")
    user.chmod(0o644)
    env = hook_env(tmp_path, repo)
    proc = run_hook(hook, repo, env, stdin=f"refs/heads/main {sha} refs/heads/main {ZERO}\n")
    assert proc.returncode == 0 and "RESULT: clean" in proc.stdout


def test_post_checkout_reports_and_exits_zero(tmp_path):
    repo = init_repo(tmp_path / "repo")
    commit(repo, "bad.js", "eval(proxyInfo)\n", "bad")
    hook = place_hook(tmp_path / "hooks" / "post-checkout")
    marker = tmp_path / "after"
    user = tmp_path / "hooks" / "post-checkout.guard-user"
    user.write_text("#!/bin/sh\nprintf '%s' \"$3\" > \"$GUARD_MARKER\"\n", encoding="utf-8")
    user.chmod(0o755)
    env = hook_env(tmp_path, repo)
    env["GUARD_MARKER"] = str(marker)
    proc = run_hook(hook, repo, env, args=("old", "new", "1"))
    assert proc.returncode == 0
    assert "Supply-chain signatures detected" in proc.stderr
    assert marker.read_text() == "1"


def test_hook_outside_a_repo_exits_zero(tmp_path):
    hook = place_hook(tmp_path / "pre-push")
    env = hook_env(tmp_path, tmp_path)
    proc = run_hook(hook, tmp_path, env, stdin="ignored\n")
    assert proc.returncode == 0


def test_git_push_is_rejected_then_allowed_with_bypass(tmp_path):
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
    repo = init_repo(tmp_path / "repo")
    commit(repo, "bad.js", "eval(proxyInfo)\n", "bad")
    git(repo, "remote", "add", "origin", str(bare))
    hooks = tmp_path / "githooks"
    place_hook(hooks / "pre-push")
    env = hook_env(tmp_path, repo)
    blocked = subprocess.run(
        ["git", "-C", str(repo), "-c", f"core.hooksPath={hooks}", "push", "origin", "HEAD:refs/heads/main"],
        capture_output=True, text=True, env=env,
    )
    assert blocked.returncode != 0
    assert "Push blocked" in blocked.stderr
    assert subprocess.run(["git", "--git-dir", str(bare), "rev-parse", "refs/heads/main"],
                          capture_output=True).returncode != 0

    env["GUARD_HOOK_BYPASS"] = "1"
    allowed = subprocess.run(
        ["git", "-C", str(repo), "-c", f"core.hooksPath={hooks}", "push", "origin", "HEAD:refs/heads/main"],
        capture_output=True, text=True, env=env,
    )
    assert allowed.returncode == 0, allowed.stderr


# ---------------------------------------------------------------- install.sh
def _install_env(tmp_path: Path) -> tuple[dict, Path]:
    home = tmp_path / "home"
    home.mkdir()
    guard = tmp_path / "guard"
    env = os.environ.copy()
    env.update({
        "HOME": str(home),
        "GUARD_HOME": str(guard),
        "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GUARD_INSTALL_SKIP_SERVICE": "1",
        "PATH": os.environ.get("PATH", ""),
    })
    return env, guard


def _git_config(env, *args):
    return subprocess.run(["git", "config", "--global", *args], capture_output=True, text=True, env=env)


def test_install_sets_hooks_path_when_unset(tmp_path):
    env, guard = _install_env(tmp_path)
    proc = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert _git_config(env, "--get", "core.hooksPath").stdout.strip() == str(guard / "githooks")
    assert (guard / "githooks" / "pre-push").is_file()
    assert not (guard / "chained-hooks-path").exists()
    text = (guard / "githooks" / "pre-push").read_text(encoding="utf-8")
    assert "GUARD_SCAN_HOOK" in text and "pre-push" in text


def test_install_chains_existing_hooks_path_and_uninstall_restores(tmp_path):
    env, guard = _install_env(tmp_path)
    foreign = tmp_path / "their-hooks"
    foreign.mkdir()
    original = foreign / "pre-push"
    original.write_text("#!/bin/sh\necho user-hook\n", encoding="utf-8")
    original.chmod(0o755)
    assert _git_config(env, "core.hooksPath", str(foreign)).returncode == 0

    proc = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert _git_config(env, "--get", "core.hooksPath").stdout.strip() == str(foreign)
    assert "left unchanged" in proc.stdout
    assert (foreign / "pre-push.guard-user").read_text(encoding="utf-8") == "#!/bin/sh\necho user-hook\n"
    assert "GUARD_SCAN_HOOK" in (foreign / "pre-push").read_text(encoding="utf-8")
    assert (guard / "chained-hooks-path").read_text(encoding="utf-8").strip() == str(foreign)

    again = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env)
    assert again.returncode == 0, again.stderr
    assert (foreign / "pre-push.guard-user").read_text(encoding="utf-8") == "#!/bin/sh\necho user-hook\n"

    removed = subprocess.run(["bash", str(INSTALL), "--uninstall"], capture_output=True, text=True, env=env)
    assert removed.returncode == 0, removed.stderr
    assert (foreign / "pre-push").read_text(encoding="utf-8") == "#!/bin/sh\necho user-hook\n"
    assert not (foreign / "pre-push.guard-user").exists()
    assert not (guard / "chained-hooks-path").exists()
    assert _git_config(env, "--get", "core.hooksPath").stdout.strip() == str(foreign)


def test_install_leaves_nondirectory_hooks_path(tmp_path):
    env, guard = _install_env(tmp_path)
    assert _git_config(env, "core.hooksPath", str(tmp_path / "not-a-dir")).returncode == 0
    proc = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "not a directory" in proc.stdout
    assert _git_config(env, "--get", "core.hooksPath").stdout.strip() == str(tmp_path / "not-a-dir")
    assert (guard / "githooks" / "pre-push").is_file()


def test_install_refreshes_when_hooks_path_is_already_ours(tmp_path):
    env, guard = _install_env(tmp_path)
    ours = guard / "githooks"
    assert _git_config(env, "core.hooksPath", str(ours)).returncode == 0
    proc = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert _git_config(env, "--get", "core.hooksPath").stdout.strip() == str(ours)
    assert not (guard / "chained-hooks-path").exists()
    assert (ours / "post-merge").is_file() and (ours / "pre-push").is_file()
