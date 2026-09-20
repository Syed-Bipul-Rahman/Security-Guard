# Security Guard — one binary, one command

A single self-contained `guard` binary for every employee machine (Linux/macOS/
Windows). It **detects and reports**; it never rewrites git history or force-pushes
— remediation stays a reviewed, human-triggered process.

## Install (one command)
```bash
curl -fsSL https://security.syedbipul.me/guard.sh | sudo bash
```
The bootstrap downloads the `guard` binary, verifies its SHA-256, installs it, and
runs `guard install` to start the always-on service (auto-start on boot, restart on
crash). Windows: `irm https://security.syedbipul.me/guard.ps1 | iex`.

## One command, everything (`guard <cmd>`)
| Command | What it does |
|---------|--------------|
| `guard scan <path>` | full tree scan: fingerprints, disguised droppers, `.vscode` auto-run, workflow baseline, **malicious deps** |
| `guard scan-git <path>` | the above **plus** every added line across git history |
| `guard open <path>` | pre-open check — safe to open this folder in VS Code? |
| `guard watch` | the always-on filesystem watcher (what the service runs) |
| `guard triage` | host IR triage (reboots / persistence / recon / SYN-flood / SSH) |
| `guard deps update` | refresh the GitHub malware-package blocklist (123k+ names) |
| `guard deps check <path>` | check a project's dependencies against the blocklist |
| `guard install` / `guard uninstall` | set up / remove the service |
| `guard version` | version |

You never run the individual `.py`/`.sh` files — they are internal modules the one
binary carries. Build the binary with `bash build/build.sh` (per OS; PyInstaller
does not cross-compile). Verified: a 9.3 MB standalone executable with all engines
and the malware blocklist bundled.

---

### Internals (for maintainers)
Detection engine for the sparktechagency supply-chain incident. It **detects and
reports**; it never rewrites git history or force-pushes.

## The attack, in one paragraph

A JS dropper was committed disguised as a font (`public/fonts/fa-solid-400.woff2`).
A `.vscode/tasks.json` task with `"runOn": "folderOpen"` plus
`"task.allowAutomaticTasks": true` in `settings.json` makes VS Code **auto-execute
that dropper the moment a developer opens the folder — no click required**. The
dropper injects an obfuscated C2 payload into build/config files (`vite.config.js`,
`postcss.config.js`, `src/server.ts`, …) and/or an `eval(proxyInfo)` IIFE that
pulls code from `auth-confirm-ten.vercel.app`, then commits under the victim's git
identity. That is why one attack shows up across ~30 developers and 38 repos: it
re-infects on every folder open. **The endpoint is the vector — hence Guard.**

## Files

| File | Purpose |
|------|---------|
| `signatures.json` | Canonical, machine-loadable signature set (the source of truth for the binary) |
| `signatures.yaml` | Same data in YAML, for CI/tooling that prefers it |
| `magic_bytes.py` | Detects JS/text droppers disguised with a binary extension (fake fonts/images) |
| `vscode_guard.py` | Pre-open guard: is it safe to open this repo in VS Code? (highest-value check) |
| `fingerprint_matcher.py` | Literal + regex + combo matching over file content **and** git diffs |
| `workflow_baseline.py` | Per-repo approved-workflow baseline; turns filename *signals* into confirmed *verdicts* |
| `scanner.py` | Orchestrator: runs all engines over a tree and (optionally) git history |
| `watcher.py` | **Always-on** filesystem watcher: detects clone/pull/checkout, new dirs, downloads → scans |
| `snapshot_store.py` | SQLite-backed path snapshot (disk, not RAM) so memory stays flat on huge trees |
| `memguard.py` | Computes a 10%-of-RAM budget; throttles the watcher if RSS approaches it |
| `hooks/guard-scan-hook.sh` | Global git hook body (post-checkout/merge/rewrite) — scans every clone/pull before you open it |
| `service/` | launchd (macOS) / systemd (Linux) / scheduled-task (Windows) definitions for boot-start + keep-alive |
| `install.sh` | Per-device installer: copies app, wires global git hooks, installs+starts the service |
| `testdata/` | Fixtures reproducing every technique + clean controls |

## Always-on agent (persistence + monitoring)

The `watcher.py` service is the "runs after restart/shutdown, watches the device"
layer. It is installed by `install.sh` as a launchd agent / systemd user service /
Windows scheduled task with **RunAtLoad + KeepAlive**, so it starts on login/boot
and restarts on crash.

What it watches (configurable in `<GUARD_HOME>/watcher.config.json`):

| Signal | How it's detected | Action |
|--------|-------------------|--------|
| repo **cloned** | new `.git/` directory appears | full scan + guard-open |
| **pull/fetch/checkout** | `.git/HEAD`, `FETCH_HEAD`, refs change | rescan repo |
| new **directory** | appears under a watch root | scan if it resolves to a repo |
| **downloaded file** | new `.woff2/.js/.env/...` outside any repo | single-file magic-byte + fingerprint scan |

Alerts are written to `<GUARD_HOME>/alerts.jsonl`; activity to `watcher.log`.
An optional `quarantine_cmd` in the config is invoked on a hit (reversible, logged).

Three hardening lessons already baked in from testing:
- **Watch-root boundary:** `_repo_root` never ascends above a watch root, so a
  download in a folder that happens to sit inside a large git repo (e.g. the home
  dir being a repo) can't trigger a scan of that whole outer repo.
- **Batched + debounced:** one clone triggers exactly one repo scan (not one per
  file), with a 30s per-repo debounce, so there's no alert storm.
- **Bounded memory (< 10% RAM):** the path snapshot lives in SQLite
  (`snapshot_store.py`), not a RAM dict, and is processed in 2000-path batches, so
  memory does not scale with tree size. File reads are capped (5 MB for text,
  header-only for binaries). `memguard.py` computes a budget of 10% of system RAM
  and throttles (gc + pause) if RSS approaches it; an opt-in `RLIMIT_AS` ceiling is
  a hard backstop. **Measured: ~30 MB peak scanning 30,600 files (~1.9% of 16 GB).**

### Two layers, defense in depth
1. **Git hooks** (`install.sh` sets `core.hooksPath` globally) catch clone/pull at
   the moment git runs — synchronous, before the editor opens.
2. **Watcher service** catches everything the hooks can't see: downloads, manual
   file drops, archive extraction, `git` invoked outside the hook path.

### Install / uninstall (run on each workstation)
```bash
./install.sh              # per-user install (recommended; no root needed)
tail -f ~/.guard/watcher.log
./install.sh --uninstall  # remove service + global hook wiring
```
`GUARD_HOME` defaults to `~/.guard`. Windows uses `service/windows/install-service.ps1`.

## Usage

```bash
# Is it safe to open this repo in VS Code? (run at clone time / pre-open hook)
python3 scanner.py guard-open /path/to/repo        # exit 1 = DO NOT OPEN

# Scan a working tree (fast, no git needed)
python3 scanner.py scan-tree /path/to/repo

# Scan the tree AND every added line across all commits/branches
python3 scanner.py scan-git /path/to/repo

# Machine-readable
python3 scanner.py scan-tree /path/to/repo --json
```

Exit codes: `0` clean, `1` infected (a `critical` finding), `2` usage/error.
Each module (`magic_bytes.py`, `vscode_guard.py`, `fingerprint_matcher.py`) also
runs standalone on individual files.

## Detection coverage (verified against `testdata/`)

| # | Technique | Engine | Signature IDs |
|---|-----------|--------|---------------|
| 1 | `.env` base64 C2 URL in `AUTH_API_KEY` | fingerprint | `env.auth.b64` |
| 2 | attack-added GitHub workflows | fingerprint | `wf.name`, `wf.added` |
| 3 | `eval(proxyInfo)` IIFE | fingerprint | `iife.combo`, `iife.full.regex`, `iife.marker.*` |
| 4 | obfuscated C2 payload | fingerprint | `payload.fp.1..7` |
| 5 | VS Code folderOpen auto-run dropper | vscode_guard | `vscode.autorun.*`, `vscode.task.*` |
| 6 | binary-disguised JS dropper (fake `.woff2`) | magic_bytes | magic-byte + text-body check |
| 2b | modified/added workflow vs. approved baseline | workflow_baseline | `record` once on a clean repo, then `diff` |

Verified behaviors:
- HEAD clean but payload in history → `scan-tree` clean, `scan-git` catches it.
- Real `.woff2` (correct `wOF2` magic) → no false positive.
- Clean source/config/settings → exit 0.
- JSONC (`.vscode` files with comments / trailing commas) is normalized before
  parsing, and unparseable configs **fail closed** (raw substring fallback).

## Design notes / how this differs from the old Python remediator

- **Detect + quarantine-flag only.** No history rewrite, no force-push, no
  full-`repo`-scope PAT on the endpoint. Those are the highest-blast-radius parts
  of the old script and are deliberately out of scope here.
- **Endpoint-first.** The `guard-open` mode is meant to run *before* VS Code opens
  a folder, which is where the compromise actually happens.
- **Signatures are data, not code.** Update `signatures.json`; the engines reload
  it. New IOCs/fingerprints require no code change.

## Next steps (not yet built)

1. **Lower-latency watching:** swap the stdlib polling loop for FSEvents (macOS) /
   inotify (Linux) / ReadDirectoryChangesW (Windows) or the `watchdog` package.
   Event handling is unchanged; only the source of events differs.
2. **Quarantine action:** implement `quarantine_cmd` as a reversible, logged move
   of suspect files to `<GUARD_HOME>/quarantine/` + a fleet alert.
3. **Central reporting:** ship `alerts.jsonl` to a SIEM / the analysis backend so
   the security team sees fleet-wide detections, not just per-device logs.
4. **Fold engines into the Guard binary** and its scheduled full-disk sweep, so
   the deployed artifact is a single signed binary (see the earlier installer plan).
5. **Signed signature updates** so a compromised host can't feed the fleet bad rules.
6. **Baseline provisioning:** record approved workflow baselines centrally (from a
   trusted CI checkout) and distribute them, rather than recording on each device.

## Boundaries (by design)
- Detect + report + optional reversible quarantine. **No** history rewrite, **no**
  force-push, **no** broad-scope GitHub token on the endpoint.
- The watcher stays within configured watch roots and caps any single scan at
  50k files, so it can't wander into the whole filesystem.
- Everything is transparent and uninstallable (`install.sh --uninstall`) — this is
  a mandatory but visible internal tool, not a hidden agent.
