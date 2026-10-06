# Guard — antivirus & supply-chain malware agent

[![tests](https://github.com/Syed-Bipul-Rahman/Security-Guard/actions/workflows/tests.yml/badge.svg)](https://github.com/Syed-Bipul-Rahman/Security-Guard/actions/workflows/tests.yml)
![coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![false positives](https://img.shields.io/badge/false%20positives-0-brightgreen)
![version](https://img.shields.io/badge/version-2.0.0-blue)

One self-contained `guard` binary for every user machine (**Linux / macOS /
Windows**). It runs always-on and combines two engines:

- a **general antivirus engine** (`guard_av`) — hash signatures, YARA-style
  rules, static heuristics and recursive archive scanning for webshells, reverse
  shells, credential dumpers, droppers, malicious macros, packed injectors,
  miners and more;
- **supply-chain malware detection** for the fake-font dropper / `.vscode`
  auto-run / obfuscated `eval` C2 family, including payloads hidden in git history.

It **auto-removes** what it finds — excising injected code while keeping your
real files, or moving whole-file malware into a neutered quarantine — and **warns
the user** with a desktop notification, like a consumer antivirus. It
self-updates over the air and can report status to an optional, self-hostable
dashboard.

- **Repo:** https://github.com/Syed-Bipul-Rahman/Security-Guard
- **Releases:** https://github.com/Syed-Bipul-Rahman/Security-Guard/releases
- **Install site:** https://security.sparktech.agency
- **Demo dashboard:** https://security-guard-fkt3.vercel.app

---

## What's new in v2.0.0

- **New antivirus engine (`guard_av`)** — layered hash DB → YARA-style rules →
  heuristics → archive scanning, used automatically by the watcher, `guard scan`
  and `guard clean`, and directly via `guard av ...`. See
  [Antivirus engine](#antivirus-engine-guard_av-v2).
- **Neutered quarantine vault** — whole-file threats are stored encrypted with a
  per-item key and restored only after a SHA-256 integrity check.
- **422 tests, 100% line + branch coverage** of the detection and remediation
  stack, plus a **zero-false-positive** gate (Python stdlib, system binaries,
  an adversarial benign corpus and this repo). CI runs on every push; releases
  are only built when it passes.
- **Fixes:** malformed `.vscode/settings.json` / `tasks.json` no longer slip past
  the pre-open check (it now fails closed as intended), and OTA signature
  verification rejects non-canonical Ed25519 signatures (RFC 8032).

---

## Install (one command)

**macOS / Linux** (installs the always-on service, auto-starts on boot):
```bash
curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash
```

**Windows** (run in an **elevated** PowerShell):
```powershell
irm https://security.sparktech.agency/guard.ps1 | iex
```

The installer downloads the right binary for your OS/arch, verifies its SHA-256,
installs it, registers the auto-start watcher service, trusts Guard in Microsoft
Defender, and (Windows) auto-configures Sysmon. Supported targets: `linux-x64`,
`linux-arm64`, `darwin-arm64`, `windows-x64`, `windows-arm64`.

Uninstall anytime: `sudo guard uninstall` (or `guard uninstall` on Windows).

---

## Features

- **Antivirus engine** — exact hash signatures, 15 high-confidence YARA-style
  rules, static heuristics (packers, injection APIs, obfuscation, disguised
  filenames) and bomb-safe zip / tar / gzip / bzip2 / xz scanning. Add your own
  rules, hashes and allowlists without touching code.
- **Always-on watcher** — detects repo clones, pulls/checkouts, new project dirs,
  and downloaded files, and scans them automatically. Bounded to <10% RAM.
- **Auto-remediation (default on)** — on a critical hit it *removes the threat*,
  not just alerts:
  - **excises** an injected malicious IIFE from a real source file (keeps the
    imports/config around it),
  - **quarantines** whole-file droppers (a fake `.woff2` that's actually JS) and
    whole-file malware found by the antivirus engine,
  - **strips** `task.allowAutomaticTasks` and `folderOpen` dropper tasks from
    `.vscode`.
  Every change is backed up first and is reversible (`guard restore`).
- **Desktop notifications** — a "Threat neutralized" popup on detection (Windows
  alert into the active session, macOS Notification Center, Linux `notify-send`).
- **OTA auto-update** — the agent checks a signed manifest and updates itself
  (Ed25519-verified, fail-closed, downgrade-protected). No manual step.
- **Malicious-dependency check** — versions matched against a GitHub-advisory
  malware blocklist (120k+ names).
- **Optional telemetry** — machines can report install + status (clean or
  infected) to a **configurable, self-hostable** dashboard endpoint; point it at
  your own server or leave it off.
- **Host IR triage** — reboot/persistence/recon/flood forensics, OS-native.
- **Kernel telemetry (Windows)** — auto-configures Microsoft Sysmon.
- **macOS permissions helper** — raises the native "Allow" prompts for Desktop /
  Documents / Downloads / removable disks.

---

## Commands

| Command | What it does |
|---|---|
| `guard scan <path>` | full tree scan: antivirus engine, fingerprints, disguised droppers, `.vscode` auto-run, workflows, malicious deps |
| `guard scan-git <path>` | the above **plus** every added line across git history |
| `guard open <path>` | pre-open check — is it safe to open this folder in VS Code? |
| `guard av scan <path...>` | general antivirus scan: hash DB + YARA-style rules + heuristics + archives (`--json`, `--quarantine`, `--fail-on-suspicious`) |
| `guard av quarantine list\|restore <id>\|delete <id>` | manage the neutered (encrypted-at-rest) quarantine vault |
| `guard av rules [--validate FILE]` | list the loaded signatures / validate a custom rule file |
| `guard av hash <file>` | print SHA-256 / SHA-1 / MD5 |
| `guard clean <path>` | **remove** injected malware in place (excise/quarantine), backing up first |
| `guard restore <path>` | undo a clean/quarantine from the backup store |
| `guard watch` | the always-on filesystem watcher (what the service runs) |
| `guard triage` | host IR triage (reboots / persistence / recon / flood) |
| `guard sensor` | Windows endpoint sensor: Sysmon + reboot events to alerts (`--selftest` runs anywhere) |
| `guard permissions [request]` | check disk access; on macOS raise the "Allow" prompts |
| `guard notify-test` | show a sample threat popup (verify desktop alerts work) |
| `guard deps update` | refresh the GitHub malware-package blocklist |
| `guard deps check <path>` | check a project's dependencies against the blocklist (`--blocklist FILE` for another one) |
| `guard update` | manual OTA check (the service also does this automatically) |
| `guard telemetry` | send a status report now |
| `guard install` / `guard uninstall` | set up / remove the auto-start service |
| `guard version` | print version |

Exit codes for scans: `0` clean, `1` infected (a `critical` / malicious finding;
with `guard av scan --fail-on-suspicious` also a suspicious one), `2` usage/error.

---

## Usage

```bash
# Scan a working tree (fast, no git needed)
guard scan /path/to/repo

# Scan the tree AND every added line across all commits/branches
guard scan-git /path/to/repo

# Pre-open gate: exit 1 means DO NOT OPEN this folder in VS Code
guard open /path/to/repo

# Antivirus scan of any files / folders (archives are unpacked and scanned too)
guard av scan ~/Downloads
guard av scan ./release.zip --json            # machine-readable report
guard av scan ~/Downloads --quarantine        # move whole-file threats into the vault
guard av quarantine list                      # ...and bring one back if needed
guard av quarantine restore <id>

# Manually clean an infected repo (the service does this automatically), then undo:
guard clean /path/to/repo
guard restore /path/to/repo/vite.config.ts
```

**Auto-clean is automatic.** You do **not** run `guard clean` by hand in normal
use — the watcher service cleans every detection on its own and pops a
"Threat neutralized" alert. `guard clean` is only the manual/on-demand version.
To make a machine alert-only (no auto-edit), set `"remediate": false` in
`<GUARD_HOME>/watcher.config.json`.

---

## How auto-remediation handles the attack

The attack injects a payload into an otherwise-legitimate file (a malicious IIFE
using `atob(process.env.AUTH_API_KEY)` + `eval(...)` bolted above your real
`vite.config.ts`), and the attacker **amends the original commit** so `git log`
looks clean. So Guard fixes the **working tree by content**, never git history:

- It locates the injected block with a string/comment/template-aware **bracket
  matcher** and removes exactly that span — imports and `export default
  defineConfig(...)` are untouched. A source file is **never deleted**; if the
  bounds are ambiguous it refuses and flags for manual review (fail-safe).
- After cleaning, commit the fix forward: `git add -A && git commit -m "remove injected payload"`.
  (Don't reset/cherry-pick — the forged history can't be trusted.)

---

## Antivirus engine (`guard_av`, v2)

Besides the incident-specific engines, Guard ships a general anti-malware engine
(pure Python stdlib, no native deps). Every file goes through a layered pipeline:

| Layer | What it does | Can produce |
|---|---|---|
| Content type ID | identifies PE / ELF / Mach-O / archives / scripts by **bytes**, not extension | — |
| Allowlist | known-good SHA-256, trusted path globs, disabled rule ids | CLEAN (stops) |
| Hash DB | exact MD5 / SHA-1 / SHA-256 signatures (JSON or `<hash> <name>` text lists) | MALICIOUS |
| YARA | Real YARA rules (`*.yar` / `*.yara`, compiled by yara-x in the Rust core, with the `pe`, `elf`, `macho`, `dotnet`, `math`, `hash` modules and more). Drop a rule file into `~/.guard/av/` or a `--signatures` directory. A rule reports SUSPICIOUS unless its meta says `verdict = "malicious"`; `whole_file = true` marks it safe to quarantine; disable one with `yara:<file stem>.<rule>` in an allowlist | MALICIOUS / SUSPICIOUS |
| Rules | JSON rules (the original format, kept for compatibility): text (ascii/wide/nocase), hex with `??` / `[n-m]` jumps / `(a\|b)`, regex; boolean conditions (`all`/`any`/`at_least`/`at`/`count`/`filesize`) | MALICIOUS / SUSPICIOUS |
| Heuristics | PE packers, encrypted executable sections, W+X sections, entry point outside code, process-injection / hollowing / keylogger API sets, ELF LD-preload rootkits, script obfuscation (encoded-blob exec, `_0x` obfuscator, char-code exec), PowerShell encoded/hidden/AMSI tampering, double/RTLO/masquerading filenames | SUSPICIOUS, MALICIOUS only when ≥3 strong independent indicators agree |
| Archives | recursive zip / tar / gzip / bzip2 / xz, in memory, bomb-safe (depth, member count, size and ratio limits) | per-member verdicts |

Bundled rules cover: EICAR, PHP webshells, bash / netcat / Python reverse shells,
Mimikatz, PowerShell download-and-execute cradles and AMSI bypasses, Node and Python
encoded-payload droppers, `base64 -d | sh` droppers, auto-exec VBA downloaders,
coin miners (PUA), ransom notes and npm install scripts that pipe to a shell.

**False-positive policy.** Only exact hashes and high-confidence rules may say
MALICIOUS; heuristics alone top out at SUSPICIOUS. Documentation files (`.md`,
`.rst`, `.txt`, `.html`) are excluded from hack-tool rules, and the engine
allowlists its own signature databases. The test suite enforces **0 false
positives** (not even SUSPICIOUS) over an adversarial benign corpus, the Python
standard library, system binaries and this repository.

**Custom signatures.** Drop `rules*.json`, `hashes*.json` / `hashes*.txt` and
`allowlist*.json` into `~/.guard/av/` (or pass `--signatures DIR`).

**Quarantine.** `guard av scan --quarantine` moves *whole-file* threats (malware
binaries, hash hits, archives) into a vault where they are XOR-encrypted with a
per-item key — never runnable, never re-detected by other AV — and restorable with
SHA-256 verification. Malicious code found inside a legitimate source file is
reported for review (or excised by `guard clean`), never deleted.

The watcher, `guard scan` and `guard clean` all use this engine automatically.

---

## Configuration

`GUARD_HOME` (defaults: `/var/lib/guard` for the Linux/Windows service,
`~/.guard` for the macOS user agent) holds:

- `watcher.config.json` — watch roots, `remediate`, `notify`, poll interval, memory budget
- `alerts.jsonl` — every detection (audit)
- `watcher.log` — activity
- `quarantine/` — backups of everything remediated + `index.jsonl` (for `guard restore`)
- `av-quarantine/` — the antivirus engine's neutered vault (`guard av quarantine ...`)
- `av/` — optional custom signatures: `rules*.json`, `hashes*.json` / `hashes*.txt`,
  `allowlist*.json` (loaded automatically on every scan)

---

## Build from source

The shipped artifact is a single static Rust binary built from `cli/` (on Linux it
links musl, so it runs on any distro, Alpine included, with no shared libraries).
Build it on each target OS with a Rust toolchain (rustup.rs):

```bash
bash build/build.sh                          # Linux needs musl-tools first
./build/dist/guard version
```

The Python modules (`guard.py`, `scanner.py`, `guard_av/`, ...) are the reference
implementation the binary was ported from. They still run from source
(`python guard.py ...`), and `tests/test_rust_*.py` run both and require the same
output on every OS.

Rule matching and the content heuristics run in a Rust extension (`core/`,
imported as `guard_core`). Without it, `guard_av` falls back to identical pure-Python
code, about 15-60x slower on rule matching; `GUARD_AV_BACKEND=python` forces that
fallback. The same extension gives the watcher native file-change events (inotify,
FSEvents, ReadDirectoryChangesW), so it reacts to a new file in under a second
without re-walking every watch root. It still runs a full snapshot pass at start,
every `full_rescan_sec` (default 300) and whenever the OS drops events. Without the
extension, or with `"native_events": false` in `watcher.config.json`, it polls every
`poll_interval_sec` as before. On Linux each watched directory uses one inotify
watch; if `fs.inotify.max_user_watches` runs out, the watcher logs it and polls.

Releases are built for all five platforms by `.github/workflows/release.yml` on a
`git tag vX.Y.Z`, which first runs the full test suite, then signs the OTA manifest
and publishes the GitHub Release.

---

## Testing

```bash
pip install -r requirements-dev.txt
pip install ./core                          # the coverage gate needs the Rust backend
python -m pytest --cov                      # every engine test runs on both backends, 100% coverage gate
cargo test --manifest-path core/Cargo.toml
GUARD_FP_FULL=1 python -m pytest tests/test_detection_accuracy.py -k false_positives --no-cov
```

The suite covers unit tests per engine, detection-rate tests (every malicious
sample detected, also inside zip / tar.gz / gzip / nested archives), the zero
false-positive sweep, and integration with the watcher, scanner, remediator and
`guard` CLI. Live malware samples are stored base64-encoded and only decoded in
memory, so the repository itself always scans clean. CI runs it on every push and
the release workflow refuses to build if it fails.

---

## Contributing

Contributions are welcome — especially new detection signatures.

1. **Fork** and create a feature branch off `main`.
2. **Signatures are data, not code.** General malware rules and hashes go in
   `guard_av/data/rules.json` / `hashes.json`, or as YARA in a `*.yar` file
   (validate either with `guard av rules --validate <file>`); incident IOCs go in `signatures.json`
   (fingerprints, dropper paths, `.vscode` rules). No code change needed. Add a
   matching fixture under `testdata/`, or a base64-encoded sample in
   `tests/samples.py` so live signatures never land in the repo.
3. **Add tests / fixtures** for anything you change, and keep false positives at
   zero (clean controls must still pass, coverage must stay at 100%).
4. Run the engines and the suite locally:
   ```bash
   guard scan testdata/<your-fixture>
   python -m pytest --cov
   ```
5. **Open a PR** describing the technique, the signature, and the fixture.

Code layout: `guard.py` (entrypoint/CLI) · `scanner.py` (orchestrator) ·
`guard_av/` (antivirus engine: `engine`, `rules`, `heuristics`, `archive`,
`yara_rules`, `hashdb`, `allowlist`, `quarantine`, `filetype`, `cli`) ·
`fingerprint_matcher.py` · `vscode_guard.py` · `magic_bytes.py` ·
`workflow_baseline.py` · `dep_blocklist.py` (detection) · `watcher.py` (service) ·
`remediator.py` (auto-clean) · `notifier.py` (alerts) · `updater.py` (OTA) ·
`telemetry.py` (dashboard) · `permissions.py` (macOS access) · `memguard.py` +
`snapshot_store.py` (memory-bounded scanning).

Please keep the project's boundaries: it detects, removes injected payloads with a
reversible backup, and reports — it does **not** rewrite remote git history,
force-push, or carry a broad-scope GitHub token on the endpoint.

See also: [Code of Conduct](CODE_OF_CONDUCT.md) · [Contributing](CONTRIBUTING.md) ·
[Privacy Policy](PRIVACY.md).

---

## Code signing

Windows release binaries are Authenticode code-signed. Free code signing for this
open-source project is provided by the **[SignPath Foundation](https://signpath.org)**,
with a certificate issued by SignPath Foundation. (Signing is being enabled for the
project; unsigned builds remain verifiable by the SHA-256 published with each
release.)

---

## The attack, in one paragraph

A JS dropper was committed disguised as a font (`public/fonts/fa-solid-400.woff2`).
A `.vscode/tasks.json` task with `"runOn": "folderOpen"` plus
`"task.allowAutomaticTasks": true` in `settings.json` makes VS Code **auto-execute
that dropper the moment a developer opens the folder — no click required**. The
dropper injects an obfuscated C2 payload / an `eval(proxyInfo)` IIFE (pulling code
from `auth-confirm-ten.vercel.app`) into build/config files, then commits under the
victim's git identity — which is why one attack shows up across dozens of
developers and repos: it re-infects on every folder open. **The endpoint is the
vector — hence Guard.**

---

## License

[MIT](LICENSE) © 2026 Syed Bipul Rahman
