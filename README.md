# Guard — supply-chain malware agent

One self-contained `guard` binary for every user machine (**Linux / macOS /
Windows**). It runs always-on, **detects** supply-chain malware (the fake-font
dropper / `.vscode` auto-run / obfuscated `eval` C2 family), **auto-removes** it —
excising the injected code while keeping your real files — and **warns the user**
with a desktop notification, like a consumer antivirus. It self-updates over the
air and can report status to an optional, self-hostable dashboard.

- **Repo:** https://github.com/Syed-Bipul-Rahman/Security-Guard
- **Releases:** https://github.com/Syed-Bipul-Rahman/Security-Guard/releases
- **Install site:** https://security.sparktech.agency
- **Demo dashboard:** https://security-guard-fkt3.vercel.app

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

- **Always-on watcher** — detects repo clones, pulls/checkouts, new project dirs,
  and downloaded files, and scans them automatically. Bounded to <10% RAM.
- **Auto-remediation (default on)** — on a critical hit it *removes the threat*,
  not just alerts:
  - **excises** an injected malicious IIFE from a real source file (keeps the
    imports/config around it),
  - **quarantines** whole-file droppers (a fake `.woff2` that's actually JS),
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
| `guard scan <path>` | full tree scan: fingerprints, disguised droppers, `.vscode` auto-run, workflows, malicious deps |
| `guard scan-git <path>` | the above **plus** every added line across git history |
| `guard open <path>` | pre-open check — is it safe to open this folder in VS Code? |
| `guard clean <path>` | **remove** injected malware in place (excise/quarantine), backing up first |
| `guard restore <path>` | undo a clean/quarantine from the backup store |
| `guard watch` | the always-on filesystem watcher (what the service runs) |
| `guard triage` | host IR triage (reboots / persistence / recon / flood) |
| `guard permissions [request]` | check disk access; on macOS raise the "Allow" prompts |
| `guard notify-test` | show a sample threat popup (verify desktop alerts work) |
| `guard deps update` | refresh the GitHub malware-package blocklist |
| `guard deps check <path>` | check a project's dependencies against the blocklist |
| `guard update` | manual OTA check (the service also does this automatically) |
| `guard telemetry` | send a status report now |
| `guard install` / `guard uninstall` | set up / remove the auto-start service |
| `guard version` | print version |

Exit codes for scans: `0` clean, `1` infected (a `critical` finding), `2` usage/error.

---

## Usage

```bash
# Scan a working tree (fast, no git needed)
guard scan /path/to/repo

# Scan the tree AND every added line across all commits/branches
guard scan-git /path/to/repo

# Pre-open gate: exit 1 means DO NOT OPEN this folder in VS Code
guard open /path/to/repo

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

## Configuration

`GUARD_HOME` (defaults: `/var/lib/guard` for the Linux/Windows service,
`~/.guard` for the macOS user agent) holds:

- `watcher.config.json` — watch roots, `remediate`, `notify`, poll interval, memory budget
- `alerts.jsonl` — every detection (audit)
- `watcher.log` — activity
- `quarantine/` — backups of everything remediated + `index.jsonl` (for `guard restore`)

---

## Build from source

The shipped artifact is a single PyInstaller binary; the `.py`/`.sh` files are
internal modules it carries (you never run them directly). PyInstaller does not
cross-compile, so build on each target OS:

```bash
python -m pip install --upgrade pyinstaller certifi
pyinstaller build/guard.spec --distpath build/dist --clean --noconfirm
./build/dist/guard version
```

Releases are built for all five platforms by `.github/workflows/release.yml` on a
`git tag vX.Y.Z`, which also signs the OTA manifest and publishes the GitHub Release.

---

## Contributing

Contributions are welcome — especially new detection signatures.

1. **Fork** and create a feature branch off `main`.
2. **Signatures are data, not code.** Most new IOCs go in `signatures.json`
   (fingerprints, dropper paths, `.vscode` rules); the engines reload it, no code
   change needed. Add a matching fixture under `testdata/`.
3. **Add tests / fixtures** for anything you change, and keep false positives at
   zero (clean controls must still pass).
4. Run the engines locally:
   ```bash
   guard scan testdata/<your-fixture>
   ```
5. **Open a PR** describing the technique, the signature, and the fixture.

Code layout: `guard.py` (entrypoint/CLI) · `scanner.py` (orchestrator) ·
`fingerprint_matcher.py` · `vscode_guard.py` · `magic_bytes.py` ·
`workflow_baseline.py` · `dep_blocklist.py` (detection) · `watcher.py` (service) ·
`remediator.py` (auto-clean) · `notifier.py` (alerts) · `updater.py` (OTA) ·
`telemetry.py` (dashboard) · `permissions.py` (macOS access) · `memguard.py` +
`snapshot_store.py` (memory-bounded scanning).

Please keep the project's boundaries: it detects, removes injected payloads with a
reversible backup, and reports — it does **not** rewrite remote git history,
force-push, or carry a broad-scope GitHub token on the endpoint.

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
