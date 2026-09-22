# Contributing to Guard

Thanks for your interest in improving Guard! Contributions are welcome —
especially new detection signatures for supply-chain malware.

## Ways to contribute

- **New detection signatures** (most valuable) — add IOCs/fingerprints
- **Bug fixes** and reliability improvements to the watcher, scanner, or installers
- **Platform coverage** — Linux/macOS/Windows edge cases
- **Docs** — clearer install/usage instructions

## Getting started

1. **Fork** the repo and create a feature branch off `main`.
2. Guard is a single binary built from the Python modules in the repo. To run it
   from source:
   ```bash
   python guard.py scan testdata/<fixture>
   ```
3. To build the standalone binary (per OS; PyInstaller does not cross-compile):
   ```bash
   python -m pip install --upgrade pyinstaller certifi
   pyinstaller build/guard.spec --distpath build/dist --clean --noconfirm
   ```

## Adding a detection signature

**Signatures are data, not code.** Most new detections need no code change:

1. Add the pattern to `signatures.json` (fingerprints, dropper paths, `.vscode`
   rules). The engines reload it automatically.
2. Add a **fixture** under `testdata/` that reproduces the technique, plus a clean
   control that must NOT match.
3. Verify:
   ```bash
   guard scan testdata/<your-fixture>     # expect: INFECTED
   guard scan testdata/<clean-control>    # expect: clean (exit 0)
   ```
   Keep **false positives at zero** — clean controls must still pass.

## Pull requests

- Keep PRs focused; describe the **technique**, the **signature**, and the
  **fixture** you added.
- Match the surrounding code style.
- By contributing, you agree your work is licensed under the project's
  [MIT License](LICENSE).

## Project boundaries (please respect these)

Guard detects, removes injected payloads **with a reversible backup**, and reports.
It deliberately does **not** rewrite remote git history, force-push, or carry a
broad-scope GitHub token on the endpoint. Please keep changes within these bounds.

## Code layout

`guard.py` (entrypoint/CLI) · `scanner.py` (orchestrator) · `fingerprint_matcher.py`
· `vscode_guard.py` · `magic_bytes.py` · `workflow_baseline.py` · `dep_blocklist.py`
(detection) · `watcher.py` (service) · `remediator.py` (auto-clean) · `notifier.py`
(alerts) · `updater.py` (OTA) · `telemetry.py` (dashboard) · `permissions.py` (macOS
access) · `memguard.py` + `snapshot_store.py` (memory-bounded scanning).

## Reporting security issues

Please report vulnerabilities privately via a
[GitHub security advisory](https://github.com/Syed-Bipul-Rahman/Security-Guard/security/advisories/new)
rather than a public issue.

See also our [Code of Conduct](CODE_OF_CONDUCT.md).
