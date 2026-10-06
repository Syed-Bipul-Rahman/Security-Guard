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
2. Guard ships as one static Rust binary (`cli/`), with the engine core in `core/`
   and the release signer in `release/`. Change the Rust, then build and re-run the
   tests:
   ```bash
   cargo build --locked --manifest-path cli/Cargo.toml
   cli/target/debug/guard scan testdata/<fixture>
   cargo test --locked --manifest-path cli/Cargo.toml
   cargo test --manifest-path core/Cargo.toml
   cargo test --manifest-path release/Cargo.toml
   ```
   The integration tests in `cli/tests/` compare the binary's output with golden
   files in `cli/tests/golden/`. A deliberate behavior change means re-recording
   the affected goldens with `GUARD_GOLDEN=record` and reviewing the diff
   (goldens are base64; read one with `base64 -d < cli/tests/golden/<dir>/<name>.b64`).
3. To build the release binary (per OS, with a Rust toolchain):
   ```bash
   bash build/build.sh
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

`cli/src/main.rs` (entrypoint/CLI) · `cli/src/av/` (antivirus engine) ·
`cli/src/scan/` (`scanner` orchestrator, `fingerprint`, `vscode`, `magic`,
`workflow`, `depbl` detection, `remediate` auto-clean) · `cli/src/watch/` (`watcher`
service, `memguard` + `store` memory-bounded scanning) · `sensor.rs` (Windows
sensor) · `deps.rs` (malware blocklist) · `update.rs` (OTA) · `telemetry.rs`
(dashboard) · `install.rs` (service install) · `notify.rs` (alerts) ·
`permissions.rs` (macOS access) · `core/src/` (`guard_core`: rule matching, YARA,
heuristics, native file events) · `release/src/` (`sign-manifest` release signer) ·
`data/av-rules.json` + `data/av-hashes.json` (AV signatures, compiled into the
binary) · `cli/tests/` (integration tests and goldens).

## Reporting security issues

Please report vulnerabilities privately via a
[GitHub security advisory](https://github.com/Syed-Bipul-Rahman/Security-Guard/security/advisories/new)
rather than a public issue.

See also our [Code of Conduct](CODE_OF_CONDUCT.md).
