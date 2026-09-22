# Guard release + OTA guide

How to cut a release and how the auto-update (OTA) stays safe. Follow the one-time
setup once; after that, shipping is a single `git tag`.

---

## 0. The safety model (read this once)
- The binary carries your **PUBLIC** key. The **SECRET** key lives only in a GitHub
  Actions secret. Whoever holds the secret can push root code to all machines — treat
  it as the master key.
- Every OTA update must pass **Ed25519 signature + SHA-256 + HTTPS + downgrade check**,
  or it is refused (**fail-closed**). An unsigned/absent key ⇒ no updates at all.

---

## 1. One-time setup

### 1a. Generate the signing keypair (do this on a trusted machine, once)
```bash
python3 release/sign_manifest.py keygen --out guard-update.key
```
This prints:
- a **PUBLIC key (hex)** — goes into the repo + the binary
- writes **`guard-update.key`** (the 32-byte SECRET seed) — never commit this

### 1b. Store the keys in GitHub (repo → Settings → Secrets and variables → Actions)
| Kind | Name | Value |
|------|------|-------|
| **Variable** | `GUARD_UPDATE_PUBKEY` | the PUBLIC key hex from 1a |
| **Variable** | `GUARD_UPDATE_URL` | `https://github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download` |
| **Secret** | `GUARD_SIGN_KEY_B64` | `base64 -w0 guard-update.key` (macOS: `base64 -i guard-update.key`) |

Then **delete `guard-update.key` from disk** (or move it to a vault). Keep one offline backup.

### 1c. Bake the public key into the source
Set `PUBKEY_HEX` in `updater.py` to your public key (the release workflow also injects
it at build time, but setting it in source makes local/dev builds consistent):
```python
PUBKEY_HEX = os.environ.get("GUARD_UPDATE_PUBKEY", "<your-public-key-hex>")
```
Commit that change.

---

## 2. Cut a release (every time)
```bash
git tag v1.1.0
git push origin v1.1.0
```
That triggers `.github/workflows/release.yml`, which:
1. builds the `guard` binary on all 5 OSes (linux-x64/arm64, darwin-arm64/x64, windows-x64),
   baking in the public key + URL + version,
2. refreshes the malware blocklist,
3. **signs** a manifest with your secret key,
4. publishes a **GitHub Release** with: `guard-<platform>` binaries, `malware-blocklist.json`,
   `manifest.json`, `manifest.json.sig`.

`releases/latest/download/manifest.json` now points at the new version — agents pick it up.

---

## 3. What users do: nothing after install
Install once:
```bash
curl -fsSL https://security.syedbipul.me/guard.sh | sudo bash
```
The service then checks the signed manifest every ~6 h (config: `update_check_sec` in
`~/.guard/watcher.config.json`) and auto-applies blocklist + binary updates. A binary
update swaps atomically and the service restarts into the new version.

---

## 4. Canary + rollback (recommended before trusting a wide push)
- **Canary:** point 2-3 machines at a pre-release URL (set their `GUARD_UPDATE_URL` to a
  `releases/download/<tag>` path) and verify for a day before promoting to `latest`.
- **Rollback:** the updater keeps the previous binary as `guard.bak` next to the installed
  one. To roll back a machine: `mv guard.bak guard` and restart the service. To roll back
  the fleet: publish a new release whose `version` is higher but whose binary is the old
  good build (never publish a *lower* version — downgrade protection ignores it).

---

## 5. Key rotation
If the secret key is exposed:
1. `keygen` a new pair, update `GUARD_UPDATE_PUBKEY` + `GUARD_SIGN_KEY_B64`, bake the new
   public key, and cut a release.
2. **Transition:** machines still running the old binary trust only the OLD key, so ship
   one release signed with the OLD key that contains a binary carrying the NEW key. After
   the fleet is on it, switch to signing with the new key. (Optionally add dual-key support
   in `updater.py` to accept either during the window.)

---

## 6. Invariants that keep it from breaking
- No public key baked in ⇒ **no updates** (safe default; nothing silently auto-runs).
- Bad signature / sha mismatch / older version ⇒ **update skipped**, agent keeps running.
- Update check failure (offline, server down) ⇒ **no-op**, never crashes the watcher.
- `git tag` is the only trigger; nothing publishes on a normal push.

---

## 7. Troubleshooting
| Symptom | Cause / fix |
|---------|-------------|
| Agents never update | `GUARD_UPDATE_PUBKEY` empty in the built binary, or `GUARD_UPDATE_URL` wrong |
| "SIGNATURE INVALID" in logs | manifest signed with a different key than baked in — re-check the pair |
| Release job fails at "Restore signing key" | `GUARD_SIGN_KEY_B64` secret missing/malformed |
| Windows binary not swapping | expected — it stages `guard.pending.exe`, applied on next service start |
| Build fails on one OS only | that runner's PyInstaller/Python issue; the matrix has `fail-fast: false` so others still ship |
