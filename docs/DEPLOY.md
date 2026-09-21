# Deploy `security.sparktech.agency` (GitHub Pages + Cloudflare DNS)

Goal: serve the install one-liners and landing page from your subdomain, over HTTPS:
```
https://security.sparktech.agency/            -> landing page (index.html)
https://security.sparktech.agency/guard.sh    -> Linux/macOS installer
https://security.sparktech.agency/guard.ps1   -> Windows installer
```
Binaries themselves stay on **GitHub Releases** (the installers download them from there).

`sparktech.agency` is managed in **Cloudflare**, so DNS is done there; the site is hosted on
**GitHub Pages** from this repo's `docs/` folder.

---

## Step 1 — turn on GitHub Pages (this repo)
1. Repo → **Settings → Pages**.
2. **Source:** Deploy from a branch. **Branch:** `main`, **Folder:** `/docs`. Save.
3. **Custom domain:** enter `security.sparktech.agency`, Save.
   (This uses the `docs/CNAME` file already in the repo.)
4. Leave **Enforce HTTPS** unchecked for now — you'll enable it after DNS + the cert is issued.

Pages will show "Your site is ready to be published" and then, after DNS, a green check.

---

## Step 2 — add the DNS record in Cloudflare
Cloudflare dashboard → your `sparktech.agency` zone → **DNS → Records → Add record**:

| Field | Value |
|-------|-------|
| Type  | `CNAME` |
| Name  | `security` |
| Target | `syed-bipul-rahman.github.io` |
| Proxy status | **DNS only (grey cloud)** ← important, see below |
| TTL | Auto |

**Why "DNS only" (grey cloud), not proxied (orange):**
- With **grey cloud**, GitHub serves the site directly and issues/serves its own HTTPS
  certificate for `security.sparktech.agency`. Simplest and most reliable — do this.
- With **orange cloud** (Cloudflare proxy), you get Cloudflare's CDN in front, but you MUST
  set Cloudflare **SSL/TLS mode = Full** (SSL/TLS → Overview). If it's on **Flexible**, you
  get an infinite redirect loop (Pages forces HTTPS, Cloudflare talks HTTP to origin). Only
  use orange cloud if you specifically want Cloudflare in front; then set Full and it works.

**Recommendation:** start **grey cloud (DNS only)**. Switch to orange later only if you want
Cloudflare caching/WAF, and set SSL/TLS to **Full** when you do.

---

## Step 3 — verify + enable HTTPS
1. Wait for DNS to propagate (usually minutes; Cloudflare is fast).
2. Back in **Settings → Pages**, GitHub verifies the domain and issues a Let's Encrypt cert
   (can take a few minutes up to ~24h; usually quick).
3. Once the cert is ready, tick **Enforce HTTPS**.
4. Test:
   ```bash
   curl -fsSL https://security.sparktech.agency/guard.sh | head -5
   curl -fsSLI https://security.sparktech.agency/           # expect HTTP/2 200
   ```

---

## Step 4 — sanity-check the installers
```bash
# macOS / Linux (will download the binary from Releases, verify sha256, install)
curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash

# Windows (elevated PowerShell)
irm https://security.sparktech.agency/guard.ps1 | iex
```

---

## Notes / gotchas
- **HTTPS only.** Never advertise the `http://` form — piping a script to a root shell over
  plaintext is MITM-exploitable. GitHub Pages + "Enforce HTTPS" redirects http→https, but the
  command you publish should say `https://`.
- **`docs/.nojekyll`** is included so Pages serves `guard.sh`/`guard.ps1` verbatim (no Jekyll
  processing).
- **Apex vs subdomain:** this is a subdomain (`security.…`), so a CNAME is correct. (An apex
  like `sparktech.agency` would need A/ALIAS records instead — not your case here.)
- **Binaries** are pulled from `github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download`.
  If you later move hosting, set `GUARD_BASE_URL` in the installers.
- **Repo must be public** for GitHub Pages on the free tier (or GitHub Pro/Team for private
  Pages). If the repo is private and you want the site public, either make it public or host
  the two scripts on Cloudflare Pages instead.
