# Guard telemetry server (Vercel + MongoDB)

Lightweight collector + live dashboard. Agents `POST /api/telemetry`; the dashboard
reads `GET /api/fleet`. Free to host on Vercel.

```
api/telemetry.js   POST — ingest one agent report (upsert latest + append history)
api/fleet.js       GET  — latest report per machine (for the dashboard)
api/_db.js         cached MongoDB connection (reads MONGODB_URI env var)
public/index.html  the dashboard (fetches /api/fleet + /location_map.json)
public/location_map.json  subnet→floor / public-IP→provider map (edit to expand)
```

## Deploy (once)
1. Push this repo to GitHub (already done).
2. **vercel.com → New Project → import the repo.** Set **Root Directory** to
   `telemetry-server`. Framework preset: **Other**. Deploy.
3. **Project → Settings → Environment Variables** (do NOT commit these):
   | Name | Value |
   |------|-------|
   | `MONGODB_URI` | your Atlas connection string (`mongodb+srv://…`) |
   | `MONGODB_DB` | `guard` |
   | `INGEST_TOKEN` | a long random string — agents must send it |
   | `DASH_TOKEN` | a long random string — needed to view the dashboard |
   Redeploy after adding them.

## ⚠️ Atlas network access (the #1 gotcha)
Vercel serverless functions have **dynamic IPs**, so Atlas must allow them:
- Atlas → **Network Access → Add IP Address → Allow access from anywhere (`0.0.0.0/0`)**.
- Without this, every request fails with a connection/timeout error.
- Compensate for the open network rule with a **strong DB password + least-privilege
  DB user** (this app only needs readWrite on the `guard` db).

## ⚠️ Rotate the DB password
If the connection string was ever shared in plaintext (chat, ticket, screen-share),
**rotate it in Atlas** (Database Access → Edit user → new password) and update
`MONGODB_URI` in Vercel. The app reads it from the env var, so rotation is one edit.

## Point agents at it
In each machine's `GUARD_HOME/telemetry.config.json`:
```json
{
  "endpoint": "https://YOUR-APP.vercel.app/api/telemetry",
  "ingest_token": "the-same-INGEST_TOKEN",
  "interval_sec": 3600,
  "send_public_ip": true
}
```

## View the dashboard
`https://YOUR-APP.vercel.app/?token=YOUR-DASH_TOKEN` (the token is remembered in the
browser after the first visit). It auto-refreshes every 30s.

## Optional hardening
- Add a **TTL index** to auto-expire raw history:
  `db.reports.createIndex({ received_at: 1 }, { expireAfterSeconds: 7776000 })` (90d).
- Put the dashboard behind **Vercel Access / SSO** instead of just `DASH_TOKEN` if you
  want real auth.
- `machine_id` is a hashed MAC (not the raw MAC); usernames/IPs are collected for IR
  scoping — make sure users are informed this monitoring exists.
