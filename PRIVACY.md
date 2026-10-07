# Privacy Policy

_Last updated: 2026-10-07_

Guard is an open-source security agent. This policy explains what data the agent
collects, why, and how to control it.

## What Guard does locally

The core of Guard runs entirely on your own machine. Scanning, detection, and
remediation happen locally — the files it inspects and the payloads it removes are
**never** transmitted anywhere. Backups of anything Guard cleans stay on your
machine under `GUARD_HOME/quarantine`.

## No telemetry

Guard sends **no telemetry**: no status reports, host details, IP addresses or
detection summaries leave your machine. Versions up to 2.1.0 included an optional
status report to a dashboard; the report and the dashboard have been removed, and
once a machine updates it stops reporting. Files an older version left in `GUARD_HOME`
(`telemetry.json`, `telemetry.config.json`, `telemetry-queue.jsonl`) are no
longer read or sent, and you can delete them.

## What Guard does contact

- **Updates:** Guard downloads its signed update manifest, new binaries and the
  malware-package blocklist from its update channel. These are plain downloads;
  Guard sends nothing about your machine with them.
- **`guard deps update`:** fetches the malware-package list from the GitHub
  advisory database when you run it.

## Contact

Questions about this policy: **syedbipulrahman2@gmail.com**, or open an issue at
https://github.com/Syed-Bipul-Rahman/Security-Guard.
