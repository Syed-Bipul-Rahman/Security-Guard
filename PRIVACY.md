# Privacy Policy

_Last updated: 2026-09-22_

Guard is an open-source security agent. This policy explains what data the agent
collects, why, and how to control it.

## What Guard does locally

The core of Guard runs entirely on your own machine. Scanning, detection, and
remediation happen locally — the files it inspects and the payloads it removes are
**never** transmitted anywhere. Backups of anything Guard cleans stay on your
machine under `GUARD_HOME/quarantine`.

## Optional telemetry

Guard includes an **optional** status-reporting feature so an operator can see the
health of the machines they administer. When telemetry is enabled, the agent sends
a small status report to a **configurable endpoint** (which you can point at your
own self-hosted server, or disable entirely).

A report may include:

- Hostname, operating system and version, and the local account username
- Agent version and a hashed, MAC-derived machine identifier
- Local and public IP address (for approximate location during incident response)
- Whether the machine is clean or has a detection, and a summary of detections

Guard does **not** collect the contents of your source files, keystrokes,
credentials, or browsing activity.

## Controlling telemetry

- **Change the endpoint:** set the telemetry endpoint in
  `GUARD_HOME/telemetry.config.json` to your own server.
- **Disable it:** operators who deploy Guard can turn reporting off in
  configuration. If you run Guard yourself, you control whether it reports and
  where.

If you deploy Guard to machines you administer, you are the data controller for any
telemetry you collect, and you are responsible for informing the people who use
those machines that this reporting exists.

## Data retention

Telemetry is stored only on the endpoint you configure. The public demo dashboard
is for demonstration only and stores anonymized, transient status records.

## Contact

Questions about this policy: **syedbipulrahman2@gmail.com**, or open an issue at
https://github.com/Syed-Bipul-Rahman/Security-Guard.
