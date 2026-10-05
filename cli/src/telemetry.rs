//! Endpoint telemetry: the Rust port of telemetry.py.
//!
//! Collects host facts and a summary of what Guard detected and posts it to the
//! configured collector, writing a local copy (telemetry.json) every time and
//! queueing failed sends (telemetry-queue.jsonl). Scoping data for incident
//! response, not a blame tool; see telemetry.py and PRIVACY.md.

use std::fs;
use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::{net, pyjson, update, util};

/// Collector and ingest token; release builds bake GUARD_TELEMETRY_URL /
/// GUARD_INGEST_TOKEN in, and the environment overrides at run time.
const SOURCE_ENDPOINT: &str = match option_env!("GUARD_TELEMETRY_URL") {
    Some(u) => u,
    None => "https://security-guard-fkt3.vercel.app/api/telemetry",
};
const SOURCE_INGEST: &str = match option_env!("GUARD_INGEST_TOKEN") {
    Some(t) => t,
    None => "d6cc56d1a3d805248452fc28ce39073d637247b675bfaf0e6df91d0c0acae706",
};

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

pub fn default_config() -> Map<String, Value> {
    let v = json!({
        "endpoint": env_or("GUARD_TELEMETRY_URL", SOURCE_ENDPOINT),
        "ingest_token": env_or("GUARD_INGEST_TOKEN", SOURCE_INGEST),
        "interval_sec": 3600,
        "public_ip_lookup": "https://api.ipify.org",
        "send_public_ip": true,
        "agent_version": "1.0.0",
    });
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

pub fn load_config(home: &Path) -> Map<String, Value> {
    let mut cfg = default_config();
    if let Ok(text) = fs::read_to_string(home.join("telemetry.config.json")) {
        if let Ok(Value::Object(file)) = serde_json::from_str::<Value>(&text) {
            cfg.extend(file);
        }
    }
    cfg
}

// ---------------------------------------------------------------------------
// host / network facts (all best-effort)
// ---------------------------------------------------------------------------
fn all_local_ips() -> Vec<String> {
    let mut ips = std::collections::BTreeSet::new();
    // primary routable IP (UDP connect: no packet is sent)
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(a) = s.local_addr() {
                ips.insert(a.ip().to_string());
            }
        }
    }
    // everything resolvable for this host
    if let Ok(addrs) = (gethostname::gethostname().to_string_lossy().as_ref(), 0).to_socket_addrs()
    {
        for a in addrs {
            ips.insert(a.ip().to_string());
        }
    }
    // OS tools for interfaces the above miss
    let (cmd, pat): (Vec<&str>, &str) = if cfg!(windows) {
        (vec!["ipconfig"], r"IPv4.*?:\s*([0-9.]+)")
    } else if util::which("ip").is_some() {
        (vec!["ip", "-o", "addr"], r"inet\s+([0-9.]+)")
    } else {
        (vec!["ifconfig"], r"inet\s+([0-9.]+)")
    };
    if let Ok(out) = Command::new(cmd[0]).args(&cmd[1..]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for c in Regex::new(pat).unwrap().captures_iter(&text) {
            ips.insert(c[1].to_string());
        }
    }
    ips.into_iter()
        .filter(|i| !i.is_empty() && !i.starts_with("127."))
        .collect()
}

fn public_ip(cfg: &Map<String, Value>) -> Option<String> {
    if !pyjson::truthy(cfg.get("send_public_ip")) || !pyjson::truthy(cfg.get("public_ip_lookup")) {
        return None;
    }
    let url = cfg.get("public_ip_lookup")?.as_str()?;
    let body = net::fetch(url, "guard-telemetry", Duration::from_secs(8), false).ok()?;
    let ip = String::from_utf8(body).ok()?.trim().to_string();
    (!ip.is_empty() && ip.chars().count() <= 45).then_some(ip)
}

/// A stable id for this machine. The one already reported (telemetry.json,
/// written by the Python build too) wins, so a host keeps its identity on the
/// dashboard across the switch; otherwise sha256 of the MAC as a number, as
/// telemetry.py derives it from uuid.getnode().
fn machine_id(home: &Path) -> String {
    let known = fs::read_to_string(home.join("telemetry.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| {
            v.pointer("/host/machine_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    if let Some(id) = known {
        return id;
    }
    let node: u64 = match mac_address::get_mac_address() {
        Ok(Some(m)) if m.bytes() != [0; 6] => {
            m.bytes().iter().fold(0, |n, b| (n << 8) | u64::from(*b))
        }
        // uuid.getnode()'s fallback: a random 48-bit number with the multicast bit set
        _ => {
            let mut b = [0u8; 8];
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            b.copy_from_slice(
                &update::sha256_hex(format!("{t:?}{}", std::process::id()).as_bytes()).as_bytes()
                    [..8],
            );
            (u64::from_le_bytes(b) & 0xffff_ffff_ffff) | (1 << 40)
        }
    };
    update::sha256_hex(node.to_string().as_bytes())[..16].to_string()
}

fn install_info(home: &Path) -> Value {
    fs::read_to_string(home.join("install.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| json!({}))
}

/// platform.system(), platform.release(), platform.platform()
fn os_facts() -> (String, String, String) {
    #[cfg(windows)]
    {
        let (major, minor, build, server) = windows_version();
        let release = windows_release((major, minor, build), server);
        let detail = format!("Windows-{release}-{major}.{minor}.{build}-SP0"); // platform.platform()
        ("Windows".into(), release, detail)
    }
    #[cfg(unix)]
    {
        let (sys, release, machine) = util::unix::uname();
        if sys == "Darwin" {
            let ver = Command::new("sw_vers")
                .arg("-productVersion")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            let cpu = if machine == "arm64" { "arm" } else { "i386" };
            let detail = format!("macOS-{ver}-{machine}-{cpu}-64bit");
            return (sys, release, detail);
        }
        let detail = format!("{sys}-{release}-{machine}");
        (sys, release, detail)
    }
}

/// (major, minor, build, is_server): anything but a workstation counts as a server, as in Python
#[cfg(windows)]
fn windows_version() -> (u32, u32, u32, bool) {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::{OSVERSIONINFOEXW, OSVERSIONINFOW};
    let mut v: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
    // SAFETY: RtlGetVersion fills an OSVERSIONINFOEXW when given its size.
    unsafe { RtlGetVersion(&mut v as *mut OSVERSIONINFOEXW as *mut OSVERSIONINFOW) };
    const VER_NT_SERVER: u8 = 3;
    (
        v.dwMajorVersion,
        v.dwMinorVersion,
        v.dwBuildNumber,
        v.wProductType == VER_NT_SERVER,
    )
}

/// platform.release() on Windows, as Python 3.12 names it (the release build's Python).
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_release(ver: (u32, u32, u32), server: bool) -> String {
    const CLIENT: &[((u32, u32, u32), &str)] = &[
        ((10, 1, 0), "post11"),
        ((10, 0, 22000), "11"),
        ((6, 4, 0), "10"),
        ((6, 3, 0), "8.1"),
        ((6, 2, 0), "8"),
        ((6, 1, 0), "7"),
        ((6, 0, 0), "Vista"),
        ((5, 2, 3790), "XP64"),
        ((5, 2, 0), "XPMedia"),
        ((5, 1, 0), "XP"),
        ((5, 0, 0), "2000"),
    ];
    const SERVER: &[((u32, u32, u32), &str)] = &[
        ((10, 1, 0), "post2025Server"),
        ((10, 0, 26100), "2025Server"),
        ((10, 0, 20348), "2022Server"),
        ((10, 0, 17763), "2019Server"),
        ((6, 4, 0), "2016Server"),
        ((6, 3, 0), "2012ServerR2"),
        ((6, 2, 0), "2012Server"),
        ((6, 1, 0), "2008ServerR2"),
        ((6, 0, 0), "2008Server"),
        ((5, 2, 0), "2003Server"),
        ((5, 0, 0), "2000Server"),
    ];
    let table = if server { SERVER } else { CLIENT };
    table
        .iter()
        .find(|(min, _)| ver >= *min)
        .map_or_else(String::new, |(_, name)| name.to_string())
}

fn collect_host(cfg: &Map<String, Value>, home: &Path) -> Value {
    let (os, os_version, os_detail) = os_facts();
    json!({
        "hostname": gethostname::gethostname().to_string_lossy(),
        "os": os,
        "os_version": os_version,
        "os_detail": os_detail,
        "username": util::username(),
        "machine_id": machine_id(home),
        "agent_version": cfg.get("agent_version").cloned().unwrap_or_else(|| json!("?")),
        "local_ips": all_local_ips(),
        "public_ip": public_ip(cfg),
        "install": install_info(home),
    })
}

// ---------------------------------------------------------------------------
// detection-event summary from alerts.jsonl
// ---------------------------------------------------------------------------
/// A dict key as json.dumps writes it.
fn key_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => pyjson::dumps(other, None, false),
    }
}

fn bump(m: &mut Map<String, Value>, k: String) {
    let n = m.get(&k).and_then(Value::as_u64).unwrap_or(0);
    m.insert(k, json!(n + 1));
}

pub fn collect_events(home: &Path, recent: usize) -> Value {
    let mut by_severity = Map::new();
    let mut by_rule = Map::new();
    let mut by_kind = Map::new();
    let mut events: Vec<Value> = Vec::new();
    let mut total = 0u64;
    if let Ok(bytes) = fs::read(home.join("alerts.jsonl")) {
        let text = String::from_utf8_lossy(&bytes)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        for line in text.lines() {
            let Ok(Value::Object(r)) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            total += 1;
            let q = json!("?");
            let sev = r.get("severity").unwrap_or(&q);
            bump(&mut by_severity, key_of(sev));
            let rule = pyjson::or(r.get("rule"), r.get("kind"))
                .filter(|v| pyjson::truthy(Some(v)))
                .unwrap_or(&q);
            bump(&mut by_rule, key_of(rule));
            let kind = r.get("kind").unwrap_or(&q);
            bump(&mut by_kind, key_of(kind));
            events.push(json!({
                "ts": r.get("ts").cloned().unwrap_or(Value::Null),
                "severity": sev,
                "rule": rule,
                "kind": kind,
                "summary": pyjson::or(r.get("summary"), r.get("path")).cloned().unwrap_or(Value::Null),
            }));
        }
    }
    let infected = by_severity
        .get("critical")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0;
    let mut top: Vec<(String, u64)> = by_rule
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
        .collect();
    top.sort_by_key(|e| std::cmp::Reverse(e.1)); // stable, like Python's sorted
    top.truncate(5);
    let skip = events.len().saturating_sub(recent);
    json!({
        "infected": infected,
        "total_detections": total,
        "by_severity": by_severity,
        "by_kind": by_kind,
        "how": top.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        "patterns": top.iter().map(|(k, n)| (k.clone(), json!(n))).collect::<Map<_, _>>(),
        "recent": events.split_off(skip),
    })
}

pub fn build_report(cfg: &Map<String, Value>, home: &Path) -> Value {
    json!({
        "schema": "guard-telemetry/1",
        "ts": util::now_iso(),
        "host": collect_host(cfg, home),
        "events": collect_events(home, 25),
    })
}

pub fn send(report: &Value, cfg: &Map<String, Value>, home: &Path) -> Value {
    // always write a local copy
    let _ = util::write_text(
        &home.join("telemetry.json"),
        &pyjson::dumps(report, Some(2), false),
    );
    if !pyjson::truthy(cfg.get("endpoint")) {
        return json!({"status": "local-only"});
    }
    let body = pyjson::dumps(report, None, false);
    let result = (|| -> Result<u16, String> {
        let endpoint = cfg
            .get("endpoint")
            .and_then(Value::as_str)
            .ok_or("unknown url type")?;
        let token = cfg.get("ingest_token").filter(|t| pyjson::truthy(Some(t)));
        let token = token.map(|t| t.as_str().map(str::to_string).unwrap_or_else(|| key_of(t)));
        let mut headers = vec![("Content-Type", "application/json")];
        if let Some(t) = token.as_deref() {
            headers.push(("X-Guard-Token", t)); // shared secret for the collector
        }
        let client = net::Client::new(
            endpoint,
            "guard-telemetry",
            Duration::from_secs(15),
            false,
            true,
        )?;
        Ok(client.post(endpoint, &headers, body.as_bytes())?.status)
    })();
    match result {
        Ok(status) => json!({"status": "sent", "http": status}),
        Err(e) => {
            // queue failed sends for retry
            if let Ok(mut q) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(home.join("telemetry-queue.jsonl"))
            {
                let _ = write!(q, "{body}{}", if cfg!(windows) { "\r\n" } else { "\n" });
            }
            json!({"status": "queued", "error": e})
        }
    }
}

pub fn run_once(home: &Path) -> Result<Value, String> {
    fs::create_dir_all(home).map_err(|e| format!("{}: {e}", home.display()))?;
    let cfg = load_config(home);
    let report = build_report(&cfg, home);
    Ok(send(&report, &cfg, home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_release_names() {
        assert_eq!(windows_release((10, 0, 19045), false), "10");
        assert_eq!(windows_release((10, 0, 22631), false), "11");
        assert_eq!(windows_release((10, 0, 20348), true), "2022Server");
        assert_eq!(windows_release((10, 0, 26100), true), "2025Server");
        assert_eq!(windows_release((10, 0, 14393), true), "2016Server");
    }

    #[test]
    fn events_summary() {
        let dir = std::env::temp_dir().join(format!("guard-tel-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("alerts.jsonl"),
            "{\"severity\":\"critical\",\"rule\":\"a\",\"kind\":\"k\",\"path\":\"/p\"}\nnot json\n{\"severity\":\"low\",\"kind\":\"k2\",\"summary\":\"s\"}\n{\"rule\":\"a\"}\n",
        )
        .unwrap();
        let e = collect_events(&dir, 2);
        assert_eq!(e["infected"], json!(true));
        assert_eq!(e["total_detections"], json!(3));
        assert_eq!(e["how"], json!(["a", "k2"]));
        assert_eq!(e["by_severity"], json!({"critical": 1, "low": 1, "?": 1}));
        assert_eq!(e["recent"].as_array().unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
}
