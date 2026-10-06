//! `guard sensor`: the Windows endpoint sensor, ported from windows/windows_sensor.py.
//!
//! Covers the three Windows behaviors from the investigation:
//!   A. python/script files staged in TEMP        -> Sysmon FileCreate (ID 11)
//!   B. registry persistence modifications         -> Sysmon RegistryEvent (12/13/14)
//!   C. repeated forced reboots during work hours   -> System log 1074 / 41 / 6008
//!
//! Two layers, as in the Python sensor:
//!   * `Detector`: pure logic over normalized event objects, matched against
//!     signatures.json["windows"]. No Windows dependency, so it runs and is
//!     tested on any OS (`guard sensor --selftest`, `guard sensor --replay`).
//!   * event sources (Windows only): live subscriptions to the Sysmon
//!     operational log and the System log through the Windows Event Log API,
//!     rendered to XML and normalized. The Python build needed pywin32 for this.
//!
//! Alerts go to <GUARD_HOME>/alerts.jsonl, same schema as the watcher.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::{pyjson, scan, util};

const USAGE: &str = "\
usage: guard sensor [--signatures FILE] [--selftest | --replay EVENTS.jsonl]

Windows endpoint sensor: tails Sysmon (file/registry/process events) and the
System log (reboots), matches them against the bundled signatures and writes
alerts to $GUARD_HOME/alerts.jsonl. Needs Windows with Sysmon installed
(`guard sysmon-config` prints the config to install it with).

  --selftest        run the detection logic on synthetic events (any OS)
  --replay FILE     match normalized events from a JSON-lines file (any OS)
  --signatures FILE use this signatures.json instead of the bundled one
";

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: &'static str,
    pub event_type: &'static str,
    pub summary: String,
    pub evidence: Value,
}

/// Match normalized Windows events against signatures.json["windows"].
pub struct Detector {
    temp_markers: Vec<String>,
    temp_exts: Vec<String>,
    interpreters: Vec<String>,
    reg_keys: Vec<String>,
    reg_value_ind: Vec<String>,
    reboot_ids: Vec<(i64, String)>,
    reboot_initiators: Vec<String>,
    burst_count: usize,
    burst_window_minutes: i64,
    parent_child: Vec<(String, String)>,
    payload_indicators: Vec<String>,
    net_iocs: Vec<String>,
    /// stateful reboot history (microseconds since the epoch)
    reboot_times: Vec<i64>,
}

fn lower_list(v: Option<&Value>) -> Vec<String> {
    scan::sigs::list(v)
        .filter_map(Value::as_str)
        .map(str::to_lowercase)
        .collect()
}

/// Python's int() of a JSON value (numbers and numeric strings).
fn int_of(v: Option<&Value>, default: i64) -> i64 {
    match v {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
        Some(Value::Bool(b)) => i64::from(*b),
        _ => default,
    }
}

/// str(ev.get(key, "")).
fn field(ev: &Value, key: &str) -> String {
    match ev.get(key) {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "None".into(),
        Some(Value::Bool(b)) => if *b { "True" } else { "False" }.into(),
        Some(other) => other.to_string(),
    }
}

/// ntpath.basename: the part after the last \ or /.
fn nt_basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// ntpath.splitext(p)[1]: the extension of the last component, ignoring
/// leading dots (".bashrc" has none).
fn nt_ext(p: &str) -> &str {
    let base = nt_basename(p);
    let stem_start = base.len() - base.trim_start_matches('.').len();
    match base[stem_start..].rfind('.') {
        Some(i) => &base[stem_start + i..],
        None => "",
    }
}

/// str(timedelta(minutes=m)): "3:00:00", "1 day, 0:00:00".
fn timedelta_str(minutes: i64) -> String {
    let secs = minutes * 60;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hms = format!("{}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
    if days == 0 {
        hms
    } else {
        format!(
            "{days} day{}, {hms}",
            if days.abs() == 1 { "" } else { "s" }
        )
    }
}

fn now_micros() -> i64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    d.as_secs() as i64 * 1_000_000 + i64::from(d.subsec_micros())
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An ISO 8601 timestamp ("2026-10-06T09:30:00+00:00", "...Z", "....123456",
/// or naive, read as UTC) in microseconds since the epoch.
pub fn parse_iso(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut rest = &s[19..];
    let mut micros = 0i64;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let mut padded = digits.clone();
        padded.truncate(6);
        while padded.len() < 6 {
            padded.push('0');
        }
        micros = padded.parse().ok()?;
        rest = &frac[digits.len()..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        tz => {
            let sign = match tz.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hm = tz[1..].replace(':', "");
            if hm.len() != 4 {
                return None;
            }
            sign * (hm[..2].parse::<i64>().ok()? * 3600 + hm[2..].parse::<i64>().ok()? * 60)
        }
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset;
    Some(secs * 1_000_000 + micros)
}

impl Detector {
    pub fn new(sig: &Value) -> Detector {
        let empty = json!({});
        let w = sig.get("windows").unwrap_or(&empty);
        let rb = w.get("reboot_burst").unwrap_or(&empty);
        let reboot_ids = w
            .get("reboot_event_ids")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| {
                        Some((
                            k.trim().parse().ok()?,
                            v.as_str().unwrap_or_default().to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let parent_child = scan::sigs::list(w.get("suspicious_parent_child"))
            .filter_map(|pair| {
                let a = pair.get(0)?.as_str()?;
                let b = pair.get(1)?.as_str()?;
                Some((a.to_lowercase(), b.to_lowercase()))
            })
            .collect();
        // shared C2/payload indicators reused from the top-level literals
        let payload_indicators = scan::sigs::list(sig.get("literals"))
            .filter(|l| {
                matches!(
                    l.get("category").and_then(Value::as_str),
                    Some("obfuscated-c2" | "dropper-cmd")
                )
            })
            .filter_map(|l| l.get("value").and_then(Value::as_str))
            .map(str::to_lowercase)
            .collect();
        let net_iocs = scan::sigs::list(sig.get("network_iocs"))
            .filter_map(|i| i.get("value").and_then(Value::as_str))
            .map(str::to_lowercase)
            .collect();
        Detector {
            temp_markers: lower_list(w.get("temp_dir_markers")),
            temp_exts: lower_list(w.get("suspicious_temp_ext")),
            interpreters: lower_list(w.get("interpreter_procs")),
            reg_keys: lower_list(w.get("registry_persistence_keys")),
            reg_value_ind: lower_list(w.get("registry_value_indicators")),
            reboot_ids,
            reboot_initiators: lower_list(w.get("reboot_initiator_procs")),
            burst_count: int_of(rb.get("count"), 2).max(0) as usize,
            burst_window_minutes: int_of(rb.get("window_minutes"), 180),
            parent_child,
            payload_indicators,
            net_iocs,
            reboot_times: Vec::new(),
        }
    }

    fn is_parent_child(&self, parent: &str, image: &str) -> bool {
        self.parent_child
            .iter()
            .any(|(a, b)| a == parent && b == image)
    }

    fn reboot_desc(&self, eid: i64) -> &str {
        self.reboot_ids
            .iter()
            .find(|(id, _)| *id == eid)
            .map_or("?", |(_, d)| d.as_str())
    }

    pub fn on_file_create(&self, ev: &Value) -> Vec<Finding> {
        let path = field(ev, "path");
        let low = path.to_lowercase();
        let ext = nt_ext(&low);
        let in_temp = self.temp_markers.iter().any(|m| low.contains(m.as_str()));
        let mut findings = Vec::new();
        if in_temp && self.temp_exts.iter().any(|e| e == ext) {
            findings.push(Finding {
                rule: "win.temp.script_drop",
                severity: "critical",
                event_type: "file_create",
                summary: format!("script/dropper staged in temp: {path}"),
                evidence: json!({"path": path, "image": ev.get("image").cloned().unwrap_or(json!("")), "ext": ext}),
            });
        }
        // a fake-font dropper anywhere is critical (reuse cross-platform IOC)
        if low.ends_with(".woff2") && pyjson::truthy(ev.get("looks_like_text")) {
            findings.push(Finding {
                rule: "win.fake_font_drop",
                severity: "critical",
                event_type: "file_create",
                summary: format!("binary-disguised dropper written: {path}"),
                evidence: json!({"path": path}),
            });
        }
        findings
    }

    pub fn on_process_create(&self, ev: &Value) -> Vec<Finding> {
        let image = nt_basename(&field(ev, "image")).to_lowercase();
        let parent = nt_basename(&field(ev, "parent_image")).to_lowercase();
        let raw_cmd = ev.get("cmdline").cloned().unwrap_or(json!(""));
        let shown_cmd = field(ev, "cmdline");
        let cmd = shown_cmd.to_lowercase();
        let mut findings = Vec::new();

        if self.is_parent_child(&parent, &image) {
            findings.push(Finding {
                rule: "win.suspicious_spawn",
                severity: "high",
                event_type: "process_create",
                summary: format!("suspicious parent/child: {parent} -> {image}"),
                evidence: json!({"parent": parent, "image": image, "cmdline": raw_cmd}),
            });
        }

        // interpreter running something from temp
        if self.interpreters.contains(&image)
            && self.temp_markers.iter().any(|m| cmd.contains(m.as_str()))
        {
            findings.push(Finding {
                rule: "win.interp_from_temp",
                severity: "critical",
                event_type: "process_create",
                summary: format!("{image} executing from temp: {shown_cmd}"),
                evidence: json!({"image": image, "cmdline": raw_cmd}),
            });
        }

        // shutdown/reboot initiated by a script/dev tool
        if (self.reboot_initiators.contains(&image) || cmd.contains("shutdown"))
            && (self.interpreters.contains(&parent) || self.is_parent_child(&parent, &image))
        {
            findings.push(Finding {
                rule: "win.script_initiated_reboot",
                severity: "critical",
                event_type: "process_create",
                summary: format!("reboot initiated by {parent}: {shown_cmd}"),
                evidence: json!({"parent": parent, "cmdline": raw_cmd}),
            });
        }

        // known payload/C2 strings in a command line
        let hits: Vec<&String> = self
            .payload_indicators
            .iter()
            .chain(&self.net_iocs)
            .filter(|s| cmd.contains(s.as_str()))
            .collect();
        if !hits.is_empty() {
            let shown: Vec<&str> = hits.iter().take(3).map(|s| s.as_str()).collect();
            findings.push(Finding {
                rule: "win.cmdline_ioc",
                severity: "critical",
                event_type: "process_create",
                summary: format!("command line matches incident IOCs: {}", shown.join(", ")),
                evidence: json!({"cmdline": raw_cmd, "iocs": hits.iter().take(5).collect::<Vec<_>>()}),
            });
        }
        findings
    }

    pub fn on_registry_set(&self, ev: &Value) -> Vec<Finding> {
        let key = field(ev, "key").to_lowercase();
        let data = field(ev, "value_data").to_lowercase();
        let mut findings = Vec::new();
        if self.reg_keys.iter().any(|k| key.contains(k.as_str())) {
            let ind: Vec<&String> = self
                .reg_value_ind
                .iter()
                .filter(|v| data.contains(v.as_str()) || key.contains(v.as_str()))
                .collect();
            let get = |k: &str| ev.get(k).cloned().unwrap_or(json!(""));
            findings.push(Finding {
                rule: "win.registry_persistence",
                severity: if ind.is_empty() { "high" } else { "critical" },
                event_type: "registry_set",
                summary: format!("write to persistence key: {}", field(ev, "key")),
                evidence: json!({"key": get("key"), "value_name": get("value_name"),
                                 "value_data": get("value_data"), "indicators": ind}),
            });
        }
        findings
    }

    /// `at`: when the reboot happened (microseconds since the epoch).
    pub fn on_reboot(&mut self, ev: &Value, at: i64) -> Vec<Finding> {
        let eid = int_of(ev.get("event_id"), 0);
        let initiator = field(ev, "initiator").to_lowercase();
        let raw_initiator = ev.get("initiator").cloned().unwrap_or(json!(""));
        let mut findings = Vec::new();

        // record and evaluate burst
        self.reboot_times.push(at);
        let cutoff = at - self.burst_window_minutes * 60_000_000;
        self.reboot_times.retain(|t| *t >= cutoff);
        if self.reboot_times.len() >= self.burst_count {
            findings.push(Finding {
                rule: "win.reboot_burst",
                severity: "critical",
                event_type: "reboot",
                summary: format!(
                    "{} reboots within {} (latest EID {eid}: {})",
                    self.reboot_times.len(),
                    timedelta_str(self.burst_window_minutes),
                    self.reboot_desc(eid)
                ),
                evidence: json!({"event_id": eid, "count": self.reboot_times.len(), "initiator": raw_initiator}),
            });
        }

        if eid == 1074
            && self
                .reboot_initiators
                .iter()
                .any(|p| initiator.contains(p.as_str()))
        {
            let who = match ev.get("initiator") {
                None => "?".to_string(),
                Some(_) => field(ev, "initiator"),
            };
            findings.push(Finding {
                rule: "win.forced_reboot",
                severity: "high",
                event_type: "reboot",
                summary: format!("reboot initiated by {who} (EID {eid})"),
                evidence: json!({"event_id": eid, "initiator": raw_initiator}),
            });
        } else if eid == 41 || eid == 6008 {
            findings.push(Finding {
                rule: "win.unexpected_reboot",
                severity: "high",
                event_type: "reboot",
                summary: format!(
                    "unexpected/unclean reboot (EID {eid}: {})",
                    self.reboot_desc(eid)
                ),
                evidence: json!({"event_id": eid}),
            });
        }
        findings
    }

    /// Route one normalized event; reboots without a parseable "ts" count as now.
    pub fn dispatch(&mut self, ev: &Value) -> Vec<Finding> {
        match ev.get("type").and_then(Value::as_str) {
            Some("file_create") => self.on_file_create(ev),
            Some("process_create") => self.on_process_create(ev),
            Some("registry_set") => self.on_registry_set(ev),
            Some("reboot") => {
                let at = ev
                    .get("ts")
                    .and_then(Value::as_str)
                    .and_then(parse_iso)
                    .unwrap_or_else(now_micros);
                self.on_reboot(ev, at)
            }
            _ => Vec::new(),
        }
    }
}

/// The sensor's alert and log files under GUARD_HOME.
struct Sink {
    alert_path: PathBuf,
    log_path: PathBuf,
}

impl Sink {
    fn new(home: &Path) -> Sink {
        let _ = std::fs::create_dir_all(home);
        Sink {
            alert_path: home.join("alerts.jsonl"),
            log_path: home.join("windows_sensor.log"),
        }
    }

    fn append(path: &Path, line: &str) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(format!("{line}\n").as_bytes());
        }
    }

    fn log(&self, msg: &str) {
        let line = format!("{}  {msg}", util::now_iso());
        println!("{line}");
        let _ = std::io::stdout().flush();
        Sink::append(&self.log_path, &line);
    }

    fn alert(&self, findings: &[Finding]) {
        for f in findings {
            let rec = json!({"ts": util::now_iso(), "kind": format!("win:{}", f.event_type),
                             "rule": f.rule, "severity": f.severity,
                             "summary": f.summary, "evidence": f.evidence});
            Sink::append(&self.alert_path, &pyjson::dumps(&rec, None, false));
            self.log(&format!("ALERT [{}] {}: {}", f.severity, f.rule, f.summary));
        }
    }
}

/// Synthetic events covering A/B/C plus one clean control (the last).
fn selftest_events() -> Vec<Value> {
    vec![
        json!({"type": "file_create", "path": r"C:\Users\dev\AppData\Local\Temp\stage9.py", "image": r"C:\Program Files\nodejs\node.exe"}),
        json!({"type": "process_create", "image": r"C:\Windows\System32\shutdown.exe", "parent_image": r"C:\Program Files\nodejs\node.exe", "cmdline": "shutdown /r /t 0"}),
        json!({"type": "process_create", "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "parent_image": r"C:\Program Files\nodejs\node.exe", "cmdline": "powershell -enc ZXZpbA=="}),
        json!({"type": "registry_set", "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "Updater", "value_data": r"python C:\Users\dev\AppData\Local\Temp\stage9.py", "image": "python.exe"}),
        json!({"type": "reboot", "event_id": 1074, "initiator": "shutdown.exe"}),
        json!({"type": "reboot", "event_id": 1074, "initiator": "shutdown.exe"}),
        json!({"type": "file_create", "path": r"C:\project\src\index.ts", "image": "Code.exe"}),
    ]
}

fn selftest(det: &mut Detector) -> u8 {
    let events = selftest_events();
    let mut total = 0;
    for ev in &events {
        for f in det.dispatch(ev) {
            total += 1;
            println!("[{}] {}: {}", f.severity.to_uppercase(), f.rule, f.summary);
        }
    }
    let clean = det
        .dispatch(events.last().expect("a clean control"))
        .is_empty();
    println!(
        "\nselftest: {total} finding(s); clean control produced none = {}",
        if clean { "OK" } else { "FAIL" }
    );
    0
}

/// Match normalized events, one JSON object per line, and alert like the live sensor.
fn replay(det: &mut Detector, path: &str) -> u8 {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("guard sensor: {path}: {e}");
            return 1;
        }
    };
    let sink = Sink::new(&util::guard_home());
    let mut total = 0;
    for (n, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("guard sensor: {path}: {e}");
                return 1;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let ev: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("guard sensor: {path}:{}: {e}", n + 1);
                return 1;
            }
        };
        let findings = det.dispatch(&ev);
        total += findings.len();
        sink.alert(&findings);
    }
    i32::from(total > 0) as u8
}

pub fn main(args: &[String]) -> u8 {
    let mut sig_path: Option<&str> = None;
    let mut mode: Option<(&str, Option<&str>)> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--signatures" => match it.next() {
                Some(p) => sig_path = Some(p),
                None => {
                    eprint!("guard sensor: --signatures needs a file\n{USAGE}");
                    return 2;
                }
            },
            "--selftest" => mode = Some(("selftest", None)),
            "--replay" => match it.next() {
                Some(p) => mode = Some(("replay", Some(p))),
                None => {
                    eprint!("guard sensor: --replay needs a file\n{USAGE}");
                    return 2;
                }
            },
            other => {
                eprint!("guard sensor: unknown argument {other}\n{USAGE}");
                return 2;
            }
        }
    }
    let sig = match scan::sigs::load(sig_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("guard sensor: {e}");
            return 1;
        }
    };
    let mut det = Detector::new(&sig);
    match mode {
        Some(("selftest", _)) => selftest(&mut det),
        Some((_, Some(path))) => replay(&mut det, path),
        _ => run_live(det),
    }
}

#[cfg(not(windows))]
fn run_live(_det: Detector) -> u8 {
    eprintln!("guard sensor: event sources run on Windows only; `guard sensor --selftest` runs the detection logic anywhere");
    2
}

#[cfg(windows)]
fn run_live(mut det: Detector) -> u8 {
    let sink = Sink::new(&util::guard_home());
    sink.log("windows sensor starting (Sysmon + System reboot sources)");
    let (tx, rx) = std::sync::mpsc::channel::<Value>();
    for (name, channel, query, normalize) in [
        ("SysmonSource", "Microsoft-Windows-Sysmon/Operational", "*", normalize_sysmon as fn(&str) -> Option<Value>),
        (
            "RebootSource",
            "System",
            "*[System[(EventID=1074 or EventID=1075 or EventID=41 or EventID=6008 or EventID=6006)]]",
            normalize_reboot,
        ),
    ] {
        if let Err(e) = evtlog::subscribe(channel, query, normalize, tx.clone()) {
            sink.log(&format!("source {name} error: {e}"));
        }
    }
    drop(tx);
    for ev in rx {
        let findings = det.dispatch(&ev);
        if !findings.is_empty() {
            sink.alert(&findings);
        }
    }
    // every subscription failed: keep alive like the Python sensor did
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Undo XML escaping in event text.
#[cfg_attr(not(windows), allow(dead_code))]
fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let ent = &tail[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .or_else(|| ent.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The EventID and the named EventData values of a rendered event.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_event_xml(xml: &str) -> Option<(String, Map<String, Value>)> {
    use std::sync::OnceLock;
    static EID: OnceLock<regex::Regex> = OnceLock::new();
    static DATA: OnceLock<regex::Regex> = OnceLock::new();
    let eid_re = EID.get_or_init(|| {
        regex::Regex::new(r"<EventID(?:\s[^>]*)?>\s*([^<]*?)\s*</EventID>").unwrap()
    });
    let data_re = DATA.get_or_init(|| {
        regex::Regex::new(r#"<Data\s+Name\s*=\s*(?:'([^']*)'|"([^"]*)")\s*(?:/>|>([^<]*)</Data>)"#)
            .unwrap()
    });
    if !xml.trim_start().starts_with('<') {
        return None;
    }
    let eid = xml_unescape(eid_re.captures(xml)?.get(1)?.as_str());
    let mut data = Map::new();
    for c in data_re.captures_iter(xml) {
        let name = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str());
        let text = c.get(3).map_or(String::new(), |m| xml_unescape(m.as_str()));
        data.insert(xml_unescape(name), Value::String(text));
    }
    Some((eid, data))
}

/// A Sysmon event (1 ProcessCreate, 11 FileCreate, 12/13/14 RegistryEvent),
/// normalized for the detector.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn normalize_sysmon(xml: &str) -> Option<Value> {
    let (eid, data) = parse_event_xml(xml)?;
    let get = |k: &str| data.get(k).cloned().unwrap_or(json!(""));
    let ts = util::now_iso();
    match eid.as_str() {
        "1" => Some(
            json!({"type": "process_create", "image": get("Image"), "parent_image": get("ParentImage"),
                           "cmdline": get("CommandLine"), "ts": ts}),
        ),
        "11" => Some(
            json!({"type": "file_create", "path": get("TargetFilename"), "image": get("Image"), "ts": ts}),
        ),
        "12" | "13" | "14" => Some(json!({"type": "registry_set", "key": get("TargetObject"),
                                          "value_data": get("Details"), "image": get("Image"), "ts": ts})),
        _ => None,
    }
}

/// A System-log reboot event (1074/1075/41/6008/6006), normalized.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn normalize_reboot(xml: &str) -> Option<Value> {
    let (eid, data) = parse_event_xml(xml)?;
    let s = |k: &str| {
        data.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let initiator = match s("param5") {
        p if !p.is_empty() => p,
        _ => s("ProcessName"),
    };
    Some(
        json!({"type": "reboot", "event_id": eid.trim().parse::<i64>().unwrap_or(0),
                "initiator": initiator, "reason": s("param3"), "ts": util::now_iso()}),
    )
}

/// Live subscriptions through the Windows Event Log API (wevtapi).
#[cfg(windows)]
mod evtlog {
    use std::ffi::c_void;
    use std::sync::mpsc::Sender;

    use serde_json::Value;
    use windows_sys::Win32::System::EventLog::{
        EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
        EvtSubscribeToFutureEvents, EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
    };

    struct Ctx {
        normalize: fn(&str) -> Option<Value>,
        tx: Sender<Value>,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn render_xml(event: EVT_HANDLE) -> Option<String> {
        let mut used = 0u32;
        let mut props = 0u32;
        // first call sizes the buffer
        unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                0,
                std::ptr::null_mut(),
                &mut used,
                &mut props,
            )
        };
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; (used as usize).div_ceil(2)];
        let ok = unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                (buf.len() * 2) as u32,
                buf.as_mut_ptr().cast(),
                &mut used,
                &mut props,
            )
        };
        if ok == 0 {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    unsafe extern "system" fn on_event(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        ctx: *const c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        if action == EvtSubscribeActionDeliver && !ctx.is_null() {
            let ctx = unsafe { &*(ctx as *const Ctx) };
            if let Some(ev) = render_xml(event).as_deref().and_then(ctx.normalize) {
                let _ = ctx.tx.send(ev);
            }
        }
        0
    }

    /// Deliver every future event on `channel` matching `query`, normalized, to `tx`.
    /// The subscription lives for the rest of the process.
    pub fn subscribe(
        channel: &str,
        query: &str,
        normalize: fn(&str) -> Option<Value>,
        tx: Sender<Value>,
    ) -> Result<(), String> {
        let ctx: *const Ctx = Box::into_raw(Box::new(Ctx { normalize, tx }));
        let (ch, q) = (wide(channel), wide(query));
        let h = unsafe {
            EvtSubscribe(
                0,
                std::ptr::null_mut(),
                ch.as_ptr(),
                q.as_ptr(),
                0,
                ctx.cast(),
                Some(on_event),
                EvtSubscribeToFutureEvents,
            )
        };
        if h == 0 {
            let err = std::io::Error::last_os_error();
            drop(unsafe { Box::from_raw(ctx as *mut Ctx) });
            return Err(format!("cannot subscribe to {channel}: {err}"));
        }
        // the subscription handle stays open while the sensor runs
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> Detector {
        Detector::new(&scan::sigs::load(None).unwrap())
    }

    #[test]
    fn paths_like_ntpath() {
        assert_eq!(
            nt_basename(r"C:\Windows\System32\shutdown.exe"),
            "shutdown.exe"
        );
        assert_eq!(nt_basename("a/b\\c.exe"), "c.exe");
        assert_eq!(nt_ext(r"c:\temp\stage9.py"), ".py");
        assert_eq!(nt_ext(r"c:\temp\.bashrc"), "");
        assert_eq!(nt_ext(r"c:\temp\..x.ps1"), ".ps1");
        assert_eq!(nt_ext(r"c:\te.mp\noext"), "");
    }

    #[test]
    fn timedelta_like_python() {
        assert_eq!(timedelta_str(180), "3:00:00");
        assert_eq!(timedelta_str(5), "0:05:00");
        assert_eq!(timedelta_str(1440), "1 day, 0:00:00");
        assert_eq!(timedelta_str(3000), "2 days, 2:00:00");
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(parse_iso("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(parse_iso("1970-01-01T01:00:00.5Z"), Some(3_600_500_000));
        assert_eq!(parse_iso("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(
            parse_iso("2026-10-06T00:00:00"),
            Some(1_791_244_800_000_000)
        );
        assert_eq!(parse_iso("yesterday"), None);
    }

    #[test]
    fn burst_needs_reboots_inside_the_window() {
        let mut d = det();
        let ev = json!({"type": "reboot", "event_id": 6006});
        let t0 = parse_iso("2026-10-06T09:00:00Z").unwrap();
        assert!(d.on_reboot(&ev, t0).is_empty());
        // 4 hours later: the first one has left the 3-hour window
        assert!(d.on_reboot(&ev, t0 + 4 * 3_600_000_000).is_empty());
        let f = d.on_reboot(&ev, t0 + 5 * 3_600_000_000);
        assert_eq!(f[0].rule, "win.reboot_burst");
        assert_eq!(
            f[0].summary,
            "2 reboots within 3:00:00 (latest EID 6006: event log stopped (clean shutdown marker))"
        );
    }

    #[test]
    fn clean_events_are_quiet() {
        let mut d = det();
        for ev in [
            json!({"type": "file_create", "path": r"C:\project\src\index.ts"}),
            json!({"type": "process_create", "image": r"C:\Windows\explorer.exe", "parent_image": r"C:\Windows\winlogon.exe", "cmdline": "explorer.exe"}),
            json!({"type": "registry_set", "key": r"HKCU\Software\Vendor\Settings", "value_data": "1"}),
            json!({"type": "something_else"}),
        ] {
            assert!(d.dispatch(&ev).is_empty(), "{ev}");
        }
    }

    #[test]
    fn normalizes_rendered_events() {
        let sysmon = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>11</EventID></System><EventData><Data Name='RuleName'>-</Data><Data Name='Image'>C:\Program Files\nodejs\node.exe</Data><Data Name='TargetFilename'>C:\Users\dev\AppData\Local\Temp\a&amp;b.py</Data></EventData></Event>"#;
        let ev = normalize_sysmon(sysmon).unwrap();
        assert_eq!(ev["type"], "file_create");
        assert_eq!(ev["path"], r"C:\Users\dev\AppData\Local\Temp\a&b.py");
        assert_eq!(ev["image"], r"C:\Program Files\nodejs\node.exe");
        let reg = sysmon
            .replace("<EventID>11<", "<EventID>13<")
            .replace("TargetFilename", "TargetObject");
        assert_eq!(
            normalize_sysmon(&reg).unwrap()["key"],
            r"C:\Users\dev\AppData\Local\Temp\a&b.py"
        );
        assert!(normalize_sysmon(&sysmon.replace("<EventID>11<", "<EventID>3<")).is_none());
        assert!(normalize_sysmon("not xml").is_none());

        let reboot = r#"<Event><System><EventID Qualifiers='32768'>1074</EventID></System><EventData><Data Name="param1">C:\Windows\system32\shutdown.exe (HOST)</Data><Data Name="param3">No title for this reason could be found</Data><Data Name="param5"/><Data Name="ProcessName">shutdown.exe</Data></EventData></Event>"#;
        let ev = normalize_reboot(reboot).unwrap();
        assert_eq!(ev["event_id"], 1074);
        assert_eq!(ev["initiator"], "shutdown.exe"); // param5 empty: falls back
        assert_eq!(ev["reason"], "No title for this reason could be found");
        assert_eq!(xml_unescape("&lt;&#65;&#x42;&bogus;&"), "<AB&bogus;&");
    }
}
