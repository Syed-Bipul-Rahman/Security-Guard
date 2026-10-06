//! `guard av`: the general antivirus engine (port of guard_av/cli.py).
//!
//!     guard av scan <path> [<path> ...] [--json] [--quarantine] [--fail-on-suspicious]
//!                   [--no-archives] [--no-heuristics] [--signatures DIR ...]
//!     guard av quarantine list | restore <id> [--to PATH] [--overwrite] | delete <id>
//!     guard av rules [--validate FILE ...]
//!     guard av hash <file> [...]
//!
//! Exit codes: 0 clean, 1 malicious found (or suspicious with
//! --fail-on-suspicious), 2 usage / error. Output matches the Python CLI.

mod allowlist;
mod archive;
mod engine;
mod filetype;
mod hashdb;
mod hashing;
mod heuristics;
mod model;
mod pystr;
mod quarantine;
mod rules;
mod yara;

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::pyjson;
use engine::{action_hint, Config, Engine};
use model::{ScanResult, Verdict};
use quarantine::Vault;

const USAGE: &str = "\
usage: guard av [-h] [--vault VAULT] {scan,quarantine,rules,hash} ...

Guard antivirus engine

positional arguments:
  {scan,quarantine,rules,hash}
    scan                scan files / directories
    quarantine          manage the quarantine vault
    rules               list or validate rules
    hash                print md5/sha1/sha256 of files

options:
  -h, --help            show this help message and exit
  --vault VAULT         quarantine vault directory
";

/// An argparse-style command line: long options (unique prefixes allowed,
/// `--opt=value` too), and one contiguous run of positionals.
struct Args {
    flags: Vec<String>,
    values: Vec<(String, String)>,
    positionals: Vec<String>,
}

impl Args {
    fn has(&self, f: &str) -> bool {
        self.flags.iter().any(|x| x == f)
    }
    fn value(&self, k: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    fn values(&self, k: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

fn usage_error(prog: &str, msg: &str) -> String {
    format!("usage: {prog} [-h] ...\n{prog}: error: {msg}")
}

/// `flags`: options without a value; `valued`: options taking one value;
/// `multi`: an option taking one or more values (rules --validate).
fn parse(
    prog: &str,
    argv: &[String],
    flags: &[&str],
    valued: &[&str],
    multi: Option<&str>,
    max_pos: usize,
) -> Result<Args, String> {
    let mut a = Args {
        flags: vec![],
        values: vec![],
        positionals: vec![],
    };
    let mut i = 0;
    let mut ended = false; // a positional run was followed by an option
    let mut after_dashes = false;
    let all: Vec<&str> = flags
        .iter()
        .chain(valued)
        .chain(multi.iter())
        .copied()
        .collect();
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        if !after_dashes && arg == "--" {
            after_dashes = true;
            continue;
        }
        if !after_dashes && arg.starts_with("--") && arg.len() > 2 {
            let (key, inline) = match arg.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (arg.as_str(), None),
            };
            let opt = match all.iter().find(|o| **o == key) {
                Some(o) => *o,
                None => {
                    let hits: Vec<&str> =
                        all.iter().filter(|o| o.starts_with(key)).copied().collect();
                    match hits.as_slice() {
                        [one] => *one,
                        [] => {
                            return Err(usage_error(
                                prog,
                                &format!("unrecognized arguments: {arg}"),
                            ))
                        }
                        many => {
                            return Err(usage_error(
                                prog,
                                &format!("ambiguous option: {key} could match {}", many.join(", ")),
                            ))
                        }
                    }
                }
            };
            if !a.positionals.is_empty() {
                ended = true;
            }
            if flags.contains(&opt) {
                if inline.is_some() {
                    return Err(usage_error(
                        prog,
                        &format!("argument {opt}: ignored explicit argument"),
                    ));
                }
                a.flags.push(opt.to_string());
            } else if Some(opt) == multi {
                let mut got = inline.into_iter().collect::<Vec<_>>();
                while i < argv.len() && !(argv[i].starts_with('-') && argv[i].len() > 1) {
                    got.push(argv[i].clone());
                    i += 1;
                }
                if got.is_empty() {
                    return Err(usage_error(
                        prog,
                        &format!("argument {opt}: expected at least one argument"),
                    ));
                }
                a.values
                    .extend(got.into_iter().map(|v| (opt.to_string(), v)));
            } else {
                let v = match inline {
                    Some(v) => v,
                    None if i < argv.len() && !(argv[i].starts_with('-') && argv[i].len() > 1) => {
                        i += 1;
                        argv[i - 1].clone()
                    }
                    None => {
                        return Err(usage_error(
                            prog,
                            &format!("argument {opt}: expected one argument"),
                        ))
                    }
                };
                a.values.push((opt.to_string(), v));
            }
            continue;
        }
        if !after_dashes && arg.starts_with('-') && arg.len() > 1 {
            return Err(usage_error(prog, &format!("unrecognized arguments: {arg}")));
        }
        if ended || a.positionals.len() >= max_pos {
            return Err(usage_error(prog, &format!("unrecognized arguments: {arg}")));
        }
        a.positionals.push(arg.clone());
    }
    Ok(a)
}

fn guard_home() -> PathBuf {
    crate::util::guard_home()
}

fn print_result(r: &ScanResult) {
    let hint = action_hint(r);
    let tag = if r.error.is_empty() {
        r.verdict.label().to_uppercase()
    } else {
        "ERROR".into()
    };
    let threat = r.threat_name();
    let mut line = format!("[{tag}] {}", r.path);
    if !threat.is_empty() {
        line.push_str(&format!("  {threat}"));
    }
    if !hint.is_empty() {
        line.push_str(&format!("  -> {hint}"));
    }
    if !r.error.is_empty() {
        line.push_str(&format!("  ({})", r.error));
    }
    println!("{line}");
    for d in r.all_detections() {
        let l = format!(
            "    - {}: {} [{}] {}",
            d.engine,
            d.name,
            d.verdict.label(),
            d.description
        );
        println!("{}", l.trim_end_matches(pystr::is_space));
    }
}

fn existing_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    dirs.into_iter().filter(|d| d.is_dir()).collect()
}

fn cmd_scan(vault: Option<&str>, argv: &[String]) -> Result<u8, String> {
    let a = parse(
        "guard av scan",
        argv,
        &[
            "--json",
            "--quarantine",
            "--fail-on-suspicious",
            "--no-archives",
            "--no-heuristics",
        ],
        &["--signatures"],
        None,
        usize::MAX,
    )?;
    if a.positionals.is_empty() {
        return Err(usage_error(
            "guard av scan",
            "the following arguments are required: paths",
        ));
    }
    let mut extra = vec![guard_home().join("av")];
    extra.extend(a.values("--signatures").into_iter().map(PathBuf::from));
    let cfg = Config {
        scan_archives: !a.has("--no-archives"),
        heuristics: !a.has("--no-heuristics"),
    };
    let mut engine = Engine::new(cfg, &existing_dirs(extra)).map_err(fatal)?;
    let vault = a.has("--quarantine").then(|| vault_for(vault));
    let as_json = a.has("--json");

    let missing: Vec<&str> = a
        .positionals
        .iter()
        .filter(|p| !Path::new(p.as_str()).exists())
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        eprintln!("no such file or directory: {}", missing.join(", "));
        return Ok(2);
    }

    let (mut scanned, mut malicious, mut suspicious, mut errors) = (0u64, 0u64, 0u64, 0u64);
    let mut elapsed = 0.0f64;
    let mut report = Vec::new();
    let mut quarantined: Vec<Map<String, Value>> = Vec::new();
    for target in &a.positionals {
        let mut show = |r: &ScanResult| {
            if !as_json && (!r.error.is_empty() || r.verdict != Verdict::Clean) {
                print_result(r);
            }
        };
        let s = engine.scan_path(target, &mut show);
        scanned += s.scanned;
        malicious += s.malicious;
        suspicious += s.suspicious;
        errors += s.errors;
        elapsed += (s.elapsed * 1000.0).round() / 1000.0;
        for r in &s.results {
            let mut entry = match r.to_json() {
                Value::Object(m) => m,
                _ => unreachable!(),
            };
            let hint = action_hint(r);
            entry.insert("action".into(), json!(hint));
            if let (Some(v), "quarantine") = (&vault, hint) {
                match v.quarantine(&r.path, &r.threat_name()) {
                    Ok(rec) => {
                        entry.insert("quarantine_id".into(), rec["id"].clone());
                        quarantined.push(rec);
                    }
                    Err(e) => {
                        entry.insert("quarantine_error".into(), json!(e));
                    }
                }
            }
            report.push(Value::Object(entry));
        }
    }

    if as_json {
        let mut summary = Map::new();
        summary.insert("scanned".into(), json!(scanned));
        summary.insert("malicious".into(), json!(malicious));
        summary.insert("suspicious".into(), json!(suspicious));
        summary.insert("errors".into(), json!(errors));
        summary.insert("elapsed_sec".into(), json!(elapsed));
        let out = json!({"summary": Value::Object(summary), "results": report});
        println!("{}", pyjson::dumps(&out, Some(2), false));
    } else {
        for rec in &quarantined {
            println!(
                "quarantined {} as {}",
                rec["original_path"].as_str().unwrap_or(""),
                rec["id"].as_str().unwrap_or("")
            );
        }
        println!(
            "\nscanned {scanned} file(s): {malicious} malicious, {suspicious} suspicious, {errors} error(s)"
        );
    }
    Ok(u8::from(
        malicious > 0 || (a.has("--fail-on-suspicious") && suspicious > 0),
    ))
}

fn vault_for(vault: Option<&str>) -> Vault {
    Vault::new(match vault {
        Some(v) => PathBuf::from(v),
        None => guard_home().join("av-quarantine"),
    })
}

fn cmd_quarantine(vault: Option<&str>, argv: &[String]) -> Result<u8, String> {
    let prog = "guard av quarantine";
    let Some(sub) = argv.first().filter(|s| !s.starts_with('-')) else {
        if argv.iter().any(|s| s == "-h" || s == "--help") {
            println!("usage: {prog} [-h] {{list,restore,delete}} ...");
            return Ok(0);
        }
        return Err(usage_error(
            prog,
            "the following arguments are required: qcmd",
        ));
    };
    let rest = &argv[1..];
    let v = vault_for(vault);
    let done = |r: Result<(), String>| match r {
        Ok(()) => Ok(0),
        Err(e) => {
            eprintln!("quarantine: {e}");
            Ok(2)
        }
    };
    match sub.as_str() {
        "list" => {
            parse("guard av quarantine list", rest, &[], &[], None, 0)?;
            println!("{}", pyjson::dumps(&Value::Array(v.list()), Some(2), false));
            Ok(0)
        }
        "restore" => {
            let a = parse("guard av quarantine restore", rest, &["--overwrite"], &["--to"], None, 1)?;
            let Some(id) = a.positionals.first() else {
                return Err(usage_error("guard av quarantine restore", "the following arguments are required: id"));
            };
            done(
                v.restore(id, a.value("--to"), a.has("--overwrite"))
                    .map(|t| println!("restored {t}")),
            )
        }
        "delete" => {
            let a = parse("guard av quarantine delete", rest, &[], &[], None, 1)?;
            let Some(id) = a.positionals.first() else {
                return Err(usage_error("guard av quarantine delete", "the following arguments are required: id"));
            };
            done(v.delete(id).map(|_| println!("deleted {id}")))
        }
        other => Err(usage_error(
            prog,
            &format!("argument qcmd: invalid choice: '{other}' (choose from 'list', 'restore', 'delete')"),
        )),
    }
}

/// Check one rules*.json or .yar file -> how many rules it holds.
fn validate(f: &str) -> Result<usize, String> {
    let bytes = std::fs::read(f).map_err(|e| pystr::os_error(&e, f))?;
    let suffix = pystr::suffix(f).to_lowercase();
    if !yara::SUFFIXES.contains(&suffix.as_str()) {
        let text = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        return rules::RuleSet::default().load_text(&text);
    }
    let mut y = yara::YaraRuleSet::default();
    y.load(&crate::deps::py_path_str(f), &bytes);
    y.compile()?;
    for w in y.warnings() {
        println!("WARN {f}: {w}");
    }
    Ok(y.len())
}

fn cmd_rules(argv: &[String]) -> Result<u8, String> {
    let a = parse("guard av rules", argv, &[], &[], Some("--validate"), 0)?;
    let files = a.values("--validate");
    if !files.is_empty() {
        let mut rc = 0;
        for f in files {
            match validate(&f) {
                Ok(n) => println!("OK   {f}: {n} rule(s)"),
                Err(e) => {
                    println!("FAIL {f}: {e}");
                    rc = 2;
                }
            }
        }
        return Ok(rc);
    }
    let home = guard_home().join("av");
    let cfg = Config {
        scan_archives: true,
        heuristics: true,
    };
    let engine = Engine::new(cfg, &existing_dirs(vec![home])).map_err(fatal)?;
    for r in &engine.rules.rules {
        println!(
            "{} {} {}",
            pad(&r.id, 45),
            pad(r.verdict.label(), 10),
            r.name
        );
    }
    println!(
        "\n{} rule(s), {} YARA rule(s), {} hash signature(s)",
        engine.rules.len(),
        engine.yara.len(),
        engine.hashdb.len()
    );
    Ok(0)
}

/// f"{s:N}": left-aligned, padded to N characters.
fn pad(s: &str, n: usize) -> String {
    let len = s.chars().count();
    format!("{s}{}", " ".repeat(n.saturating_sub(len)))
}

fn cmd_hash(argv: &[String]) -> Result<u8, String> {
    let a = parse("guard av hash", argv, &[], &[], None, usize::MAX)?;
    if a.positionals.is_empty() {
        return Err(usage_error(
            "guard av hash",
            "the following arguments are required: files",
        ));
    }
    let mut rc = 0;
    for f in &a.positionals {
        match hashing::hash_file(Path::new(f)) {
            Ok(h) => println!("{}  {}  {}  {f}", h.sha256, h.sha1, h.md5),
            Err(e) => {
                eprintln!("{f}: {}", pystr::os_error(&e, f));
                rc = 2;
            }
        }
    }
    Ok(rc)
}

/// A signature file that doesn't load stops the command, as in Python.
fn fatal(e: String) -> String {
    format!("FATAL:{e}")
}

pub fn main(argv: &[String]) -> u8 {
    let mut vault: Option<String> = None;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-h" || a == "--help" {
            print!("{USAGE}");
            return 0;
        }
        if let Some(v) = a.strip_prefix("--vault=") {
            vault = Some(v.into());
            i += 1;
        } else if a.len() > 2 && "--vault".starts_with(a.as_str()) {
            match argv.get(i + 1) {
                Some(v) => vault = Some(v.clone()),
                None => {
                    eprintln!(
                        "{}",
                        usage_error("guard av", "argument --vault: expected one argument")
                    );
                    return 2;
                }
            }
            i += 2;
        } else {
            break;
        }
    }
    let Some(cmd) = argv.get(i) else {
        eprintln!(
            "{}",
            usage_error("guard av", "the following arguments are required: cmd")
        );
        return 2;
    };
    let rest = &argv[i + 1..];
    if rest.iter().any(|s| s == "-h" || s == "--help") && cmd != "quarantine" {
        println!("usage: guard av {cmd} [-h] ...");
        return 0;
    }
    let v = vault.as_deref();
    let r = match cmd.as_str() {
        "scan" => cmd_scan(v, rest),
        "quarantine" => cmd_quarantine(v, rest),
        "rules" => cmd_rules(rest),
        "hash" => cmd_hash(rest),
        other => Err(usage_error(
            "guard av",
            &format!("argument cmd: invalid choice: '{other}' (choose from 'scan', 'quarantine', 'rules', 'hash')"),
        )),
    };
    match r {
        Ok(rc) => rc,
        Err(e) => match e.strip_prefix("FATAL:") {
            Some(m) => {
                eprintln!("guard av: {m}");
                1
            }
            None => {
                eprintln!("{e}");
                2
            }
        },
    }
}
