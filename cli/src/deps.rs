//! `guard deps`: the malware-package blocklist, ported from
//! malware-feed/check_deps.py (check) and collect_malware_advisories.py (update).
//!
//! check: scan a project's manifests and lockfiles for package names GitHub's
//! malware advisories flag. update: page through GitHub's advisory API
//! (type=malware), resumable and rate-limit aware, and rebuild the blocklist.
//! Output and files match the Python tools byte for byte.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::{net, pyjson, pyrepr, util};

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    "coverage",
    "venv",
    ".venv",
    "__pycache__",
];

/// The blocklist snapshot shipped in the binary (gzip, see build.rs), used until
/// the first `guard deps update`.
static BUNDLED_BLOCKLIST: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/malware-blocklist.json.gz"));

pub fn bundled_blocklist() -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(BUNDLED_BLOCKLIST)
        .read_to_end(&mut out)
        .expect("bundled blocklist");
    out
}

/// str(Path(s)): Python's normalised spelling of a path argument.
pub fn py_path_str(s: &str) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    let s = if cfg!(windows) {
        s.replace('/', "\\")
    } else {
        s.to_string()
    };
    let abs = s.starts_with(sep);
    let parts: Vec<&str> = s
        .split(sep)
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let body = parts.join(&sep.to_string());
    match (abs, body.is_empty()) {
        (true, _) => format!("{sep}{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

/// Path.read_text(encoding="utf-8"): strict UTF-8, universal newlines.
fn read_text(p: &Path) -> Option<String> {
    let s = fs::read_to_string(p).ok()?;
    Some(s.replace("\r\n", "\n").replace('\r', "\n"))
}

/// str() of a JSON value as Python prints it.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => pyrepr::repr(other),
    }
}

type Dep = (&'static str, String, Option<String>);

fn json_file(p: &Path) -> Option<Value> {
    serde_json::from_str(&read_text(p)?).ok()
}

fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.filter(|v| pyjson::truthy(Some(v)))
        .and_then(Value::as_object)
}

fn opt_version(meta: Option<&Value>) -> Option<String> {
    obj(meta)
        .and_then(|m| m.get("version"))
        .filter(|v| !v.is_null())
        .map(py_str)
}

fn parse_package_json(p: &Path, out: &mut Vec<Dep>) {
    let Some(Value::Object(data)) = json_file(p) else {
        return;
    };
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        for (name, ver) in obj(data.get(key)).into_iter().flatten() {
            out.push(("npm", name.clone(), Some(py_str(ver))));
        }
    }
}

fn walk_v1(deps: Option<&Value>, out: &mut Vec<Dep>) {
    for (name, meta) in obj(deps).into_iter().flatten() {
        out.push(("npm", name.clone(), opt_version(Some(meta))));
        walk_v1(obj(Some(meta)).and_then(|m| m.get("dependencies")), out);
    }
}

fn parse_package_lock(p: &Path, out: &mut Vec<Dep>) {
    let Some(Value::Object(data)) = json_file(p) else {
        return;
    };
    // npm v2/v3: "packages": { "node_modules/foo": {version}, ... }
    for (pkgpath, meta) in obj(data.get("packages")).into_iter().flatten() {
        if pkgpath.is_empty() {
            continue;
        }
        let name = pkgpath.rsplit("node_modules/").next().unwrap_or(pkgpath);
        out.push(("npm", name.to_string(), opt_version(Some(meta))));
    }
    // npm v1: "dependencies": { name: {version, dependencies} }
    walk_v1(data.get("dependencies"), out);
}

fn parse_yarn_lock(p: &Path, out: &mut Vec<Dep>) {
    let Some(text) = read_text(p) else { return };
    let names = Regex::new(r#"(?:^|,\s*)"?((?:@[^/@\s]+/)?[^@/\s"]+)@"#).unwrap();
    let version = Regex::new(r#"version\s+"([^"]+)""#).unwrap();
    for block in Regex::new(r"\n\n+").unwrap().split(&text) {
        let head = block.trim().split('\n').next().unwrap_or("");
        let ver = version.captures(block).map(|c| c[1].to_string());
        let found: BTreeSet<String> = names
            .captures_iter(head)
            .map(|c| c[1].to_string())
            .collect();
        for name in found {
            out.push(("npm", name, ver.clone()));
        }
    }
}

fn parse_pnpm_lock(p: &Path, out: &mut Vec<Dep>) {
    let Some(text) = read_text(p) else { return };
    let re = Regex::new(r"(?m)^\s*/?((?:@[^/@\s]+/)?[^@/\s]+)@([0-9][^\s:(]*)").unwrap();
    for c in re.captures_iter(&text) {
        out.push(("npm", c[1].to_string(), Some(c[2].to_string())));
    }
}

fn parse_requirements(p: &Path, out: &mut Vec<Dep>) {
    let Some(text) = read_text(p) else { return };
    let re = Regex::new(r"^([A-Za-z0-9._-]+)\s*(?:==\s*([^\s;]+))?").unwrap();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        if let Some(c) = re.captures(line) {
            out.push((
                "pip",
                c[1].to_string(),
                c.get(2).map(|m| m.as_str().to_string()),
            ));
        }
    }
}

fn parse_pipfile_lock(p: &Path, out: &mut Vec<Dep>) {
    let Some(Value::Object(data)) = json_file(p) else {
        return;
    };
    for sect in ["default", "develop"] {
        for (name, meta) in obj(data.get(sect)).into_iter().flatten() {
            let ver = obj(Some(meta))
                .and_then(|m| m.get("version"))
                .and_then(Value::as_str)
                .unwrap_or("");
            out.push((
                "pip",
                name.clone(),
                Some(ver.trim_start_matches('=').to_string()),
            ));
        }
    }
}

fn parse_poetry_lock(p: &Path, out: &mut Vec<Dep>) {
    let Some(text) = read_text(p) else { return };
    let re =
        Regex::new(r#"(?m)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)""#)
            .unwrap();
    for c in re.captures_iter(&text) {
        out.push(("pip", c[1].to_string(), Some(c[2].to_string())));
    }
}

type Parser = fn(&Path, &mut Vec<Dep>);

fn parser_for(name: &str) -> Option<Parser> {
    Some(match name {
        "package.json" => parse_package_json,
        "package-lock.json" | "npm-shrinkwrap.json" => parse_package_lock,
        "yarn.lock" => parse_yarn_lock,
        "pnpm-lock.yaml" => parse_pnpm_lock,
        "Pipfile.lock" => parse_pipfile_lock,
        "poetry.lock" => parse_poetry_lock,
        n if Regex::new(r"^requirements.*\.txt$").unwrap().is_match(n) => parse_requirements,
        _ => return None,
    })
}

/// Path.rglob("*") minus directories: recurses into real directories only.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let is_link = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        if p.is_dir() {
            if !is_link {
                walk(&p, out);
            }
        } else {
            out.push(p);
        }
    }
}

pub fn check(root_arg: &str, blocklist: &[u8]) -> Result<u8, String> {
    let bl: Map<String, Value> =
        match serde_json::from_slice(blocklist).map_err(|e| e.to_string())? {
            Value::Object(m) => m,
            _ => return Err("blocklist is not a JSON object".into()),
        };
    let total: usize = bl
        .values()
        .map(|v| v.as_object().map_or(0, |m| m.len()))
        .sum();
    let root_s = py_path_str(root_arg);
    let root = PathBuf::from(&root_s);
    println!(
        "blocklist: {total} malicious package names across {} ecosystem(s)",
        bl.len()
    );
    println!("scanning: {root_s}\n");

    let mut files = Vec::new();
    walk(&root, &mut files);
    let mut hits: HashSet<(String, String, Option<String>, String, String)> = HashSet::new();
    let mut scanned = 0;
    for path in files {
        let rel = path.strip_prefix(&root).unwrap_or(&path);
        let full = if root_s == "." {
            rel.to_path_buf()
        } else {
            path.clone()
        };
        let skipped = full
            .components()
            .any(|c| SKIP_DIRS.iter().any(|s| c.as_os_str() == *s));
        let Some(parse) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(parser_for)
        else {
            continue;
        };
        if skipped {
            continue;
        }
        scanned += 1;
        let mut deps = Vec::new();
        parse(&path, &mut deps);
        for (eco, name, ver) in deps {
            if let Some(ranges) = obj(bl.get(eco)).and_then(|m| m.get(&name)) {
                let range = ranges.as_array().map_or_else(
                    || py_str(ranges),
                    |a| a.iter().map(py_str).collect::<Vec<_>>().join(", "),
                );
                hits.insert((eco.to_string(), name, ver, range, rel.display().to_string()));
            }
        }
    }
    if !hits.is_empty() {
        let mut hits: Vec<_> = hits.into_iter().collect();
        hits.sort();
        println!("!!! MALICIOUS DEPENDENCIES FOUND !!!\n");
        for (eco, name, ver, range, place) in &hits {
            let ver = ver.as_deref().filter(|v| !v.is_empty()).unwrap_or("?");
            println!("  [{eco}] {name}  (your version: {ver}; malicious range: {range})");
            println!("        in {place}");
        }
        println!(
            "\n{} malicious dependency reference(s) in {scanned} manifest file(s).",
            hits.len()
        );
        println!("Remove/replace these, audit for compromise, and rotate any secrets the build could reach.");
        return Ok(1);
    }
    println!("clean: no blocklisted packages in {scanned} manifest file(s).");
    Ok(0)
}

// ---------------------------------------------------------------------------
// update: GitHub malware advisories -> blocklist
// ---------------------------------------------------------------------------
fn api_base() -> String {
    // GUARD_ADVISORY_API points at a mirror (or a test server)
    std::env::var("GUARD_ADVISORY_API")
        .unwrap_or_else(|_| "https://api.github.com/advisories".into())
}

fn get_token(cli: Option<&str>) -> Option<String> {
    if let Some(t) = cli.filter(|t| !t.is_empty()) {
        return Some(t.to_string());
    }
    if let Ok(t) = std::env::var("GITHUB_TOKEN") {
        if !t.is_empty() {
            return Some(t.trim().to_string());
        }
    }
    let out = Command::new("gh").args(["auth", "token"]).output().ok()?;
    let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !t.is_empty()).then_some(t)
}

pub fn parse_next(link: Option<&str>) -> Option<String> {
    for part in link?.split(',') {
        let seg: Vec<&str> = part.split(';').collect();
        if seg.len() < 2 {
            continue;
        }
        let url = seg[0].trim().trim_matches(|c| c == '<' || c == '>');
        if seg[1..].iter().any(|s| s.contains("rel=\"next\"")) {
            return Some(url.to_string());
        }
    }
    None
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn sleep(secs: f64) {
    std::thread::sleep(Duration::from_secs_f64(secs.max(0.0)));
}

fn request(url: &str, token: Option<&str>) -> Result<(Value, net::Response), String> {
    let client = net::Client::new(
        url,
        "guard-malware-feed",
        Duration::from_secs(30),
        false,
        false,
    )?;
    let auth = token.map(|t| format!("Bearer {t}"));
    let mut headers = vec![
        ("Accept", "application/vnd.github+json"),
        ("X-GitHub-Api-Version", "2022-11-28"),
    ];
    if let Some(a) = auth.as_deref() {
        headers.push(("Authorization", a));
    }
    let mut last_err = String::from("None");
    for attempt in 1..=4u32 {
        match client.get(url, &headers) {
            Ok(r) if (200..300).contains(&r.status) => {
                let data = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
                return Ok((data, r));
            }
            Ok(r) if r.status == 403 || r.status == 429 => {
                // rate limited or abuse detection: honour Retry-After / reset
                let wait = if let Some(ra) = r
                    .header("Retry-After")
                    .and_then(|v| v.trim().parse::<f64>().ok())
                {
                    ra + 2.0
                } else if let Some(reset) = r
                    .header("X-RateLimit-Reset")
                    .and_then(|v| v.trim().parse::<f64>().ok())
                {
                    (reset - now()).max(0.0) + 3.0
                } else {
                    60.0
                };
                println!(
                    "  rate limited (HTTP {}); sleeping {}s...",
                    r.status, wait as i64
                );
                sleep(wait);
            }
            Ok(r) => {
                last_err = format!("HTTP Error {}", r.status);
                sleep(f64::from(3 * attempt));
            }
            Err(e) => {
                last_err = e;
                sleep(f64::from(3 * attempt));
            }
        }
    }
    Err(format!(
        "request failed after 4 attempts: {url} ({last_err})"
    ))
}

fn throttle(r: &net::Response) {
    let remaining = r
        .header("X-RateLimit-Remaining")
        .unwrap_or("9999")
        .trim()
        .parse::<i64>();
    let reset = match r.header("X-RateLimit-Reset") {
        Some(v) => v.trim().parse::<i64>(),
        None => Ok(now() as i64 + 60),
    };
    let (Ok(remaining), Ok(reset)) = (remaining, reset) else {
        return;
    };
    if remaining <= 1 {
        let wait = (reset as f64 - now()).max(0.0) + 3.0;
        println!(
            "  budget exhausted ({remaining} left); sleeping {}s until reset...",
            wait as i64
        );
        sleep(wait);
    }
}

/// urllib.parse.quote_plus
fn quote_plus(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".into(),
            b => format!("%{b:02X}"),
        })
        .collect()
}

struct UpdateArgs {
    token: Option<String>,
    ecosystem: Option<String>,
    out: String,
    max_pages: u64,
    resume: bool,
}

const UPDATE_USAGE: &str = "usage: guard deps update [-h] [--token TOKEN] [--ecosystem ECOSYSTEM] [--out OUT] [--max-pages MAX_PAGES] [--resume]";

/// The collector's argparse options (long options may be abbreviated).
fn parse_update_args(args: &[String]) -> Result<UpdateArgs, String> {
    const OPTS: [&str; 5] = ["--token", "--ecosystem", "--out", "--max-pages", "--resume"];
    let mut a = UpdateArgs {
        token: None,
        ecosystem: None,
        out: ".".into(),
        max_pages: 0,
        resume: false,
    };
    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (args[i].clone(), None),
        };
        if flag == "-h" || flag == "--help" {
            return Err(String::new());
        }
        let matches: Vec<&str> = OPTS
            .iter()
            .copied()
            .filter(|o| flag.len() > 2 && o.starts_with(flag.as_str()))
            .collect();
        let opt = match matches.as_slice() {
            [one] => *one,
            [] => return Err(format!("unrecognized arguments: {}", args[i..].join(" "))),
            many => {
                return Err(format!(
                    "ambiguous option: {flag} could match {}",
                    many.join(", ")
                ))
            }
        };
        if opt == "--resume" {
            a.resume = true;
            i += 1;
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                args.get(i)
                    .cloned()
                    .ok_or_else(|| format!("argument {opt}: expected one argument"))?
            }
        };
        match opt {
            "--token" => a.token = Some(value),
            "--ecosystem" => a.ecosystem = Some(value),
            "--out" => a.out = value,
            _ => {
                a.max_pages = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("argument --max-pages: invalid int value: '{value}'"))?
            }
        }
        i += 1;
    }
    Ok(a)
}

pub fn update(args: &[String]) -> Result<u8, String> {
    let a = match parse_update_args(args) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            println!("{UPDATE_USAGE}");
            return Ok(0);
        }
        Err(e) => {
            eprintln!("{UPDATE_USAGE}\nguard deps update: error: {e}");
            return Ok(2);
        }
    };
    let out = PathBuf::from(py_path_str(&a.out));
    fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let token = get_token(a.token.as_deref());
    println!(
        "auth: {}",
        if token.is_some() {
            "token"
        } else {
            "UNAUTHENTICATED (60 req/hr - slow; use a token)"
        }
    );

    let adv_path = out.join("malware-advisories.json");
    let state_path = out.join("collect-state.json");

    let mut advisories: Map<String, Value> = Map::new();
    if let Some(Value::Array(list)) =
        read_text(&adv_path).and_then(|t| serde_json::from_str(&t).ok())
    {
        for adv in list {
            if let Some(id) = adv.get("ghsa_id").map(py_str) {
                advisories.insert(id, adv);
            }
        }
    }

    let mut url = format!(
        "{}?type=malware&per_page=100&sort=published&direction=desc",
        api_base()
    );
    if let Some(eco) = &a.ecosystem {
        url.push_str(&format!("&ecosystem={}", quote_plus(eco)));
    }
    if a.resume {
        let saved = read_text(&state_path)
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| {
                v.get("next_url")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .filter(|u| !u.is_empty());
        if let Some(saved) = saved {
            url = saved;
            println!(
                "resuming from saved cursor ({} already collected)",
                advisories.len()
            );
        }
    }

    let save_all = |adv: &Map<String, Value>| {
        let list = Value::Array(adv.values().cloned().collect());
        util::write_text(&adv_path, &pyjson::dumps(&list, Some(1), false))
    };
    let mut page = 0u64;
    loop {
        page += 1;
        let (data, resp) = request(&url, token.as_deref())?;
        let mut new = 0;
        for adv in data.as_array().into_iter().flatten() {
            if let Some(id) = adv
                .get("ghsa_id")
                .filter(|g| pyjson::truthy(Some(g)))
                .map(py_str)
            {
                if !advisories.contains_key(&id) {
                    advisories.insert(id, adv.clone());
                    new += 1;
                }
            }
        }
        let next = parse_next(resp.header("Link"));
        let rem = resp
            .header("X-RateLimit-Remaining")
            .unwrap_or("?")
            .to_string();
        println!(
            "page {page}: +{new} new (total {}), budget {rem}",
            advisories.len()
        );
        // the cursor every page; the big advisories file only every 100 pages
        util::write_text(
            &state_path,
            &pyjson::dumps(&json!({"next_url": next}), None, false),
        )
        .map_err(|e| e.to_string())?;
        if page.is_multiple_of(100) {
            save_all(&advisories).map_err(|e| e.to_string())?;
        }
        if a.max_pages > 0 && page >= a.max_pages {
            println!("stopping at --max-pages {}", a.max_pages);
            break;
        }
        let Some(next) = next else {
            println!("reached end of results.");
            break;
        };
        url = next;
        throttle(&resp);
    }
    let _ = save_all(&advisories);
    build_outputs(&advisories, &out).map_err(|e| e.to_string())?;
    Ok(0)
}

/// csv.writer (excel dialect) row.
fn csv_row(fields: &[String]) -> String {
    let cells: Vec<String> = fields
        .iter()
        .map(|f| {
            if f.contains([',', '"', '\r', '\n']) {
                format!("\"{}\"", f.replace('"', "\"\""))
            } else {
                f.clone()
            }
        })
        .collect();
    format!("{}\r\n", cells.join(","))
}

fn text_or_empty(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(v) => py_str(v),
    }
}

pub fn build_outputs(advisories: &Map<String, Value>, out: &Path) -> std::io::Result<()> {
    let mut blocklist: Map<String, Value> = Map::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut eco_counts: Vec<(String, u64)> = Vec::new();
    for a in advisories.values() {
        let gid = text_or_empty(a.get("ghsa_id"));
        let summary = pyjson::or(a.get("summary"), None)
            .map(py_str)
            .unwrap_or_default()
            .replace('\n', " ");
        let published = text_or_empty(a.get("published_at"));
        let withdrawn = pyjson::truthy(a.get("withdrawn_at"));
        for v in a
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let empty = Map::new();
            let pkg = obj(v.get("package")).unwrap_or(&empty);
            let eco = text_or_empty(pkg.get("ecosystem"));
            let name = text_or_empty(pkg.get("name"));
            if name.is_empty() {
                continue;
            }
            let vr = pyjson::or(v.get("vulnerable_version_range"), None)
                .map(py_str)
                .unwrap_or_default();
            let status = if withdrawn { "withdrawn" } else { "active" };
            rows.push(vec![
                eco.clone(),
                name.clone(),
                vr.clone(),
                gid.clone(),
                status.into(),
                published.clone(),
                summary.clone(),
            ]);
            if !withdrawn {
                let entry = blocklist
                    .entry(eco.clone())
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .unwrap()
                    .entry(name)
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .unwrap();
                if !vr.is_empty() && !entry.contains(&json!(vr)) {
                    entry.push(json!(vr));
                }
                match eco_counts.iter_mut().find(|(e, _)| *e == eco) {
                    Some((_, n)) => *n += 1,
                    None => eco_counts.push((eco, 1)),
                }
            }
        }
    }
    let bl_path = out.join("malware-blocklist.json");
    let csv_path = out.join("malware-packages.csv");
    util::write_text(
        &bl_path,
        &pyjson::dumps(&Value::Object(blocklist.clone()), Some(1), true),
    )?;
    rows.sort();
    let mut csv = csv_row(
        &[
            "ecosystem",
            "package",
            "vulnerable_version_range",
            "ghsa_id",
            "status",
            "published_at",
            "summary",
        ]
        .map(String::from),
    );
    for r in &rows {
        csv.push_str(&csv_row(r));
    }
    fs::write(&csv_path, csv)?;

    println!("\n=== blocklist summary (active malware packages per ecosystem) ===");
    eco_counts.sort_by_key(|e| std::cmp::Reverse(e.1));
    for (eco, n) in &eco_counts {
        let uniq = blocklist
            .get(eco)
            .and_then(Value::as_object)
            .map_or(0, |m| m.len());
        println!("  {eco:<12} {n:>6} advisory-entries  ({uniq} unique package names)");
    }
    println!(
        "\n  advisories: {}   -> {}, {}",
        advisories.len(),
        bl_path.display(),
        csv_path.display()
    );
    Ok(())
}

/// `guard deps {update|check} ...`
pub fn main(args: &[String]) -> Result<u8, String> {
    let Some(sub) = args
        .first()
        .filter(|a| !matches!(a.as_str(), "-h" | "--help"))
    else {
        println!("usage: guard deps {{update|check}} ...");
        return Ok(0);
    };
    let rest = &args[1..];
    let feed = util::guard_home().join("feed");
    fs::create_dir_all(&feed).map_err(|e| format!("{}: {e}", feed.display()))?;
    match sub.as_str() {
        "update" => {
            let mut a = vec![
                "--out".to_string(),
                feed.display().to_string(),
                "--resume".into(),
            ];
            a.extend(rest.iter().cloned());
            update(&a)
        }
        "check" => {
            let bl = feed.join("malware-blocklist.json");
            // until the first `deps update`, use the snapshot shipped in the binary
            let data = if bl.exists() {
                fs::read(&bl).map_err(|e| e.to_string())?
            } else {
                bundled_blocklist()
            };
            let target = rest
                .first()
                .filter(|t| !t.starts_with('-'))
                .map_or(".", |t| t.as_str());
            check(target, &data)
        }
        other => {
            eprintln!("unknown deps subcommand: {other}");
            Ok(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_header() {
        let l =
            r#"<https://api.github.com/advisories?after=X>; rel="next", <https://a/b>; rel="prev""#;
        assert_eq!(
            parse_next(Some(l)).unwrap(),
            "https://api.github.com/advisories?after=X"
        );
        assert_eq!(parse_next(Some(r#"<u>; rel="prev""#)), None);
        assert_eq!(parse_next(None), None);
    }

    #[test]
    fn paths_like_python() {
        if !cfg!(windows) {
            assert_eq!(py_path_str("./a//b/"), "a/b");
            assert_eq!(py_path_str("."), ".");
            assert_eq!(py_path_str("/x/./y"), "/x/y");
        }
        assert_eq!(quote_plus("a b/c"), "a+b%2Fc");
    }

    #[test]
    fn csv_like_python() {
        let r = csv_row(&["a".into(), "b,c".into(), "q\"x".into(), String::new()]);
        assert_eq!(r, "a,\"b,c\",\"q\"\"x\",\r\n");
    }

    #[test]
    fn bundled_snapshot_is_json() {
        let v: Value = serde_json::from_slice(&bundled_blocklist()).unwrap();
        assert!(v.get("npm").is_some());
    }
}
