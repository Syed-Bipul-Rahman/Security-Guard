//! `guard sysmon-config`, `triage`, `notify-test`, `permissions`,
//! `install` / `uninstall` and `deps`, checked against goldens recorded from
//! guard.py and the Python tools it wraps. Was tests/test_rust_commands.py,
//! which ran both builds side by side with OS tools (systemctl, launchctl,
//! bash, notify-send, osascript) replaced by recording shims on PATH.

mod common;

use std::path::{Path, PathBuf};

use common::server::Server;
use common::*;
use serde_json::{json, Value};

const SUITE: &str = "commands";

/// Lookups that would leave the machine fail fast instead.
fn no_network(g: Guard) -> Guard {
    g.env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("https_proxy", "http://127.0.0.1:9")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
}

fn g(args: &[&str]) -> Guard {
    guard(args).env("PYTHONIOENCODING", "utf-8")
}

/// The interpreter for the Python-side wrappers (install, the advisory collector).
fn python() -> PathBuf {
    let name = std::env::var("GUARD_PYTHON").unwrap_or_else(|_| {
        if WINDOWS {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let exe = if WINDOWS && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.clone()
    };
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(&exe))
                .find(|c| c.is_file())
        })
        .unwrap_or_else(|| PathBuf::from(name))
}

/// `bin_args` on the binary; with GUARD_REFERENCE, `python -c script py_args`.
fn py_or_bin(script: &str, py_args: &[&str], bin_args: &[&str]) -> Guard {
    match reference() {
        Some(_) => {
            let mut args = vec!["-c", script];
            args.extend(py_args);
            g(&args).exe(&python())
        }
        None => g(bin_args),
    }
}

/// A fake OS tool on PATH that records how it was called.
#[cfg(unix)]
fn shim(bindir: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = write(&bindir.join(name), format!("#!/bin/sh\n{body}"));
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn shim_path(bindir: &Path) -> std::ffi::OsString {
    let mut dirs = vec![bindir.to_path_buf()];
    if let Some(p) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&p));
    }
    std::env::join_paths(dirs).unwrap()
}

fn golden_dir_has(name: &str) -> bool {
    let os = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(SUITE)
        .join(format!("{name}.{os}.b64"))
        .exists()
}

/// A golden for output that differs per OS: recorded on Linux; elsewhere it is
/// checked only when a per-OS golden was recorded (GUARD_GOLDEN=record-os).
fn os_golden(name: &str, actual: &str) {
    let recording = std::env::var("GUARD_GOLDEN").is_ok_and(|m| m.starts_with("record"));
    if cfg!(target_os = "linux") || recording || golden_dir_has(name) {
        golden(SUITE, name, actual);
    } else {
        eprintln!("no per-OS golden for {name}; only the asserts ran");
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The version string the build under test stamps.
fn build_version() -> String {
    match reference() {
        Some(py) => {
            let src = read(&py);
            let re = regex::Regex::new(r#"(?m)^VERSION = "([^"]+)""#).unwrap();
            re.captures(&src).unwrap()[1].to_string()
        }
        None => option_env!("GUARD_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
    }
}

// ------------------------------------------- sysmon-config, triage, notify, permissions
#[test]
fn sysmon_config() {
    let tmp = Tmp::new("sysmon");
    let xml = std::fs::read(repo_root().join("windows/sysmon-config.xml")).unwrap();
    let out = g(&["sysmon-config"]).run();
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.raw_stdout == xml,
        "stdout is not windows/sysmon-config.xml"
    );

    let n = Norm::new().path(&tmp.path, "TMP");
    let mut all = String::new();
    let dest = tmp.join("out.xml");
    let out = g(&["sysmon-config", &s(&dest)]).run();
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.trim(), format!("wrote {}", s(&dest)));
    assert!(std::fs::read(&dest).unwrap() == xml);
    all.push_str(&format!("=== write\n{}", n.apply(&out.shown_all())));

    let bad = tmp.join("missing").join("x.xml");
    let out = g(&["sysmon-config", &s(&bad)]).run();
    assert_eq!(out.code, 1);
    let prefix = format!("could not write {}: ", s(&bad));
    // the OS error text after the prefix differs between the builds
    assert!(out.stderr.starts_with(&prefix), "{}", out.stderr);
    all.push_str(&format!(
        "=== missing dir\nexit {}\n--- stdout\n{}--- stderr starts\n{}\n",
        out.code,
        out.stdout,
        n.apply(&prefix)
    ));
    golden(SUITE, "sysmon_config", &all);
}

/// triage runs the bundled bash script on Linux/macOS.
#[cfg(unix)]
#[test]
fn triage_runs_the_bundled_script() {
    let tmp = Tmp::new("triage");
    let shims = tmp.join("shims");
    // fake bash: keep a copy of the script it was given, echo the arguments
    shim(
        &shims,
        "bash",
        "cp \"$1\" \"$OUT_SCRIPT\"; shift; echo \"triage args: $*\"; exit 3\n",
    );
    let copy = tmp.join("script.sh");
    let out = g(&["triage", "--days", "3"])
        .env("PATH", shim_path(&shims))
        .env("OUT_SCRIPT", &copy)
        .run();
    assert_eq!(out.code, 3);
    assert_eq!(out.stdout, "triage args: --days 3\n");
    let script = std::fs::read(repo_root().join("linux/guard-triage-linux.sh")).unwrap();
    assert!(std::fs::read(&copy).unwrap() == script);
    golden(
        SUITE,
        "triage_runs_the_bundled_script",
        &Norm::new().path(&tmp.path, "TMP").apply(&out.shown_all()),
    );
}

/// guard.py's Windows triage message.
#[cfg(windows)]
#[test]
fn triage_on_windows() {
    let out = g(&["triage"]).run();
    assert_eq!(out.code, 0);
    assert_eq!(
        out.stdout,
        "On Windows, host triage uses the Sysmon-based sensor (`guard sensor`) + IR scripts.\n\
         Run:  guard-triage.ps1 / reboot-forensics.ps1 (bundled under windows/),\n\
         and install Sysmon with windows/sysmon-config.xml. See windows/README-windows-sensor.md.\n"
    );
}

/// Not on Windows: it would pop a real message box on the runner's console.
#[cfg(unix)]
#[test]
fn notify_test() {
    let tmp = Tmp::new("notify");
    let shims = tmp.join("shims");
    let tool = if cfg!(target_os = "macos") {
        "osascript"
    } else {
        "notify-send"
    };
    shim(
        &shims,
        tool,
        "for a in \"$@\"; do printf \"%s\\n\" \"$a\"; done > \"$OUT_ARGS\"\n",
    );
    let args = tmp.join("args");
    let out = g(&["notify-test"])
        .env("PATH", shim_path(&shims))
        .env("OUT_ARGS", &args)
        .run();
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "notified\n");
    let called = read(&args);
    assert!(called.contains("This is a TEST alert"), "{called}");
    os_golden(
        "notify_test",
        &format!("{}--- {tool} args\n{called}", out.shown_all()),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn notify_test_without_a_notifier() {
    let tmp = Tmp::new("no-notifier");
    let out = g(&["notify-test"]).env("PATH", &tmp.path).run();
    assert_eq!(out.code, 1);
    assert!(
        out.stdout.contains("no mechanism available"),
        "{}",
        out.stdout
    );
    golden(
        SUITE,
        "notify_test_without_a_notifier",
        &Norm::new().path(&tmp.path, "TMP").apply(&out.shown()),
    );
}

#[test]
fn permissions_check() {
    let mut all = String::new();
    for cmd in ["permissions", "perms"] {
        for action in [vec![], vec!["check"], vec!["CHECK"]] {
            let mut args = vec![cmd];
            args.extend(action);
            let out = g(&args).run();
            all.push_str(&format!("=== {}\n{}", args.join(" "), out.shown()));
        }
    }
    // the folders checked are the user's own
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        all = Norm::new().path(Path::new(&home), "userhome").apply(&all);
    }
    os_golden("permissions_check", &all);
}

/// Not on macOS: there it would raise real Allow prompts.
#[cfg(not(target_os = "macos"))]
#[test]
fn permissions_request_elsewhere_is_a_noop() {
    let out = g(&["permissions", "request"]).run();
    os_golden("permissions_request_elsewhere_is_a_noop", &out.shown());
}

// ------------------------------------------------------- install / uninstall
/// guard.py with its system paths moved under $GUARD_INSTALL_PREFIX (the
/// binary honours that variable itself) and the service exe set to $FAKE_EXE.
const PY_INSTALL: &str = r#"
import os, sys
sys.path.insert(0, os.environ["ROOT"])
import guard
p = os.environ["GUARD_INSTALL_PREFIX"]
for k in ("SYSTEMD_UNIT", "LAUNCHD_PLIST", "LAUNCHAGENT_PLIST"):
    setattr(guard, k, p + getattr(guard, k))
for d in ("/etc/systemd/system", "/Library/LaunchAgents", "/Library/LaunchDaemons"):
    os.makedirs(p + d, exist_ok=True)
guard._self_exe = lambda: os.environ["FAKE_EXE"]
sys.exit(guard.main(sys.argv[1:]))
"#;

#[cfg(unix)]
fn install(base: &Path, server: &Server, sudo_user: &str, cmd: &str) -> (Out, String) {
    let shims = base.join("shims");
    for tool in ["systemctl", "launchctl"] {
        shim(&shims, tool, &format!("echo \"{tool} $*\" >> \"$CALLS\"\n"));
    }
    std::fs::create_dir_all(base.join("prefix")).unwrap();
    let out = no_network(py_or_bin(PY_INSTALL, &[cmd], &[cmd]))
        .env("PATH", shim_path(&shims))
        .env("CALLS", base.join("calls"))
        .home(&base.join("home"))
        .env("GUARD_INSTALL_PREFIX", base.join("prefix"))
        .env("SUDO_USER", sudo_user)
        .env("FAKE_EXE", bin())
        .env("ROOT", repo_root())
        // what older releases read for telemetry: now ignored, nothing is sent
        .env(
            "GUARD_TELEMETRY_URL",
            format!("{}/api/telemetry", server.url),
        )
        .env("GUARD_INGEST_TOKEN", "tok-9")
        .run();
    let calls = std::fs::read_to_string(base.join("calls")).unwrap_or_default();
    std::fs::remove_file(base.join("calls")).ok();
    (out, calls)
}

fn keys(v: &Value) -> String {
    v.as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(",")
}

/// The user's home directory from /etc/passwd, as the watch roots spell it.
#[cfg(unix)]
fn passwd_home(user: &str) -> Option<String> {
    let pw = std::fs::read_to_string("/etc/passwd").ok()?;
    pw.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 5 && f[0] == user).then(|| f[5].to_string())
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn install_and_uninstall() {
    let tmp = Tmp::new("install");
    let server = Server::new();
    let base = tmp.join("b");
    let user = "nobody";
    let n = Norm::new().path(&base, "BASE").path(&bin(), "EXE");
    let linux = cfg!(target_os = "linux");
    let unit = if linux {
        "etc/systemd/system/guard.service"
    } else {
        "Library/LaunchAgents/me.syedbipul.guard.plist"
    };

    let (out, calls) = install(&base, &server, user, "install");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!calls.is_empty());
    let unit_text = read(&base.join("prefix").join(unit));
    assert!(unit_text.contains(&s(&bin())), "{unit_text}");
    let mut all = format!(
        "=== install\n{}--- calls\n{}--- {unit}\n{}",
        n.apply(&out.shown_all()),
        n.apply(&calls),
        n.apply(&unit_text)
    );
    if linux {
        // the service's state is seeded as guard.py seeded it
        let home = base.join("home");
        let stamp = parse_json(&read(&home.join("install.json")));
        assert_eq!(keys(&stamp), "installed_by,installed_at,version");
        assert_eq!(stamp["installed_by"], user);
        assert_eq!(stamp["version"].as_str(), Some(build_version().as_str()));
        let mut shown = stamp.clone();
        shown["installed_at"] = json!("<ts>");
        shown["version"] = json!("<version>");
        all.push_str(&format!("--- install.json\n{}", canon_json(&shown)));

        let wc = parse_json(&read(&home.join("watcher.config.json")));
        let roots = wc["watch_roots"].as_array().unwrap();
        let uh = passwd_home(user).unwrap_or_else(|| format!("/home/{user}"));
        let mut shown = Vec::new();
        for r in roots {
            let r = r.as_str().unwrap();
            let rest = r
                .strip_prefix(&format!("{uh}/"))
                .unwrap_or_else(|| panic!("{r} not under {uh}"));
            shown.push(format!("<userhome>/{rest}"));
        }
        all.push_str(&format!(
            "--- watcher.config.json\n{}",
            canon_json(&json!({"watch_roots": shown}))
        ));
        // no telemetry: install writes no collector config and sends nothing
        assert!(!home.join("telemetry.config.json").exists());
        assert!(server.posts().is_empty());
    }

    let (out, calls) = install(&base, &server, user, "uninstall");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!base.join("prefix").join(unit).exists());
    all.push_str(&format!(
        "=== uninstall\n{}--- calls\n{}",
        n.apply(&out.shown_all()),
        n.apply(&calls)
    ));
    os_golden("install_and_uninstall", &all);
}

/// Needs a directory this user cannot write: skipped as root.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn install_without_root() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: needs a non-root user to make a directory unwritable");
        return;
    }
    let tmp = Tmp::new("install-noroot");
    let server = Server::new();
    let base = tmp.join("b");
    let dirs = [
        "etc/systemd/system",
        "Library/LaunchAgents",
        "Library/LaunchDaemons",
    ];
    for d in dirs {
        let p = base.join("prefix").join(d);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "nobody".into());
    let (out, _) = install(&base, &server, &user, "install");
    for d in dirs {
        let p = base.join("prefix").join(d);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(out.code, 1);
    assert_eq!(
        out.stderr.trim(),
        "guard install needs root (run with sudo)"
    );
}

/// guard.py's Windows install message.
#[cfg(windows)]
#[test]
fn install_on_windows_points_at_guard_ps1() {
    let tmp = Tmp::new("install-win");
    let out = no_network(g(&["install"]).home(&tmp.join("home"))).run();
    assert_eq!(out.code, 0);
    assert_eq!(
        out.stdout,
        "Windows: install via guard.ps1 (it registers the GuardWatcher scheduled task).\n"
    );
}

// --------------------------------------------------------------- deps check
fn blocklist() -> Value {
    json!({
        "npm": {"evil-pkg": ["< 9.9.9"], "@bad/scope": [">= 0", "= 1.0.0"], "lock-only": [">= 0"],
                "yarn-evil": [">= 0"], "pnpm-evil": [">= 0"], "deep-evil": [">= 0"]},
        "pip": {"py-evil": ["< 2"], "pipfile-evil": [">= 0"], "poetry-evil": [">= 0"]},
    })
}

fn make_project(root: &Path) {
    let files: Vec<(&str, String)> = vec![
        (
            "package.json",
            json!({"dependencies": {"evil-pkg": "^1.2.0", "left-pad": "1.0.0"},
                   "devDependencies": {"@bad/scope": "1.0.0"}})
            .to_string(),
        ),
        (
            "sub/package-lock.json",
            json!({"packages": {"": {}, "node_modules/lock-only": {"version": "2.0.0"},
                                "node_modules/a/node_modules/evil-pkg": {"version": "0.5"}},
                   "dependencies": {"x": {"version": "1",
                                          "dependencies": {"deep-evil": {"version": "0.1"}}}}})
            .to_string(),
        ),
        (
            "yarn.lock",
            "# yarn\n\n\"yarn-evil@^1.0.0\", yarn-evil@~1:\n  version \"1.4.0\"\n\nok@1:\n  version \"1\"\n"
                .into(),
        ),
        (
            "pnpm-lock.yaml",
            "packages:\n  /pnpm-evil@3.1.0:\n    resolution: x\n  /@bad/scope@1.0.0(react@18):\n"
                .into(),
        ),
        (
            "requirements-dev.txt",
            "# dev\npy-evil == 1.5 ; python_version>'3'\n-r other.txt\nrequests\n".into(),
        ),
        (
            "Pipfile.lock",
            json!({"default": {"pipfile-evil": {"version": "==0.3"}}, "develop": {}}).to_string(),
        ),
        (
            "poetry.lock",
            "[[package]]\nname = \"poetry-evil\"\nversion = \"4.0\"\n".into(),
        ),
        (
            "node_modules/evil-pkg/package.json",
            json!({"dependencies": {"evil-pkg": "1"}}).to_string(),
        ),
        ("broken/package.json", "{not json".into()),
        ("notes.txt", "evil-pkg".into()),
    ];
    for (rel, text) in files {
        write(&root.join(rel), text);
    }
    write(
        &root.join("crlf/yarn.lock"),
        b"yarn-evil@1:\r\n  version \"9\"\r\n\r\n",
    );
}

fn deps_home(base: &Path, bl: Option<&Value>) -> PathBuf {
    std::fs::create_dir_all(base.join("feed")).unwrap();
    if let Some(bl) = bl {
        write(&base.join("feed/malware-blocklist.json"), bl.to_string());
    }
    base.to_path_buf()
}

#[test]
fn deps_check_finds_the_packages() {
    let tmp = Tmp::new("deps-check");
    let proj = tmp.join("proj");
    make_project(&proj);
    let home = deps_home(&tmp.join("home"), Some(&blocklist()));
    let n = Norm::new().path(&tmp.path, "TMP");
    let out = g(&["deps", "check", &s(&proj)]).home(&home).run();
    assert_eq!(out.code, 1, "{}", out.stderr);
    for name in [
        "evil-pkg",
        "@bad/scope",
        "lock-only",
        "yarn-evil",
        "pnpm-evil",
        "deep-evil",
        "py-evil",
        "pipfile-evil",
        "poetry-evil",
    ] {
        assert!(out.stdout.contains(&format!("] {name}  (")), "{name}");
    }
    let mut all = format!("=== <TMP>/proj\n{}", n.apply(&out.shown_all()));
    // relative targets, from inside the project
    for args in [
        vec!["deps", "check", "."],
        vec!["deps", "check"],
        vec!["deps", "check", "./sub/"],
    ] {
        let out = g(&args).home(&home).cwd(&proj).run();
        all.push_str(&format!(
            "=== {}\n{}",
            args.join(" "),
            n.apply(&out.shown_all())
        ));
    }
    golden(SUITE, "deps_check_finds_the_packages", &all);
}

/// check_deps.py crashes sorting a hit with no version next to one with a
/// version (None < str); the binary lists the versionless one first.
#[test]
fn deps_check_versionless_and_versioned_hits() {
    if reference().is_some() {
        return;
    }
    let tmp = Tmp::new("deps-versionless");
    let proj = tmp.join("proj");
    std::fs::create_dir_all(proj.join("sub")).unwrap();
    write(
        &proj.join("package.json"),
        json!({"dependencies": {"evil-pkg": "1.0.0"}}).to_string(),
    );
    write(
        &proj.join("package-lock.json"),
        json!({"packages": {"node_modules/evil-pkg": {}}}).to_string(),
    );
    let home = deps_home(&tmp.join("home"), Some(&blocklist()));
    let out = g(&["deps", "check", "."]).home(&home).cwd(&proj).run();
    assert_eq!(out.code, 1);
    let lines: Vec<&str> = out
        .stdout
        .lines()
        .filter(|l| l.starts_with("  [npm]"))
        .collect();
    assert_eq!(
        lines,
        [
            "  [npm] evil-pkg  (your version: ?; malicious range: < 9.9.9)",
            "  [npm] evil-pkg  (your version: 1.0.0; malicious range: < 9.9.9)"
        ]
    );
}

#[test]
fn deps_check_with_the_bundled_snapshot() {
    for target in [
        "testdata/fake-infected-repo",
        "testdata/clean-repo",
        "malware-feed",
    ] {
        let tmp = Tmp::new("deps-bundled");
        let home = deps_home(&tmp.join("home"), None);
        let out = g(&["deps", "check", target])
            .home(&home)
            .cwd(&repo_root())
            .run();
        assert!(
            out.stdout.contains("malicious package names across"),
            "{}",
            out.stdout
        );
        golden(
            SUITE,
            &format!(
                "deps_check_with_the_bundled_snapshot-{}",
                target.replace('/', "-")
            ),
            &Norm::new()
                .path(&tmp.path, "TMP")
                .path(&repo_root(), "REPO")
                .apply(&out.shown_all()),
        );
    }
}

#[test]
fn deps_usage_and_errors() {
    let tmp = Tmp::new("deps-usage");
    let home = tmp.join("home");
    let mut all = String::new();
    for args in [
        vec!["deps"],
        vec!["deps", "-h"],
        vec!["deps", "--help"],
        vec!["deps", "bogus"],
    ] {
        let out = g(&args).home(&home).run();
        if args[1..] == ["bogus"] {
            assert_eq!(out.stderr, "unknown deps subcommand: bogus\n");
        }
        all.push_str(&format!("=== {}\n{}", args.join(" "), out.shown_all()));
    }
    golden(SUITE, "deps_usage_and_errors", &all);
}

/// `deps check` without a feed uses exactly malware-feed/malware-blocklist.json.
#[test]
fn bundled_snapshot_is_the_committed_one() {
    let tmp = Tmp::new("deps-snapshot");
    let bl = parse_json(&read(
        &repo_root().join("malware-feed/malware-blocklist.json"),
    ));
    let bl = bl.as_object().unwrap();
    let total: usize = bl.values().map(|v| v.as_object().unwrap().len()).sum();
    let out = g(&["deps", "check", &s(&tmp.path)])
        .home(&tmp.join("h"))
        .run();
    assert_eq!(
        out.stdout.lines().next().unwrap_or(""),
        format!(
            "blocklist: {total} malicious package names across {} ecosystem(s)",
            bl.len()
        )
    );
}

// ------------------------------------- deps update (advisory API, served locally)
fn advisory(i: u32) -> Value {
    json!({"ghsa_id": format!("GHSA-{i:04}"), "summary": format!("Malicious package {i}\nsecond line"),
           "published_at": format!("2026-01-{i:02}T00:00:00Z"), "withdrawn_at": null,
           "cvss": {"score": 9.8},
           "vulnerabilities": [{"package": {"ecosystem": "npm", "name": format!("pkg-{i}")},
                                "vulnerable_version_range": ">= 0"}]})
}

fn with(mut a: Value, kw: Value) -> Value {
    for (k, v) in kw.as_object().unwrap() {
        a[k] = v.clone();
    }
    a
}

fn pages() -> [Value; 2] {
    [
        json!([
            advisory(1),
            with(
                advisory(2),
                json!({"summary": "na\u{ef}ve, \"quoted\" \u{2014} \u{3c0}", "cvss": {"score": 10.0}})
            ),
            with(advisory(3), json!({"withdrawn_at": "2026-02-01T00:00:00Z"})),
        ]),
        json!([
            with(
                advisory(4),
                json!({"vulnerabilities": [
                    {"package": {"ecosystem": "pip", "name": "py-a"}, "vulnerable_version_range": "< 1"},
                    {"package": {"ecosystem": "pip", "name": "py-a"}, "vulnerable_version_range": "= 2"},
                    {"package": {"ecosystem": "pip", "name": "py-a"}, "vulnerable_version_range": "< 1"},
                    {"package": {"ecosystem": "npm", "name": ""}},
                    {"package": {"ecosystem": "go", "name": "x/y"}, "vulnerable_version_range": null}]})
            ),
            advisory(1),
            with(
                advisory(5),
                json!({"summary": null, "vulnerabilities": null})
            ),
        ]),
    ]
}

fn serve_advisories(server: &Server, ecosystem: Option<&str>) -> String {
    let api = format!("{}/advisories", server.url);
    let mut first =
        "/advisories?type=malware&per_page=100&sort=published&direction=desc".to_string();
    if let Some(e) = ecosystem {
        first.push_str(&format!("&ecosystem={e}"));
    }
    let link = format!("<{api}?after=page2>; rel=\"next\", <{api}?x=1>; rel=\"prev\"");
    let [p1, p2] = pages();
    server.route(
        &first,
        200,
        &[("Link", &link), ("X-RateLimit-Remaining", "4999")],
        p1.to_string(),
    );
    server.route(
        "/advisories?after=page2",
        200,
        &[("X-RateLimit-Remaining", "4998")],
        p2.to_string(),
    );
    api
}

/// collect_malware_advisories.py with its API pointed at $GUARD_ADVISORY_API,
/// as `guard deps update` ran it (--out GUARD_HOME/feed --resume).
const PY_COLLECT: &str = r#"
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("collect", os.path.join(os.environ["ROOT"], "malware-feed", "collect_malware_advisories.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.API = os.environ["GUARD_ADVISORY_API"]
sys.argv = ["collect_malware_advisories.py"] + sys.argv[1:]
sys.exit(m.main())
"#;

const FEED_FILES: [&str; 4] = [
    "malware-blocklist.json",
    "malware-packages.csv",
    "malware-advisories.json",
    "collect-state.json",
];

fn update(home: &Path, api: &str, extra: &[&str]) -> Out {
    let feed = home.join("feed");
    std::fs::create_dir_all(&feed).unwrap();
    let feed_s = s(&feed);
    let mut py_args = vec!["--out", feed_s.as_str(), "--resume"];
    py_args.extend(extra);
    let mut bin_args = vec!["deps", "update"];
    bin_args.extend(extra);
    py_or_bin(PY_COLLECT, &py_args, &bin_args)
        .home(home)
        .env("GUARD_ADVISORY_API", api)
        .env("GITHUB_TOKEN", "tkn")
        .env("ROOT", repo_root())
        .run()
}

fn feed_files(feed: &Path) -> String {
    FEED_FILES
        .iter()
        .map(|f| format!("--- {f}\n{}", read(&feed.join(f))))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn deps_update_builds_the_feed() {
    let tmp = Tmp::new("deps-update");
    let server = Server::new();
    let api = serve_advisories(&server, None);
    let home = tmp.join("home");
    let feed = home.join("feed");
    let n = Norm::new()
        .path(&feed, "feed")
        .path(&tmp.path, "TMP")
        .lit(&server.url, "<server>");
    let out = update(&home, &api, &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let gets = server.gets();
    assert!(!gets.is_empty());
    for (p, h) in &gets {
        assert_eq!(
            h.get("authorization").map(String::as_str),
            Some("Bearer tkn"),
            "{p}"
        );
    }
    let bl = parse_json(&read(&feed.join("malware-blocklist.json")));
    assert!(bl["npm"].get("pkg-3").is_none());
    assert_eq!(bl["pip"]["py-a"], json!(["< 1", "= 2"]));
    let mut all = format!(
        "=== update\n{}{}",
        n.apply(&out.shown()),
        n.apply(&feed_files(&feed))
    );

    // a second run resumes from the saved cursor (end reached -> starts over, deduped)
    let out = update(&home, &api, &["--max-pages", "1"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("stopping at --max-pages 1"),
        "{}",
        out.stdout
    );
    all.push_str(&format!(
        "=== update --max-pages 1\n{}{}",
        n.apply(&out.shown()),
        n.apply(&feed_files(&feed))
    ));
    golden(SUITE, "deps_update_builds_the_feed", &all);
}

#[test]
fn deps_update_ecosystem() {
    let tmp = Tmp::new("deps-update-eco");
    let server = Server::new();
    let api = serve_advisories(&server, Some("npm"));
    let home = tmp.join("home");
    let out = update(&home, &api, &["--eco", "npm"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    golden(
        SUITE,
        "deps_update_ecosystem",
        &read(&home.join("feed/malware-blocklist.json")),
    );
}

/// argparse's errors, as the binary words them (the Python test checked only
/// the binary here).
#[test]
fn deps_update_bad_args() {
    let tmp = Tmp::new("deps-update-args");
    let home = tmp.join("h");
    let out = guard(&["deps", "update", "--max-pages", "x"])
        .exe(&bin())
        .home(&home)
        .run();
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("invalid int value: 'x'"),
        "{}",
        out.stderr
    );
    let out = guard(&["deps", "update", "--nope"])
        .exe(&bin())
        .home(&home)
        .run();
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("unrecognized arguments: --nope"),
        "{}",
        out.stderr
    );
}
