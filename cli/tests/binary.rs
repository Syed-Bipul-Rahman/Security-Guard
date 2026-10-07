//! CLI basics (version, usage) and the OTA updater against a signed update
//! channel, checked against goldens recorded from guard.py (Python). Was
//! tests/test_rust_binary.py, which ran updater.py in-process (posing as a
//! frozen build) next to the binary and compared logs, results and files.
//!
//! Each update scenario publishes a channel with the release signer
//! (release/, `sign-manifest build-and-sign`) under a freshly generated test
//! key, serves it over HTTP and runs `guard update` from a copy of the build
//! installed in a scratch bin dir, since the updater replaces the running
//! executable. With GUARD_REFERENCE the installed copy is a small launcher
//! script that runs guard.py as a frozen build would (sys.frozen set,
//! sys.executable pointing at the launcher), as the Python test did.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use common::server::Server;
use common::*;
use serde_json::Value;

const SUITE: &str = "binary";

const OLD_BIN: &[u8] = b"OLD-GUARD-BINARY";
const NEW_BIN: &[u8] = b"NEW-GUARD-BINARY";
const BLOCKLIST: &[u8] = b"{\"npm\": [\"evil-pkg\"]}";
const EXE: &str = if WINDOWS { ".exe" } else { "" };

// ----------------------------------------------------------------- helpers
/// The version the build under test reports (`guard version`).
fn current() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| {
        let out = guard(&["version"]).run();
        assert_eq!(out.code, 0, "{}", out.shown_all());
        out.stdout
            .trim()
            .strip_prefix("guard ")
            .unwrap_or_else(|| panic!("odd version line: {:?}", out.stdout))
            .to_string()
    })
}

/// The update platform key, as updater.py / update.rs compute it.
fn platform_key() -> String {
    let arch = match std::env::consts::ARCH {
        "aarch64" | "arm64" => "arm64",
        "x86_64" | "amd64" => "x64",
        other => other,
    };
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    format!("{os}-{arch}")
}

/// The interpreter for the reference launcher (GUARD_PYTHON, else python3 on PATH).
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

/// The release signer, built once.
fn signer() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let release = repo_root().join("release");
        let target = release.join("target");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let st = Command::new(cargo)
            .args([
                "build",
                "--release",
                "--locked",
                "--quiet",
                "--manifest-path",
            ])
            .arg(release.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .status()
            .expect("run cargo to build the signer");
        assert!(st.success(), "building release/ (sign-manifest) failed");
        target.join("release").join(format!("sign-manifest{EXE}"))
    })
}

fn sign_tool(args: &[&std::ffi::OsStr]) -> String {
    let o = Command::new(signer()).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "sign-manifest {args:?} failed: {}",
        text(&o.stderr)
    );
    text(&o.stdout)
}

/// Test signing keys, generated once: (seed file, public key hex).
struct Keys {
    _tmp: Tmp,
    main: (PathBuf, String),
    other: String,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let tmp = Tmp::new("binary-keys");
        let gen = |name: &str| {
            let p = tmp.join(name);
            let out = sign_tool(&["keygen".as_ref(), "--out".as_ref(), p.as_os_str()]);
            let pk = out
                .lines()
                .map(str::trim)
                .find(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or_else(|| panic!("no public key in keygen output:\n{out}"))
                .to_string();
            (p, pk)
        };
        let main = gen("signing.key");
        let other = gen("other.key").1;
        Keys {
            _tmp: tmp,
            main,
            other,
        }
    })
}

fn pubkey() -> &'static str {
    &keys().main.1
}

/// A served update channel (the Python `channel` fixture).
struct Channel {
    root: PathBuf,
    srv: Server,
}

impl Channel {
    fn new(tmp: &Tmp) -> Channel {
        let root = tmp.join("channel");
        fs::create_dir_all(&root).unwrap();
        let srv = Server::serve_dir(root.clone());
        Channel { root, srv }
    }
    fn base(&self) -> &str {
        &self.srv.url
    }
}

struct Publish<'a> {
    version: &'a str,
    min_version: &'a str,
    plat: Option<&'a str>,
    binary: bool,
    blocklist: Option<&'a [u8]>,
    binary_bytes: &'a [u8],
}

impl Default for Publish<'_> {
    fn default() -> Self {
        Publish {
            version: "9.0.0",
            min_version: "0.0.0",
            plat: None,
            binary: true,
            blocklist: Some(BLOCKLIST),
            binary_bytes: NEW_BIN,
        }
    }
}

fn publish(ch: &Channel, p: Publish) {
    let manifest = ch.root.join("manifest.json");
    let mut args: Vec<std::ffi::OsString> = vec![
        "build-and-sign".into(),
        "--version".into(),
        p.version.into(),
        "--min-version".into(),
        p.min_version.into(),
        "--key".into(),
        keys().main.0.clone().into(),
        "--base-url".into(),
        ch.base().into(),
        "--out".into(),
        manifest.into(),
    ];
    if let Some(bl) = p.blocklist {
        let f = write(&ch.root.join("malware-blocklist.json"), bl);
        args.extend(["--blocklist".into(), f.into()]);
    }
    if p.binary {
        let plat = p.plat.map(str::to_string).unwrap_or_else(platform_key);
        let f = write(&ch.root.join(format!("guard-{plat}")), p.binary_bytes);
        let mut spec = std::ffi::OsString::from(format!("{plat}="));
        spec.push(f.as_os_str());
        args.extend(["--binary".into(), spec]);
    }
    let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
    sign_tool(&refs);
}

fn sign_raw(ch: &Channel, raw: &[u8]) {
    let m = write(&ch.root.join("manifest.json"), raw);
    sign_tool(&[
        "sign".as_ref(),
        m.as_os_str(),
        "--key".as_ref(),
        keys().main.0.as_os_str(),
    ]);
}

/// One installed copy: a home dir and the executable the updater replaces.
/// The build under test, or with GUARD_REFERENCE a launcher for guard.py.
struct Install {
    home: PathBuf,
    bindir: PathBuf,
    exe: PathBuf,
    original: Vec<u8>,
}

impl Install {
    fn new(base: &Path) -> Install {
        let bytes = match reference() {
            Some(py) => launcher(&py),
            None => fs::read(bin()).unwrap(),
        };
        Install::with_bytes(base, &bytes)
    }
    fn with_bytes(base: &Path, bytes: &[u8]) -> Install {
        let home = base.join("home");
        let bindir = base.join("bin");
        let exe = write(&bindir.join(format!("guard{EXE}")), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Install {
            home,
            bindir,
            exe,
            original: bytes.to_vec(),
        }
    }
    fn blocklist(&self) -> PathBuf {
        self.home.join("feed").join("malware-blocklist.json")
    }
    fn names(&self) -> Vec<String> {
        let mut n: Vec<String> = fs::read_dir(&self.bindir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    }
    /// `guard update` from this install against `base`.
    fn update(&self, base: &str, pubkey: &str, py_version: Option<&str>) -> Out {
        let cmd = if reference().is_some() {
            let mut c = guard(&[s(&self.exe), "update".into()])
                .exe(&python())
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .env("PYTHONIOENCODING", "utf-8");
            if let Some(v) = py_version {
                c = c.env("GUARD_TEST_PY_VERSION", v);
            }
            c
        } else {
            guard(&["update"]).exe(&self.exe)
        };
        cmd.home(&self.home)
            .env("GUARD_UPDATE_URL", base)
            .env("GUARD_UPDATE_PUBKEY", pubkey)
            .run()
    }
    fn replaced(&self) -> bool {
        fs::read(&self.exe).unwrap() == NEW_BIN
    }
    fn backup_is_original(&self) -> bool {
        self.names()
            .iter()
            .filter(|n| *n == "guard.bak" || *n == "guard.old.exe")
            .any(|n| fs::read(self.bindir.join(n)).unwrap() == self.original)
    }
    /// What test_rust_binary.py's Install.state() compared.
    fn state(&self) -> String {
        let files: Vec<String> = self
            .names()
            .iter()
            .map(|n| n.replace(&format!("guard{EXE}"), "guard"))
            .collect();
        let bl = match fs::read(self.blocklist()) {
            Ok(b) => text(&b),
            Err(_) => "<none>".into(),
        };
        format!(
            "files: {}\nreplaced: {}\nbackup_is_original: {}\nblocklist: {}\n",
            files.join(" "),
            self.replaced(),
            self.backup_is_original(),
            bl
        )
    }
}

/// An installed "frozen" Python build: guard.py's main() with sys.frozen set
/// and sys.executable at this file, so updater.py swaps the file itself.
fn launcher(guard_py: &Path) -> Vec<u8> {
    let repo = fs::canonicalize(guard_py.parent().unwrap()).unwrap();
    format!(
        "import os, sys\n\
         sys.dont_write_bytecode = True\n\
         sys.path.insert(0, {repo:?})\n\
         sys.frozen = True\n\
         sys.executable = os.path.abspath(__file__)\n\
         import guard\n\
         if os.environ.get('GUARD_TEST_PY_VERSION'):\n    \
             guard.VERSION = os.environ['GUARD_TEST_PY_VERSION']\n\
         sys.exit(guard.main(sys.argv[1:]))\n",
        repo = s(&repo)
    )
    .into_bytes()
}

fn norm(tmp: &Tmp, ch: &Channel) -> Norm {
    let cur = current();
    Norm::new()
        .path(&tmp.path, "TMP")
        .lit(ch.base(), "<URL>")
        .lit(&platform_key(), "<PLAT>")
        // the running version changes with every release
        .lit(&format!("updated {cur} ->"), "updated <VERSION> ->")
        .lit(&format!("current {cur} below"), "current <VERSION> below")
        .lit(
            &format!("'offered_version': '{cur}'"),
            "'offered_version': '<VERSION>'",
        )
}

/// A field of the result dict on the last stdout line, as Python repr text.
fn res_field(out: &Out, key: &str) -> String {
    let last = out.stdout.lines().last().unwrap_or_default();
    let pat = format!("'{key}': ");
    let at = last
        .find(&pat)
        .unwrap_or_else(|| panic!("no {key} in {last:?}"));
    let rest = &last[at + pat.len()..];
    rest[..rest.find([',', '}']).unwrap()].to_string()
}

fn log_lines(out: &Out) -> Vec<&str> {
    let mut l: Vec<&str> = out.stdout.lines().collect();
    l.pop();
    l
}

/// Install, update, golden; returns the output and the install for asserts.
fn run_update(name: &str, tmp: &Tmp, ch: &Channel, pubkey: &str, readonly: bool) -> (Out, Install) {
    let inst = Install::new(&tmp.join("inst"));
    #[cfg(unix)]
    let set_mode = |m: u32| {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&inst.bindir, fs::Permissions::from_mode(m)).unwrap();
    };
    #[cfg(unix)]
    if readonly {
        set_mode(0o555);
    }
    let out = inst.update(ch.base(), pubkey, None);
    #[cfg(unix)]
    if readonly {
        set_mode(0o755);
    }
    #[cfg(not(unix))]
    let _ = readonly;
    assert_eq!(out.code, 0, "{}", out.shown_all());
    let n = norm(tmp, ch);
    golden(
        SUITE,
        name,
        &format!("{}--- state\n{}", n.apply(&out.shown_all()), inst.state()),
    );
    (out, inst)
}

// --------------------------------------------------------------- CLI basics
#[test]
fn version() {
    let out = guard(&["version"]).run();
    let cur = current();
    golden(
        SUITE,
        "version",
        &out.shown_all()
            .replace(&format!("guard {cur}\n"), "guard <VERSION>\n"),
    );
    let pkg = env!("CARGO_PKG_VERSION");
    match std::env::var("GUARD_VERSION") {
        // the reference build reports its own VERSION, not the release one
        Ok(v) if !v.is_empty() => {
            if reference().is_none() {
                assert_eq!(cur, v)
            }
        }
        _ => {
            // a release build rewrites guard.py's VERSION (and bakes GUARD_VERSION in)
            assert_eq!(cur, pkg);
            let py = repo_root().join("guard.py");
            if let Ok(src) = fs::read_to_string(py) {
                let re = regex::Regex::new(r#"(?m)^VERSION = "([^"]+)""#).unwrap();
                if let Some(c) = re.captures(&src) {
                    assert_eq!(&c[1], pkg, "guard.py VERSION vs cli/Cargo.toml");
                }
            }
        }
    }
}

#[test]
fn help_and_unknown() {
    // The usage text itself differs on purpose (the binary lists `update`,
    // `telemetry`, `sensor`, ...), so the golden holds exit codes and the
    // shape: every help spelling prints the same text to stdout, and an
    // unknown command names itself on stderr, then prints that text.
    let mut shown = String::new();
    let mut usage: Option<String> = None;
    for args in [vec![], vec!["help"], vec!["-h"], vec!["--help"]] {
        let out = guard(&args).run();
        shown.push_str(&format!(
            "$ guard {}\nexit {}\nstderr empty: {}\nsame usage: {}\n",
            args.join(" "),
            out.code,
            out.stderr.is_empty(),
            *usage.get_or_insert_with(|| out.stdout.clone()) == out.stdout
        ));
        if reference().is_none() {
            assert!(out.stdout.contains("guard update"), "{}", out.stdout);
        }
    }
    let usage = usage.unwrap();
    let out = guard(&["bogus"]).run();
    let (first, rest) = out.stderr.split_once('\n').unwrap_or((&out.stderr, ""));
    shown.push_str(&format!(
        "$ guard bogus\nexit {}\nstdout empty: {}\nstderr line 1: {first}\nthen a blank line and the usage: {}\n",
        out.code,
        out.stdout.is_empty(),
        rest.strip_prefix('\n').map(str::trim_end) == Some(usage.trim_end()),
    ));
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("unknown command: bogus"));
    golden(SUITE, "help-and-unknown", &shown);
}

// ---------------------------------------------------------- OTA update
#[test]
fn update_applies_blocklist_and_binary() {
    let tmp = Tmp::new("upd");
    let ch = Channel::new(&tmp);
    publish(&ch, Publish::default());
    let (out, inst) = run_update("update-applies", &tmp, &ch, pubkey(), false);
    assert_eq!(
        out.stdout.lines().last().unwrap(),
        "{'status': 'updated', 'blocklist_updated': True, 'binary_updated': True, 'offered_version': '9.0.0'}"
    );
    assert!(inst.replaced() && inst.backup_is_original());
    assert_eq!(fs::read(inst.blocklist()).unwrap(), BLOCKLIST);
    assert!(!inst.names().iter().any(|n| n == "guard.new"));
    assert_eq!(
        *log_lines(&out).last().unwrap(),
        format!(
            "updater: binary updated {} -> 9.0.0; restart to run it",
            current()
        )
    );
}

/// The switch: a release publishes the Rust binary under the same asset name.
/// An installed Python build verifies and installs it through the current
/// channel, and the Rust binary it installed then finds itself current.
///
/// Only the reference run can perform the first half (a Python build
/// replacing itself); without GUARD_REFERENCE the test lays down what it
/// leaves behind (the binary, the old build as guard.bak, the blocklist). The golden holds
/// the second half, which is the binary's behaviour in both modes.
#[test]
fn python_install_switches_to_rust_binary() {
    let tmp = Tmp::new("switch");
    let ch = Channel::new(&tmp);
    let rust = fs::read(bin()).unwrap();
    // the version the binary itself reports (not guard.py's)
    let rust_version = {
        let o = guard(&["version"]).exe(&bin()).run();
        o.stdout.trim().trim_start_matches("guard ").to_string()
    };
    publish(
        &ch,
        Publish {
            version: &rust_version,
            binary_bytes: &rust,
            ..Default::default()
        },
    );
    let base = tmp.join("inst");
    let inst = if let Some(py) = reference() {
        let inst = Install::with_bytes(&base, &launcher(&py));
        // "0" is older than any build, PR dry runs (0.0.0-prN) included
        let out = inst.update(ch.base(), pubkey(), Some("0"));
        assert_eq!(out.code, 0, "{}", out.shown_all());
        assert_eq!(res_field(&out, "binary_updated"), "True", "{}", out.stdout);
        inst
    } else {
        let inst = Install::with_bytes(&base, OLD_BIN);
        fs::copy(&inst.exe, inst.bindir.join("guard.bak")).unwrap();
        fs::write(&inst.exe, &rust).unwrap();
        write(&inst.blocklist(), BLOCKLIST);
        inst
    };
    assert!(fs::read(&inst.exe).unwrap() == rust && inst.backup_is_original());
    let env = |g: Guard| {
        g.exe(&inst.exe)
            .home(&inst.home)
            .env("GUARD_UPDATE_URL", ch.base())
            .env("GUARD_UPDATE_PUBKEY", pubkey())
    };
    let ver = env(guard(&["version"])).run();
    assert_eq!(ver.stdout.trim(), format!("guard {rust_version}"));
    let files = inst.names();
    let upd = env(guard(&["update"])).run();
    assert_eq!(upd.code, 0, "{}", upd.shown_all());
    assert_eq!(
        upd.stdout.lines().last().unwrap(),
        format!("{{'status': 'current', 'blocklist_updated': False, 'binary_updated': False, 'offered_version': '{rust_version}'}}")
    );
    assert!(inst.names() == files && fs::read(&inst.exe).unwrap() == rust);
    let n = norm(&tmp, &ch)
        .lit(&format!("guard {rust_version}\n"), "guard <VERSION>\n")
        .lit(
            &format!("'offered_version': '{rust_version}'"),
            "'offered_version': '<VERSION>'",
        );
    golden(
        SUITE,
        "python-install-switches",
        &format!(
            "$ guard version\n{}$ guard update\n{}--- files\n{}\n",
            n.apply(&ver.shown_all()),
            n.apply(&upd.shown_all()),
            files.join(" ")
        ),
    );
}

#[test]
fn current_blocklist_is_not_refetched() {
    let tmp = Tmp::new("current");
    let ch = Channel::new(&tmp);
    publish(
        &ch,
        Publish {
            binary: false,
            ..Default::default()
        },
    );
    let inst = Install::new(&tmp.join("inst"));
    write(&inst.blocklist(), BLOCKLIST);
    let out = inst.update(ch.base(), pubkey(), None);
    assert_eq!(out.code, 0, "{}", out.shown_all());
    assert_eq!(res_field(&out, "status"), "'current'");
    assert_eq!(res_field(&out, "blocklist_updated"), "False");
    golden(
        SUITE,
        "current-blocklist",
        &format!(
            "{}--- state\n{}",
            norm(&tmp, &ch).apply(&out.shown_all()),
            inst.state()
        ),
    );
}

#[test]
fn refuses_unverified_manifests() {
    for case in [
        "tampered-manifest",
        "wrong-key",
        "no-key",
        "malformed-sig",
        "not-json",
        "empty-manifest",
    ] {
        let tmp = Tmp::new("unverified");
        let ch = Channel::new(&tmp);
        publish(&ch, Publish::default());
        let mut pk = pubkey().to_string();
        match case {
            "tampered-manifest" => {
                let m = ch.root.join("manifest.json");
                let t = fs::read_to_string(&m).unwrap().replace("9.0.0", "9.0.1");
                fs::write(&m, t).unwrap();
            }
            "wrong-key" => pk = keys().other.clone(),
            "no-key" => pk = String::new(),
            "malformed-sig" => {
                fs::write(ch.root.join("manifest.json.sig"), "abc").unwrap();
            }
            "not-json" => sign_raw(&ch, b"not json"),
            "empty-manifest" => sign_raw(&ch, b"{}"),
            _ => unreachable!(),
        }
        let (out, inst) = run_update(&format!("unverified-{case}"), &tmp, &ch, &pk, false);
        assert_eq!(out.stdout.lines().last().unwrap(), "{'status': 'no-op'}");
        assert!(!inst.replaced() && !inst.blocklist().exists());
        let expected: &[&str] = match case {
            "tampered-manifest" | "wrong-key" => {
                &["updater: SIGNATURE INVALID -> refusing update (possible tampering)"]
            }
            "no-key" => &["updater: NO public key embedded -> refusing all updates (fail closed)"],
            "malformed-sig" => &["updater: malformed signature -> refusing"],
            "not-json" => &["updater: manifest not valid JSON -> refusing"],
            _ => &[],
        };
        assert_eq!(log_lines(&out), expected, "{case}");
    }
}

#[test]
fn tampered_binary_is_discarded() {
    let tmp = Tmp::new("tampered");
    let ch = Channel::new(&tmp);
    publish(&ch, Publish::default());
    fs::write(ch.root.join(format!("guard-{}", platform_key())), "EVIL").unwrap();
    let (out, inst) = run_update("tampered-binary", &tmp, &ch, pubkey(), false);
    assert_eq!(res_field(&out, "blocklist_updated"), "True");
    assert_eq!(res_field(&out, "binary_updated"), "False");
    assert!(!inst.replaced() && !inst.names().iter().any(|n| n == "guard.new"));
    assert!(log_lines(&out)
        .iter()
        .any(|l| l.contains("SHA-256 MISMATCH")));
}

#[test]
fn no_downgrade_or_reinstall() {
    for (name, version) in [("older", "0.0.0"), ("same", current())] {
        let tmp = Tmp::new("downgrade");
        let ch = Channel::new(&tmp);
        publish(
            &ch,
            Publish {
                version,
                ..Default::default()
            },
        );
        let (out, inst) = run_update(&format!("no-downgrade-{name}"), &tmp, &ch, pubkey(), false);
        assert_eq!(res_field(&out, "binary_updated"), "False");
        assert!(!inst.replaced());
    }
}

#[test]
fn forced_upgrade_is_logged() {
    let tmp = Tmp::new("forced");
    let ch = Channel::new(&tmp);
    publish(
        &ch,
        Publish {
            min_version: "8.0.0",
            ..Default::default()
        },
    );
    let (out, _) = run_update("forced-upgrade", &tmp, &ch, pubkey(), false);
    assert_eq!(res_field(&out, "binary_updated"), "True");
    let want = format!(
        "updater: current {} below min_version 8.0.0; forced upgrade",
        current()
    );
    assert!(log_lines(&out).contains(&want.as_str()), "{}", out.stdout);
}

#[test]
fn platform_keys_agree() {
    let tmp = Tmp::new("plat");
    let ch = Channel::new(&tmp);
    publish(
        &ch,
        Publish {
            plat: Some("plan9-x64"),
            ..Default::default()
        },
    );
    let (out, _) = run_update("platform-keys", &tmp, &ch, pubkey(), false);
    assert_eq!(res_field(&out, "binary_updated"), "False");
    // the golden (from updater.py) names the same key, so both compute it alike
    assert_eq!(
        *log_lines(&out).last().unwrap(),
        format!(
            "updater: no binary for platform {} in manifest",
            platform_key()
        )
    );
}

#[test]
fn unwritable_install_dir_skips_binary() {
    #[cfg(unix)]
    {
        // needs a directory this user cannot write
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: running as root");
            return;
        }
        let tmp = Tmp::new("readonly");
        let ch = Channel::new(&tmp);
        publish(&ch, Publish::default());
        let (out, _) = run_update("unwritable-dir", &tmp, &ch, pubkey(), true);
        assert_eq!(res_field(&out, "blocklist_updated"), "True");
        assert_eq!(res_field(&out, "binary_updated"), "False");
        assert!(log_lines(&out)
            .last()
            .unwrap()
            .contains("binary self-update skipped"));
    }
}

/// The signer's manifest shape is unchanged: flat URLs named after the files.
#[test]
fn manifest_from_signer() {
    let tmp = Tmp::new("manifest");
    let ch = Channel::new(&tmp);
    publish(&ch, Publish::default());
    let raw = fs::read_to_string(ch.root.join("manifest.json")).unwrap();
    let m: Value = parse_json(&raw);
    let plat = platform_key();
    assert_eq!(
        m["binary"][&plat]["url"],
        format!("{}/guard-{plat}", ch.base())
    );
    assert_eq!(
        m["blocklist"]["url"],
        format!("{}/malware-blocklist.json", ch.base())
    );
    golden(SUITE, "signer-manifest", &norm(&tmp, &ch).apply(&raw));
}
