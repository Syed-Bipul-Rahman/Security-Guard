//! guard — the single Guard entrypoint, as one static Rust binary.
//!
//! Step 4 of the Rust migration ports guard.py command by command. Until every
//! command is here, releases keep shipping the PyInstaller build; this binary is
//! built and tested next to it on every platform. Commands not ported yet exit 2
//! with a message instead of guessing.

mod av;
mod deps;
mod install;
mod net;
mod notify;
mod permissions;
mod pyjson;
mod pyrepr;
mod telemetry;
mod update;
mod util;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Release builds bake the version in with GUARD_VERSION at compile time.
pub const VERSION: &str = match option_env!("GUARD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

static TRIAGE_SH: &[u8] = include_bytes!("../../linux/guard-triage-linux.sh");
static SYSMON_CONFIG: &[u8] = include_bytes!("../../windows/sysmon-config.xml");

const USAGE: &str = "\
guard - supply-chain and malware protection, one command: `guard <cmd>`.

Commands in this build:
  guard triage             host IR triage (reboots/persistence/recon/flood) - OS-native
  guard permissions        check disk access; on macOS raise the \"Allow\" prompts (internal + removable)
  guard notify-test        show a sample threat popup (verify desktop alerts work)
  guard deps update        refresh the malware-package blocklist from GitHub advisories
  guard deps check <path>  check a project's dependencies against the malware blocklist
  guard install            install Guard as an auto-start service on this machine
  guard uninstall          remove the Guard service + hooks
  guard telemetry          send one telemetry report now
  guard update             check the signed update channel now (blocklist + binary)
  guard version            print version

  guard av scan <path>     antivirus engine: hash DB + YARA-style rules + heuristics + archives
  guard av quarantine ...  list / restore / delete items in the neutered quarantine vault

Not ported to the Rust build yet (use the current release for these):
  scan, scan-git, open, watch, clean, restore
";

const NOT_PORTED: &[&str] = &["scan", "scan-git", "open", "watch", "clean", "restore"];

fn report(r: Result<u8, String>) -> u8 {
    r.unwrap_or_else(|e| {
        eprintln!("guard: {e}");
        1
    })
}

/// Run the bundled triage script (Linux/macOS) the way guard.py does.
fn triage(args: &[String]) -> u8 {
    if cfg!(windows) {
        println!("On Windows, host triage uses the Sysmon-based sensor + IR scripts.");
        println!("Run:  guard-triage.ps1 / reboot-forensics.ps1 (bundled under windows/),");
        println!("and install Sysmon with windows/sysmon-config.xml. See windows/README-windows-sensor.md.");
        return 0;
    }
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        eprintln!("unsupported platform for triage: {}", std::env::consts::OS);
        return 2;
    }
    // copy out so it's executable from anywhere
    let dir = std::env::temp_dir().join(format!("guard_{}", std::process::id()));
    let script: PathBuf = dir.join("triage.sh");
    let written = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&script, TRIAGE_SH));
    if let Err(e) = written {
        eprintln!("could not stage the triage script: {e}");
        return 1;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
    }
    let rc = Command::new("bash").arg(&script).args(args).status();
    let _ = std::fs::remove_dir_all(&dir);
    match rc {
        Ok(s) => s.code().unwrap_or(1) as u8,
        Err(e) => {
            eprintln!("bash: {e}");
            1
        }
    }
}

/// Emit the bundled Sysmon config (guard.ps1 configures Sysmon from it).
fn sysmon_config(args: &[String]) -> u8 {
    match args.first() {
        Some(dest) => match std::fs::write(dest, SYSMON_CONFIG) {
            Ok(()) => {
                println!("wrote {dest}");
                0
            }
            Err(e) => {
                eprintln!("could not write {dest}: {e}");
                1
            }
        },
        None => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(SYSMON_CONFIG).and_then(|_| out.flush());
            0
        }
    }
}

fn run(args: &[String]) -> u8 {
    update::cleanup_stale();
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return 0;
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            0
        }
        "version" => {
            println!("guard {VERSION}");
            0
        }
        "triage" => triage(rest),
        "permissions" | "perms" => permissions::main(rest),
        "sysmon-config" => sysmon_config(rest),
        "notify-test" => {
            let ok = notify::notify(
                "Guard - Threat detected (TEST)",
                "This is a TEST alert. If you can see this, Guard's threat notifications work on this machine.",
            );
            println!(
                "{}",
                if ok {
                    "notified"
                } else {
                    "notify returned False (no mechanism available)"
                }
            );
            if ok {
                0
            } else {
                1
            }
        }
        "av" => av::main(rest),
        "deps" => report(deps::main(rest)),
        "telemetry" => match telemetry::run_once(&util::guard_home()) {
            Ok(res) => {
                println!("{}", pyrepr::repr(&res));
                0
            }
            Err(e) => {
                eprintln!("telemetry failed: {e}");
                1
            }
        },
        // manual OTA check (the service also does this periodically)
        "update" => match update::Updater::from_env(VERSION).and_then(|up| up.check_and_apply()) {
            Ok(res) => {
                println!("{}", res.repr());
                0
            }
            Err(e) => {
                eprintln!("update failed: {e}");
                1
            }
        },
        "install" => report(install::run(false)),
        "uninstall" => report(install::run(true)),
        c if NOT_PORTED.contains(&c) => {
            eprintln!(
                "guard: `{c}` is not in the Rust build yet; use the current guard release for it"
            );
            2
        }
        c => {
            eprintln!("unknown command: {c}\n");
            eprint!("{USAGE}");
            2
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args))
}
