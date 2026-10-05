//! guard — the single Guard entrypoint, as one static Rust binary.
//!
//! Step 4 of the Rust migration ports guard.py command by command. Until every
//! command is here, releases keep shipping the PyInstaller build; this binary is
//! built and tested next to it on every platform. Commands not ported yet exit 2
//! with a message instead of guessing.

mod pyrepr;
mod update;

use std::process::ExitCode;

/// Release builds bake the version in with GUARD_VERSION at compile time.
pub const VERSION: &str = match option_env!("GUARD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

const USAGE: &str = "\
guard - supply-chain and malware protection, one command: `guard <cmd>`.

Commands in this build:
  guard update             check the signed update channel now (blocklist + binary)
  guard version            print version

Not ported to the Rust build yet (use the current release for these):
  scan, scan-git, open, av, watch, triage, clean, restore, permissions,
  notify-test, deps, telemetry, sysmon-config, install, uninstall
";

const NOT_PORTED: &[&str] = &[
    "scan",
    "scan-git",
    "open",
    "av",
    "watch",
    "triage",
    "clean",
    "restore",
    "permissions",
    "perms",
    "notify-test",
    "deps",
    "telemetry",
    "sysmon-config",
    "install",
    "uninstall",
];

fn run(args: &[String]) -> u8 {
    update::cleanup_stale();
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return 0;
    };
    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            0
        }
        "version" => {
            println!("guard {VERSION}");
            0
        }
        // manual OTA check (the service also does this periodically)
        "update" => match update::Updater::from_env(VERSION) {
            Ok(up) => match up.check_and_apply() {
                Ok(res) => {
                    println!("{}", res.repr());
                    0
                }
                Err(e) => {
                    eprintln!("update failed: {e}");
                    1
                }
            },
            Err(e) => {
                eprintln!("update failed: {e}");
                1
            }
        },
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
