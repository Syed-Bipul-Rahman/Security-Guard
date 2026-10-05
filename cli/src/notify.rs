//! Desktop threat alerts: the Rust port of notifier.py.
//!
//! Windows: the watcher runs as SYSTEM in session 0, which the logged-in user
//! never sees, so the alert goes to the active console session through
//! WTSSendMessageW (msg.exe as fallback). macOS: a Notification Center banner via
//! osascript (the watcher is a per-user LaunchAgent). Linux: notify-send.
//! notify() never fails loudly; a missing alert must not take down the watcher.

use std::process::{Command, Stdio};

pub fn notify(title: &str, message: &str) -> bool {
    if cfg!(windows) {
        notify_windows(title, message)
    } else if cfg!(target_os = "macos") {
        let t = title.replace('"', "'");
        let m = message.replace('"', "'").replace('\n', " ");
        let script =
            format!("display notification \"{m}\" with title \"{t}\" sound name \"Basso\"");
        run(Command::new("osascript").args(["-e", &script]))
    } else {
        let Some(exe) = crate::util::which("notify-send") else {
            return false;
        };
        run(Command::new(exe).args(["-u", "critical", "-a", "Guard", title, message]))
    }
}

/// subprocess.run(..., timeout=10): true if it ran (any exit code) in time.
fn run(cmd: &mut Command) -> bool {
    let Ok(mut child) = cmd.stdin(Stdio::null()).spawn() else {
        return false;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[cfg(windows)]
fn notify_windows(title: &str, message: &str) -> bool {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSGetActiveConsoleSessionId, WTSSendMessageW,
    };
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;
    const MB_TOPMOST: u32 = 0x0004_0000;
    // SAFETY: plain Win32 calls with valid, NUL-terminated UTF-16 buffers that
    // outlive them; bWait = FALSE so the call doesn't block on the user.
    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        if session == 0xFFFF_FFFF {
            return notify_windows_msg(title, message); // no one at the console
        }
        let t: Vec<u16> = title.encode_utf16().chain([0]).collect();
        let m: Vec<u16> = message.encode_utf16().chain([0]).collect();
        let mut response = 0i32;
        let ok = WTSSendMessageW(
            std::ptr::null_mut(), // WTS_CURRENT_SERVER_HANDLE
            session,
            t.as_ptr(),
            ((t.len() - 1) * 2) as u32, // bytes, without the NUL
            m.as_ptr(),
            ((m.len() - 1) * 2) as u32,
            MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
            0,
            &mut response,
            0,
        );
        if ok == 0 {
            return notify_windows_msg(title, message);
        }
    }
    true
}

#[cfg(windows)]
fn notify_windows_msg(title: &str, message: &str) -> bool {
    let exe = crate::util::which("msg").unwrap_or_else(|| r"C:\Windows\System32\msg.exe".into());
    run(Command::new(exe).args(["*", &format!("{title}: {message}")]))
}

#[cfg(not(windows))]
fn notify_windows(_: &str, _: &str) -> bool {
    false
}
