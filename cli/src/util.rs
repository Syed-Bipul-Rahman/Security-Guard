//! Small shared pieces: Guard's directories, PATH lookup, timestamps.

use std::env;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Python's Path.home().
pub fn user_home() -> PathBuf {
    let vars: &[&str] = if cfg!(windows) {
        &["USERPROFILE"]
    } else {
        &["HOME"]
    };
    for v in vars {
        if let Some(h) = env::var_os(v).filter(|h| !h.is_empty()) {
            return PathBuf::from(h);
        }
    }
    #[cfg(unix)]
    if let Some(h) = unix::passwd_home(unsafe { libc::getuid() }) {
        return h;
    }
    PathBuf::from(".")
}

/// $GUARD_HOME, else ~/.guard (per-user state: watcher, telemetry, feed).
pub fn guard_home() -> PathBuf {
    env::var_os("GUARD_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join(".guard"))
}

/// $GUARD_HOME, else /var/lib/guard (the root service's state, used by install).
pub fn service_home() -> PathBuf {
    env::var_os("GUARD_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/guard"))
}

/// shutil.which
pub fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) && Path::new(name).extension().is_none() {
        env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(|e| e.to_string())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in env::split_paths(&path) {
        for ext in &exts {
            let p = dir.join(format!("{name}{ext}"));
            if is_executable(&p) {
                return Some(p);
            }
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Path.write_text: text mode, so "\n" is written as "\r\n" on Windows.
pub fn write_text(p: &Path, s: &str) -> std::io::Result<()> {
    if cfg!(windows) {
        std::fs::write(p, s.replace('\n', "\r\n"))
    } else {
        std::fs::write(p, s)
    }
}

/// datetime.now(timezone.utc).isoformat()
pub fn now_iso() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso_utc(d.as_secs() as i64, d.subsec_micros())
}

pub fn iso_utc(secs: i64, micros: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let frac = if micros == 0 {
        String::new()
    } else {
        format!(".{micros:06}")
    };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{frac}+00:00",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// A named account's home directory (pwd; Unix only).
pub fn home_of(user: &str) -> Option<PathBuf> {
    #[cfg(unix)]
    return unix::by_name(user).map(|p| p.dir);
    #[cfg(not(unix))]
    {
        let _ = user;
        None
    }
}

/// getpass.getuser(): the login name from the environment, else the account.
pub fn username() -> Option<String> {
    for v in ["LOGNAME", "USER", "LNAME", "USERNAME"] {
        if let Ok(u) = env::var(v) {
            if !u.is_empty() {
                return Some(u);
            }
        }
    }
    #[cfg(unix)]
    return unix::passwd_name(unsafe { libc::getuid() });
    #[cfg(not(unix))]
    None
}

#[cfg(unix)]
pub mod unix {
    use std::ffi::{CStr, CString};
    use std::path::PathBuf;

    pub struct Passwd {
        pub name: String,
        pub uid: u32,
        pub dir: PathBuf,
    }

    fn from_raw(p: *mut libc::passwd) -> Option<Passwd> {
        if p.is_null() {
            return None;
        }
        // SAFETY: non-null result of getpwnam/getpwuid; copied out right away.
        unsafe {
            Some(Passwd {
                name: CStr::from_ptr((*p).pw_name).to_string_lossy().into_owned(),
                uid: (*p).pw_uid,
                dir: PathBuf::from(CStr::from_ptr((*p).pw_dir).to_string_lossy().into_owned()),
            })
        }
    }

    pub fn by_name(name: &str) -> Option<Passwd> {
        let c = CString::new(name).ok()?;
        from_raw(unsafe { libc::getpwnam(c.as_ptr()) })
    }

    pub fn passwd_home(uid: u32) -> Option<PathBuf> {
        from_raw(unsafe { libc::getpwuid(uid) }).map(|p| p.dir)
    }

    pub fn passwd_name(uid: u32) -> Option<String> {
        from_raw(unsafe { libc::getpwuid(uid) }).map(|p| p.name)
    }

    pub fn uname() -> (String, String, String) {
        // (sysname, release, machine)
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut u) } != 0 {
            return (String::new(), String::new(), String::new());
        }
        let f = |a: &[libc::c_char]| {
            unsafe { CStr::from_ptr(a.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        (f(&u.sysname), f(&u.release), f(&u.machine))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_like_python() {
        assert_eq!(iso_utc(0, 0), "1970-01-01T00:00:00+00:00");
        assert_eq!(
            iso_utc(1_791_216_274, 5),
            "2026-10-05T16:04:34.000005+00:00"
        );
        assert_eq!(iso_utc(951_782_400, 0), "2000-02-29T00:00:00+00:00");
    }
}
