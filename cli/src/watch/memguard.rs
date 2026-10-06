//! Keeps the watcher under a memory budget, by default 10% of RAM (port of
//! memguard.py). Near the budget it pauses briefly between batches. An opt-in
//! hard ceiling caps the address space (RLIMIT_AS) as a backstop.

use std::time::Duration;

const MB: u64 = 1024 * 1024;

#[cfg(unix)]
fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as u64
    } else {
        4096
    }
}

/// Physical RAM; 4 GiB when it can't be read, so the budget stays finite.
pub fn total_ram_bytes() -> u64 {
    const FALLBACK: u64 = 4 * 1024 * MB;
    #[cfg(unix)]
    {
        // SAFETY: sysconf has no preconditions.
        let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        if pages > 0 {
            return pages as u64 * page_size();
        }
        FALLBACK
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        // SAFETY: a zeroed MEMORYSTATUSEX with dwLength set is what the call expects.
        unsafe {
            let mut st: MEMORYSTATUSEX = std::mem::zeroed();
            st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut st) != 0 {
                return st.ullTotalPhys;
            }
        }
        FALLBACK
    }
    #[cfg(not(any(unix, windows)))]
    FALLBACK
}

/// Current resident set size (peak on macOS, as memguard.py reads it).
pub fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(Ok(pages)) = s.split_whitespace().nth(1).map(str::parse::<u64>) {
            return pages * page_size();
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: getrusage fills the struct we pass.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
            return 0;
        }
        let max = ru.ru_maxrss.max(0) as u64;
        // kilobytes on Linux, bytes on macOS
        if cfg!(target_os = "macos") {
            max
        } else {
            max * 1024
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: the counters struct is sized and passed as the call expects.
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
                return c.WorkingSetSize as u64;
            }
        }
        0
    }
    #[cfg(not(any(unix, windows)))]
    0
}

pub struct MemoryGuard {
    fraction: f64,
    total: u64,
    pub budget: u64,
    throttles: u64,
}

impl MemoryGuard {
    pub fn new(fraction: f64) -> MemoryGuard {
        let total = total_ram_bytes();
        // never below a small floor, so tiny hosts still get a usable budget
        let budget = ((total as f64 * fraction) as u64).max(64 * MB);
        MemoryGuard {
            fraction,
            total,
            budget,
            throttles: 0,
        }
    }

    /// Near the budget: pause briefly. True when it throttled.
    pub fn check_and_throttle(&mut self, log: &dyn Fn(&str)) -> bool {
        let rss = current_rss_bytes();
        if rss as f64 > self.budget as f64 * 0.85 && current_rss_bytes() > self.budget {
            self.throttles += 1;
            if self.throttles <= 3 || self.throttles.is_multiple_of(50) {
                log(&format!(
                    "memguard: RSS {}MB > budget {}MB \u{2014} throttling (#{})",
                    current_rss_bytes() / MB,
                    self.budget / MB,
                    self.throttles
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
            return true;
        }
        false
    }

    /// Opt-in backstop: cap the address space at 1.5x the budget (Unix only).
    pub fn install_hard_ceiling(&self) -> bool {
        #[cfg(unix)]
        {
            let cap = (self.budget as f64 * 1.5) as libc::rlim_t;
            // SAFETY: getrlimit/setrlimit only read and write the struct passed.
            unsafe {
                let mut cur: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_AS, &mut cur) != 0 {
                    return false;
                }
                let hard = if cur.rlim_max == libc::RLIM_INFINITY {
                    cap
                } else {
                    cap.min(cur.rlim_max)
                };
                let new = libc::rlimit {
                    rlim_cur: cap,
                    rlim_max: hard,
                };
                libc::setrlimit(libc::RLIMIT_AS, &new) == 0
            }
        }
        #[cfg(not(unix))]
        false
    }

    pub fn summary(&self) -> String {
        format!(
            "total={}MB budget={}MB ({:.0}%) rss={}MB",
            self.total / MB,
            self.budget / MB,
            self.fraction * 100.0,
            current_rss_bytes() / MB
        )
    }
}
