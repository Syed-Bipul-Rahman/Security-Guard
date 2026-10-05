//! Content heuristics — a line-for-line port of the data-dependent parts of
//! `guard_av/heuristics.py` (PE / ELF / Mach-O structure and script obfuscation).
//! Filename checks stay in Python. Every indicator id, score and description
//! must match the Python implementation exactly; the test suite runs both
//! backends and compares them.

use std::sync::LazyLock;

use memchr::memmem;
use regex::bytes::Regex;

use crate::entropy::shannon_entropy;

pub type Indicator = (&'static str, u32, String);

fn ind(id: &'static str, score: u32, desc: impl Into<String>) -> Indicator {
    (id, score, desc.into())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    memmem::find(hay, needle).is_some()
}

// ---------------------------------------------------------------------- PE
const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_WRITE: u32 = 0x8000_0000;
const SCN_CODE: u32 = 0x0000_0020;

const PACKERS: &[(&[u8], &str)] = &[
    (b"UPX0", "UPX"), (b"UPX1", "UPX"), (b"UPX2", "UPX"),
    (b".aspack", "ASPack"), (b".adata", "ASPack"), (b".petite", "Petite"),
    (b".MPRESS1", "MPRESS"), (b".MPRESS2", "MPRESS"), (b".themida", "Themida"),
    (b".vmp0", "VMProtect"), (b".vmp1", "VMProtect"), (b".enigma1", "Enigma"),
    (b"nsp0", "NsPack"),
];

const API_GROUPS: &[(&str, u32, &str, &[&[u8]])] = &[
    ("pe.api.process-injection", 45, "classic remote-process injection API set",
     &[b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"]),
    ("pe.api.process-hollowing", 45, "process-hollowing API set",
     &[b"NtUnmapViewOfSection", b"SetThreadContext", b"ResumeThread"]),
    ("pe.api.keylogger", 30, "global keyboard hook + key-state polling",
     &[b"SetWindowsHookEx", b"GetAsyncKeyState"]),
    ("pe.api.anti-debug", 10, "debugger-detection APIs",
     &[b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"]),
];

struct Section {
    name: Vec<u8>,
    vaddr: u64,
    vsize: u64,
    raw_ptr: usize,
    raw_size: usize,
    flags: u32,
}

struct PeInfo {
    entry_point: u64,
    sections: Vec<Section>,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Python slicing semantics: clamp instead of failing.
fn slice(d: &[u8], start: usize, len: usize) -> &[u8] {
    let s = start.min(d.len());
    let e = start.saturating_add(len).min(d.len());
    &d[s..e]
}

fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew = u32_at(data, 0x3C)? as usize;
    if slice(data, e_lfanew, 4) != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    // struct "<HHIIIHH": machine, nsects, timestamp, symtab, nsyms, opt_size, chars
    u16_at(data, coff + 18)?; // the whole 20-byte header must be present
    let nsects = u16_at(data, coff + 2)? as usize;
    let opt_size = u16_at(data, coff + 16)? as usize;
    let opt = coff + 20;
    let magic = u16_at(data, opt)?;
    if magic != 0x10B && magic != 0x20B {
        return None;
    }
    let entry = u32_at(data, opt + 16)? as u64;
    let sec_off = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsects.min(96) {
        let o = sec_off + 40 * i;
        let mut name = slice(data, o, 8).to_vec();
        while name.last() == Some(&0) {
            name.pop();
        }
        // "<IIII" at o+8 then "<I" at o+36 (raising in Python if out of range)
        let vsize = u32_at(data, o + 8)? as u64;
        let vaddr = u32_at(data, o + 12)? as u64;
        let raw_size = u32_at(data, o + 16)? as usize;
        let raw_ptr = u32_at(data, o + 20)? as usize;
        let flags = u32_at(data, o + 36)?;
        sections.push(Section { name, vaddr, vsize, raw_ptr, raw_size, flags });
    }
    Some(PeInfo { entry_point: entry, sections })
}

/// Python `repr()` of a latin-1 decoded str (used in one description).
fn py_repr_latin1(b: &[u8]) -> String {
    let has_sq = b.contains(&b'\'');
    let has_dq = b.contains(&b'"');
    let quote = if has_sq && !has_dq { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if c as char == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7E => out.push(c as char),
            0xA1..=0xFF if c != 0xAD => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote);
    out
}

pub fn pe_indicators(data: &[u8]) -> Vec<Indicator> {
    let Some(info) = parse_pe(data) else {
        return vec![ind("pe.malformed", 15, "MZ header without a valid PE structure")];
    };
    let mut out = Vec::new();
    let mut packers: Vec<&str> = info
        .sections
        .iter()
        .filter_map(|s| PACKERS.iter().find(|(n, _)| *n == s.name.as_slice()).map(|(_, p)| *p))
        .collect();
    packers.sort_unstable();
    packers.dedup();
    if !packers.is_empty() {
        out.push(ind("pe.packer", 25, format!("packed with {}", packers.join(", "))));
    }
    for s in &info.sections {
        if s.flags & SCN_EXECUTE == 0 {
            continue;
        }
        let body = slice(data, s.raw_ptr, s.raw_size);
        if body.len() >= 1024 && shannon_entropy(body) > 7.2 {
            out.push(ind("pe.section.high-entropy", 35, format!(
                "executable section {} is encrypted/compressed", py_repr_latin1(&s.name))));
            break;
        }
    }
    if info.sections.iter().any(|s| s.flags & SCN_EXECUTE != 0 && s.flags & SCN_WRITE != 0) {
        out.push(ind("pe.section.wx", 20, "section is both writable and executable"));
    }
    if !info.sections.is_empty() && info.entry_point != 0 {
        let ep = info.entry_point;
        let inside = info
            .sections
            .iter()
            .find(|s| s.vaddr <= ep && ep < s.vaddr + s.vsize.max(s.raw_size as u64));
        match inside {
            None => out.push(ind("pe.entry.outside", 30, "entry point lies outside every section")),
            Some(s) if s.flags & (SCN_CODE | SCN_EXECUTE) == 0 => {
                out.push(ind("pe.entry.non-code", 30, "entry point is in a non-executable section"))
            }
            Some(_) => {}
        }
    }
    for (id, score, desc, apis) in API_GROUPS {
        if apis.iter().all(|a| contains(data, a)) {
            out.push(ind(id, *score, *desc));
        }
    }
    out
}

// --------------------------------------------------------------- ELF / Mach-O
pub fn elf_indicators(data: &[u8]) -> Vec<Indicator> {
    let mut out = Vec::new();
    let head = &data[..data.len().min(4096)];
    let tail = &data[data.len().saturating_sub(4096)..];
    if contains(head, b"UPX!") || contains(tail, b"UPX!") {
        out.push(ind("elf.packer", 25, "packed with UPX"));
    }
    if data.len() >= 4096 && shannon_entropy(data) > 7.4 {
        out.push(ind("elf.high-entropy", 30, "body is encrypted/compressed"));
    }
    if contains(data, b"/etc/ld.so.preload") {
        out.push(ind("elf.ld-preload", 40, "writes the system-wide LD preload list (rootkit persistence)"));
    }
    out
}

pub fn macho_indicators(data: &[u8]) -> Vec<Indicator> {
    if data.len() >= 4096 && shannon_entropy(data) > 7.4 {
        return vec![ind("macho.high-entropy", 30, "body is encrypted/compressed")];
    }
    Vec::new()
}

// ------------------------------------------------------------------- scripts
fn re(src: &str) -> Regex {
    Regex::new(src).expect("built-in heuristic regex")
}

static DYNAMIC_EXEC: LazyLock<Regex> = LazyLock::new(|| re(
    r"(?-u)(?i)\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|Invoke-Expression|\bIEX\b|\bexecute\s*\("));
static JSOBF_ID: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)\b_0x[0-9a-f]{4,6}\b"));
static CHARCODE: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)fromCharCode\s*\(\s*(?:\d+\s*,\s*){29,}\d+"));
static HEX_ESC: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)\\x[0-9a-fA-F]{2}"));
static PS_ENC: LazyLock<Regex> = LazyLock::new(|| re(
    r"(?-u)(?i)-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/]{100}"));
static PS_HIDDEN: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)-(?:w|win|window|windowstyle)\s+hidden"));
static PS_FROMB64: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)FromBase64String"));
static PS_IEX: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)Invoke-Expression|\bIEX\b"));
static AMSI: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)Amsi(?:Utils|ScanBuffer)|amsi(?:Init)Failed"));

fn is_b64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// Equivalent to Python's `re.search(rb"[A-Za-z0-9+/]{2000,}={0,2}", data)`.
fn has_b64_blob(data: &[u8]) -> bool {
    let mut run = 0usize;
    for &c in data {
        if is_b64(c) {
            run += 1;
            if run >= 2000 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub fn script_indicators(data: &[u8]) -> Vec<Indicator> {
    let mut out = Vec::new();
    let dyn_exec = DYNAMIC_EXEC.is_match(data);
    if dyn_exec && has_b64_blob(data) {
        out.push(ind("script.exec-encoded-blob", 50, "dynamically executes code next to a large encoded blob"));
    }
    if JSOBF_ID.find_iter(data).count() >= 50 {
        out.push(ind("script.js-obfuscator", 35, "javascript-obfuscator style _0x identifiers"));
    }
    if dyn_exec && CHARCODE.is_match(data) {
        out.push(ind("script.charcode-exec", 40, "builds code from character codes and executes it"));
    }
    let n_hex = HEX_ESC.find_iter(data).count();
    if n_hex >= 300 && n_hex * 4 > data.len() / 3 {
        out.push(ind("script.hex-escaped", 25, "body is mostly hex-escaped bytes"));
    }
    if PS_ENC.is_match(data) {
        out.push(ind("ps.encoded-command", 30, "PowerShell launched with an encoded command"));
        if PS_HIDDEN.is_match(data) {
            out.push(ind("ps.hidden-window", 20, "PowerShell window hidden from the user"));
        }
    }
    if dyn_exec && PS_FROMB64.is_match(data) && PS_IEX.is_match(data) {
        out.push(ind("ps.decode-exec", 30, "decodes base64 and pipes it to Invoke-Expression"));
    }
    if AMSI.is_match(data) {
        out.push(ind("ps.amsi-bypass", 60, "tampers with the Antimalware Scan Interface"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[Indicator]) -> Vec<&str> {
        v.iter().map(|i| i.0).collect()
    }

    #[test]
    fn malformed_pe() {
        assert_eq!(ids(&pe_indicators(b"MZ")), ["pe.malformed"]);
        assert_eq!(ids(&pe_indicators(b"ELF")), ["pe.malformed"]);
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr_latin1(b"UPX0"), "'UPX0'");
        assert_eq!(py_repr_latin1(b"a'b"), "\"a'b\"");
        assert_eq!(py_repr_latin1(b"a'\"b"), "'a\\'\"b'");
        assert_eq!(py_repr_latin1(b"\x01\xad\xe9\\"), "'\\x01\\xad\u{e9}\\\\'");
    }

    #[test]
    fn scripts() {
        let blob = b"QUJD".repeat(600);
        let mut s = b"eval(atob('".to_vec();
        s.extend_from_slice(&blob);
        s.extend_from_slice(b"'))");
        assert_eq!(ids(&script_indicators(&s)), ["script.exec-encoded-blob"]);
        assert!(script_indicators(b"print('hi')").is_empty());
    }

    #[test]
    fn elf() {
        let mut d = b"\x7fELF".to_vec();
        d.extend_from_slice(&[0u8; 9000]);
        d.extend_from_slice(b"UPX!/etc/ld.so.preload");
        assert_eq!(ids(&elf_indicators(&d)), ["elf.packer", "elf.ld-preload"]);
        assert!(macho_indicators(b"\xcf\xfa\xed\xfe").is_empty());
    }
}
