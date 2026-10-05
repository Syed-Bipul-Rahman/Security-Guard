//! Static heuristics (port of guard_av/heuristics.py). The content checks are
//! guard_core's; the filename checks and the dispatch live here.

use guard_core::heuristics as core_h;
use regex::Regex;
use std::sync::LazyLock;

use super::filetype as ft;
use super::pystr;

/// Indicators at or above this weight may count towards a MALICIOUS verdict.
pub const STRONG: u32 = 30;

pub struct Indicator {
    pub id: String,
    pub score: u32,
    pub description: String,
}

impl Indicator {
    fn new(id: &str, score: u32, description: impl Into<String>) -> Self {
        Indicator {
            id: id.into(),
            score,
            description: description.into(),
        }
    }
}

impl std::fmt::Display for Indicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(+{})", self.id, self.score)
    }
}

const EXEC_EXTS: &[&str] = &[
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".ps1", ".msi", ".jar", ".lnk", ".cpl",
];
const BIDI: &[char] = &['\u{202e}', '\u{202d}', '\u{2066}', '\u{2067}', '\u{2068}'];

/// unicodedata.category(c) == "Cf" (Unicode 15).
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x890..=0x891 | 0x8E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

static PADDED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\s\x1c-\x1f]{5,}\.[A-Za-z0-9]{2,4}\n?\z").unwrap());

pub fn filename_indicators(name: &str, tag: &str) -> Vec<Indicator> {
    let mut out = Vec::new();
    let replaced = name.replace('\\', "/");
    let base = pystr::name(&replaced);
    if base.chars().any(|c| BIDI.contains(&c)) {
        out.push(Indicator::new(
            "name.bidi-override",
            60,
            "filename uses a Unicode bidi override to fake its extension",
        ));
    }
    let sfx: Vec<String> = pystr::suffixes(base)
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let n = sfx.len();
    let exec_last = n > 0 && EXEC_EXTS.contains(&sfx[n - 1].as_str());
    if n >= 2 && exec_last && ft::DOCUMENT_EXTS.contains(&sfx[n - 2].as_str()) {
        out.push(Indicator::new(
            "name.double-extension",
            40,
            format!(
                "executable hiding behind a document extension ({}{})",
                sfx[n - 2],
                sfx[n - 1]
            ),
        ));
    } else if PADDED.is_match(base) && exec_last {
        out.push(Indicator::new(
            "name.padded-extension",
            40,
            "whitespace padding pushes the real extension out of view",
        ));
    }
    let ext = sfx.last().map(String::as_str).unwrap_or("");
    if ft::is_executable(tag) && ft::DOCUMENT_EXTS.contains(&ext) {
        out.push(Indicator::new(
            "name.masquerade",
            50,
            format!(
                "{} executable disguised with a {ext} extension",
                tag.to_uppercase()
            ),
        ));
    }
    if base
        .chars()
        .any(|c| is_format_char(c) && !BIDI.contains(&c) && c != '\u{feff}')
    {
        out.push(Indicator::new(
            "name.invisible-char",
            15,
            "filename contains invisible format characters",
        ));
    }
    out
}

pub fn analyze(data: &[u8], name: &str, tag: &str) -> Vec<Indicator> {
    let mut out = filename_indicators(name, tag);
    let content = match tag {
        "pe" => core_h::pe_indicators(data),
        "elf" => core_h::elf_indicators(data),
        "macho" | "macho-fat" => core_h::macho_indicators(data),
        t if ft::is_script(t) || t == "text" || t == "script" => core_h::script_indicators(data),
        _ => Vec::new(),
    };
    out.extend(
        content
            .into_iter()
            .map(|(id, score, d)| Indicator::new(id, score, d)),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(name: &str, tag: &str) -> Vec<String> {
        filename_indicators(name, tag)
            .into_iter()
            .map(|i| i.id)
            .collect()
    }

    #[test]
    fn filename_checks() {
        assert_eq!(
            ids("dir/invoice.pdf.exe", "pe"),
            vec!["name.double-extension"]
        );
        assert_eq!(ids("photo      .exe", "pe"), vec!["name.padded-extension"]);
        assert_eq!(ids("report.pdf", "pe"), vec!["name.masquerade"]);
        assert_eq!(ids("a\u{200b}b.txt", "text"), vec!["name.invisible-char"]);
        assert_eq!(ids("x\u{202e}fdp.exe", "pe"), vec!["name.bidi-override"]);
        assert!(ids("readme.md", "text").is_empty());
    }
}
