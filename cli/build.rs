// Compress data shipped in the binary: the malware blocklist snapshot (5 MB of
// JSON), the av signature files, the bundled community YARA rules, the
// incident signatures, and the triage
// script and Sysmon config (both name the incident's IOCs). None of these may
// sit in the binary as plain text, or Guard would detect itself (and other
// scanners would too).
use std::io::Write;

/// `fallback`: what to ship when `src` is missing (only the blocklist may be).
fn gzip_into_out_dir(src: &str, name: &str, fallback: Option<&[u8]>) {
    println!("cargo:rerun-if-changed={src}");
    let data = match (std::fs::read(src), fallback) {
        (Ok(d), _) => d,
        (Err(_), Some(f)) => f.to_vec(),
        (Err(e), None) => panic!("{src}: {e}"),
    };
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join(name);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&data).unwrap();
    std::fs::write(out, gz.finish().unwrap()).unwrap();
}

fn main() {
    gzip_into_out_dir(
        "../malware-feed/malware-blocklist.json",
        "malware-blocklist.json.gz",
        Some(b"{}"),
    );
    gzip_into_out_dir("../data/av-rules.json", "av-rules.json.gz", None);
    gzip_into_out_dir("../data/av-hashes.json", "av-hashes.json.gz", None);
    gzip_into_out_dir("../signatures.json", "signatures.json.gz", None);
    gzip_into_out_dir(
        "../linux/guard-triage-linux.sh",
        "guard-triage-linux.sh.gz",
        None,
    );
    gzip_into_out_dir("../windows/sysmon-config.xml", "sysmon-config.xml.gz", None);
    bundle_yara();
}

/// data/yara/*.yar (the community rule sets) -> one gzip each, plus
/// bundled_yara.rs listing them as (namespace, gzipped source), and the
/// rule sets' license texts.
fn bundle_yara() {
    let dir = std::path::Path::new("../data/yara");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".yar").map(str::to_string))
        .collect();
    names.sort();
    let mut list = String::from("pub static BUNDLED_YARA: &[(&str, &[u8])] = &[\n");
    for n in &names {
        gzip_into_out_dir(
            &format!("../data/yara/{n}.yar"),
            &format!("yara-{n}.yar.gz"),
            None,
        );
        list += &format!(
            "    ({n:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/yara-{n}.yar.gz\"))),\n"
        );
    }
    list += "];\n";
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("bundled_yara.rs");
    std::fs::write(out, list).unwrap();
    gzip_into_out_dir("../data/yara/LICENSES.txt", "yara-licenses.txt.gz", None);
}
