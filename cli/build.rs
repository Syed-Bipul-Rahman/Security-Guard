// Compress data shipped in the binary: the malware blocklist snapshot (5 MB of
// JSON), the av signature files, the incident signatures, and the triage
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
}
