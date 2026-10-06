// Compress data shipped in the binary: the malware blocklist snapshot (5 MB of
// JSON) and the av signature files. The signatures must not sit in the binary
// as plain text, or Guard would detect itself (and other scanners would too).
use std::io::Write;

fn gzip_into_out_dir(src: &str, name: &str) {
    println!("cargo:rerun-if-changed={src}");
    let data = std::fs::read(src).unwrap_or_else(|_| b"{}".to_vec());
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join(name);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&data).unwrap();
    std::fs::write(out, gz.finish().unwrap()).unwrap();
}

fn main() {
    println!("cargo:rerun-if-changed=../linux/guard-triage-linux.sh");
    println!("cargo:rerun-if-changed=../windows/sysmon-config.xml");
    gzip_into_out_dir(
        "../malware-feed/malware-blocklist.json",
        "malware-blocklist.json.gz",
    );
    gzip_into_out_dir("../guard_av/data/rules.json", "av-rules.json.gz");
    gzip_into_out_dir("../guard_av/data/hashes.json", "av-hashes.json.gz");
}
