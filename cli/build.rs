// Compress the malware blocklist snapshot shipped in the binary (5 MB of JSON).
use std::io::Write;

fn main() {
    let src = "../malware-feed/malware-blocklist.json";
    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-changed=../linux/guard-triage-linux.sh");
    println!("cargo:rerun-if-changed=../windows/sysmon-config.xml");
    let data = std::fs::read(src).unwrap_or_else(|_| b"{}".to_vec());
    let out =
        std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("malware-blocklist.json.gz");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&data).unwrap();
    std::fs::write(out, gz.finish().unwrap()).unwrap();
}
