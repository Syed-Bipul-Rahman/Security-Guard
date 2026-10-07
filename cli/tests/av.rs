//! `guard av`: scan, rules, hash and quarantine, checked against goldens
//! recorded from guard_av (Python). Was tests/test_rust_av.py, which ran both
//! builds side by side.

mod common;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::fixtures::*;
use common::samples::{self, eicar, sample};
use common::*;
use serde_json::{json, Value};
use sha2::Digest;

const SUITE: &str = "av";

const YARA: &str = r#"
rule DropperMarker : dropper {
    meta:
        verdict = "malicious"
        whole_file = true
        description = "drops the second stage"
    strings:
        $url = "evil.example/stage2"
    condition:
        any of them
}

rule LooseHunt : hunting research {
    meta:
        verdict = "nonsense"
    strings:
        $a = "hunting-marker"
    condition:
        $a
}

rule Quiet { strings: $q = "quiet-marker" condition: $q }
"#;

fn extra_rules() -> Value {
    json!({"rules": [{
        "id": "test.marker", "name": "Test.Marker", "verdict": "suspicious",
        "description": "test marker", "filetypes": ["textual"], "exclude_extensions": [".md"],
        "strings": {"$m": {"text": "guard-test-marker", "nocase": true}, "$w": {"text": "wide-mark", "wide": true}},
        "condition": {"any": "them"},
    }]})
}

fn evil_pe() -> Vec<u8> {
    build_pe_with(
        &[
            section(b"UPX0", EXEC | WRITE | READ, random_bytes(4096, 7)),
            section(b".rsrc", READ, vec![0; 64]),
        ],
        0x9000,
        b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0",
        0x10B,
        false,
    )
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Samples, clean files, archives, duplicates and odd names.
fn build_corpus(root: &Path) -> PathBuf {
    let d = root.join("corpus");
    for (name, _, data) in samples::decoded(samples::MALICIOUS)
        .into_iter()
        .chain(samples::decoded(samples::SUSPICIOUS))
    {
        write(&d.join("samples").join(name), data);
    }
    write(&d.join("eicar.com"), eicar());
    write(
        &d.join("eicar-crlf.txt"),
        [eicar(), b"\r\n".to_vec()].concat(),
    );
    write(
        &d.join("clean/README.md"),
        "# hello\nguard-test-marker in docs is fine\n",
    );
    write(&d.join("clean/app.py"), "print('hello')\n");
    write(&d.join("clean/empty"), b"");
    write(&d.join("clean/noise.bin"), random_bytes(5000, 3));
    write(&d.join("clean/notes.txt"), "guard-test-marker\n");
    write(&d.join("clean/wide.dat"), utf16le("xx wide-mark"));
    write(
        &d.join("clean/drop.txt"),
        "GET http://evil.example/stage2 HTTP/1.1 hunting-marker quiet-marker\n",
    );
    // same content under another name and in another folder (the result cache)
    let webshell = sample("webshell_eval.php");
    write(&d.join("dup/a/webshell_eval.php"), &webshell);
    write(&d.join("dup/b/other.php"), &webshell);
    // heuristics
    write(&d.join("pe/svch0st.exe"), evil_pe());
    write(&d.join("pe/invoice.pdf.exe"), build_pe());
    write(&d.join("pe/report.pdf"), build_pe());
    write(&d.join("pe/photo       .scr"), build_pe());
    write(&d.join("pe/résumé\u{202e}txt.exe"), build_pe());
    write(&d.join("pe/zero\u{200b}width.txt"), "hi\n");
    write(
        &d.join("elf/tool"),
        build_elf(&[b"/etc/ld.so.preload".as_slice(), &random_bytes(8192, 5)].concat()),
    );
    // archives
    let rev = sample("revshell.sh");
    let inner = make_zip(&[("payload/run.sh", &rev), ("ok.txt", b"fine")], &[]);
    write(
        &d.join("arch/nested.zip"),
        make_zip(
            &[
                ("inner.zip", &inner),
                ("dir/", b""),
                ("eicar.com", &eicar()),
            ],
            &[],
        ),
    );
    write(
        &d.join("arch/enc.zip"),
        make_zip(
            &[("secret.bin", &[b'x'; 100]), ("plain.sh", &rev)],
            &["secret.bin"],
        ),
    );
    write(
        &d.join("arch/bomb.zip"),
        make_zip(
            &[
                ("zeros.bin", &vec![0u8; 3 * 1024 * 1024]),
                ("eicar.com", &eicar()),
            ],
            &[],
        ),
    );
    write(
        &d.join("arch/bundle.tar.gz"),
        gz(&make_tar(&[("a/x.sh", &rev), ("a/y.txt", b"ok")])),
    );
    write(
        &d.join("arch/plain.tar"),
        make_tar(&[("evil.php", &webshell)]),
    );
    write(
        &d.join("arch/bundle.tar.bz2"),
        bz2(&make_tar(&[("m.ps1", &sample("amsi.ps1"))])),
    );
    write(&d.join("arch/one.sh.gz"), gz(&rev));
    write(&d.join("arch/one.py.bz2"), bz2(&sample("revshell.py")));
    write(&d.join("arch/one.php.xz"), xz(&webshell));
    write(&d.join("arch/zeros.gz"), gz(&vec![0u8; 40 * 1024 * 1024]));
    write(&d.join("arch/broken.zip"), b"PK\x03\x04garbage");
    // never scanned: VCS internals, symlinks
    write(&d.join(".git/objects/evil.php"), &webshell);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(d.join("eicar.com"), d.join("link.com")).unwrap();
        std::os::unix::fs::symlink(d.join("samples"), d.join("linkdir")).unwrap();
    }
    d
}

/// The corpus, built once for the whole file.
fn tree() -> &'static Path {
    static TREE: OnceLock<(Tmp, PathBuf)> = OnceLock::new();
    &TREE
        .get_or_init(|| {
            let t = Tmp::new("av-corpus");
            let d = build_corpus(&t.path);
            (t, d)
        })
        .1
}

fn norm(tmp: &Tmp) -> Norm {
    Norm::new().path(tree(), "TREE").path(&tmp.path, "TMP")
}

/// The JSON report with the timing scrubbed, canonical and path-normalised.
fn report(out: &Out, n: &Norm) -> String {
    let mut v = parse_json(&out.stdout);
    let el = v["summary"]["elapsed_sec"].take();
    assert!(el.is_f64(), "elapsed_sec is a float: {el}");
    v["summary"]["elapsed_sec"] = json!("<elapsed>");
    format!(
        "exit {}\n--- report\n{}",
        out.code,
        n.apply(&canon_json(&v))
    )
}

fn av(tmp: &Tmp, args: &[&str]) -> Guard {
    let mut a = vec!["av"];
    a.extend_from_slice(args);
    guard(&a).home(&tmp.join("home"))
}

// -------------------------------------------------------------------- scan
#[test]
fn scan_json() {
    for (flags, name) in [
        (vec![], "scan_json"),
        (vec!["--no-archives"], "scan_json-no-archives"),
        (vec!["--no-heuristics"], "scan_json-no-heuristics"),
        (vec!["--fail-on-suspicious"], "scan_json-fail-on-suspicious"),
    ] {
        let tmp = Tmp::new("scan-json");
        let mut args = vec!["scan", tree().to_str().unwrap(), "--json"];
        args.extend(flags);
        let out = av(&tmp, &args).run();
        assert_eq!(out.code, 1, "{}", out.stderr);
        golden(SUITE, name, &report(&out, &norm(&tmp)));
    }
}

#[test]
fn scan_text() {
    let tmp = Tmp::new("scan-text");
    let t = tree();
    let out = av(
        &tmp,
        &[
            "scan",
            &s(&t.join("samples")),
            &s(&t.join("arch")),
            &s(&t.join("eicar.com")),
        ],
    )
    .run();
    assert!(out.stdout.contains("[MALICIOUS]"));
    golden(SUITE, "scan_text", &norm(&tmp).apply(&out.shown()));
}

#[test]
fn scan_relative_paths_and_dot() {
    let tmp = Tmp::new("scan-rel");
    let out = av(&tmp, &["scan", ".", "./dup//a/", "--json"])
        .cwd(tree())
        .run();
    golden(
        SUITE,
        "scan_relative_paths_and_dot",
        &report(&out, &norm(&tmp)),
    );
}

#[test]
fn scan_exit_codes() {
    for (target, rc, name) in [
        ("clean", 0, "clean"),
        ("samples/miner.json", 0, "miner"),
        ("eicar.com", 1, "eicar"),
    ] {
        let tmp = Tmp::new("scan-rc");
        let p = s(&tree().join(target));
        let out = av(&tmp, &["scan", &p]).run();
        assert_eq!(out.code, rc, "{target}");
        let strict = av(&tmp, &["scan", &p, "--fail-on-suspicious"]).run();
        golden(
            SUITE,
            &format!("scan_exit_codes-{name}"),
            &norm(&tmp).apply(&format!(
                "{}\n=== --fail-on-suspicious\n{}",
                out.shown(),
                strict.shown()
            )),
        );
    }
}

#[test]
fn scan_missing_path() {
    let tmp = Tmp::new("scan-missing");
    let out = av(
        &tmp,
        &[
            "scan",
            &s(&tree().join("eicar.com")),
            &s(&tmp.join("nope")),
            "zzz",
        ],
    )
    .run();
    assert_eq!(out.code, 2);
    golden(
        SUITE,
        "scan_missing_path",
        &norm(&tmp).apply(&out.shown_all()),
    );
}

#[cfg(unix)]
#[test]
fn scan_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: needs a non-root user to make a file unreadable");
        return;
    }
    let tmp = Tmp::new("scan-unreadable");
    let f = write(&tmp.join("t/locked.txt"), "x");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = av(&tmp, &["scan", &s(&tmp.join("t")), "--json"]).run();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(out.stdout.contains("PermissionError"));
    golden(SUITE, "scan_unreadable_file", &report(&out, &norm(&tmp)));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sig_dir(root: &Path, yara: bool) -> PathBuf {
    let s = root.join("sigs");
    write(&s.join("rules-extra.json"), extra_rules().to_string());
    let clean_sha = hex(&sha2::Sha256::digest(b"print('hello')\n"));
    write(
        &s.join("hashes-local.txt"),
        format!("# local list\n{clean_sha}  Local.Bad.App\nnot-a-hash x\n"),
    );
    let md5 = hex(&md5::Md5::digest(b"fine"));
    write(
        &s.join("hashes-more.json"),
        json!({"entries": [{"md5": md5, "name": "Fine.But.Listed", "verdict": "suspicious"}]})
            .to_string(),
    );
    write(
        &s.join("allowlist-team.json"),
        json!({"paths": ["*/samples/bind.sh", "*/pe/report.pdf"],
               "rules": ["HackTool.ReverseShell.Python", "yara:community.Quiet"]})
        .to_string(),
    );
    if yara {
        write(&s.join("community.yar"), YARA);
    }
    s
}

#[test]
fn scan_with_signatures() {
    for yara in [false, true] {
        let tmp = Tmp::new("scan-sigs");
        let sigs = sig_dir(&tmp.path, yara);
        let out = av(
            &tmp,
            &["scan", &s(tree()), "--json", "--signatures", &s(&sigs)],
        )
        .run();
        let names: Vec<String> = parse_json(&out.stdout)["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["threat"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            names.iter().any(|n| n == "Local.Bad.App") && names.iter().any(|n| n == "Test.Marker")
        );
        if yara {
            assert!(names.iter().any(|n| n == "DropperMarker"));
        }
        let clean = av(
            &tmp,
            &["scan", &s(&tree().join("clean")), "--signatures", &s(&sigs)],
        )
        .run();
        let n = norm(&tmp);
        golden(
            SUITE,
            &format!(
                "scan_with_signatures-{}",
                if yara { "yara" } else { "json" }
            ),
            &format!(
                "{}\n=== clean\n{}",
                report(&out, &n),
                n.apply(&clean.shown())
            ),
        );
    }
}

#[test]
fn scan_reads_guard_home_av() {
    let tmp = Tmp::new("scan-home-av");
    write(
        &tmp.join("home/av/rules-extra.json"),
        extra_rules().to_string(),
    );
    let out = av(&tmp, &["scan", &s(&tree().join("clean"))]).run();
    assert!(out.stdout.contains("Test.Marker"));
    golden(
        SUITE,
        "scan_reads_guard_home_av",
        &norm(&tmp).apply(&out.shown()),
    );
}

// ------------------------------------------------------------------- rules
#[test]
fn rules_listing() {
    for yara in [false, true] {
        let tmp = Tmp::new("rules");
        let bundled = av(&tmp, &["rules"]).run();
        let sigs = sig_dir(&tmp.join("home"), yara);
        std::fs::rename(&sigs, tmp.join("home/av")).unwrap();
        let with_home = av(&tmp, &["rules"]).run();
        golden(
            SUITE,
            &format!("rules_listing-{}", if yara { "yara" } else { "json" }),
            &norm(&tmp).apply(&format!(
                "{}\n=== with ~/.guard/av\n{}",
                bundled.shown(),
                with_home.shown()
            )),
        );
    }
}

fn bad_rules() -> Vec<(&'static str, Value)> {
    vec![
        ("missing", json!([{"id": "x", "name": "n"}])),
        (
            "verdict",
            json!([{"id": "x", "name": "n", "condition": "$a", "verdict": "bogus"}]),
        ),
        (
            "clean",
            json!([{"id": "x", "name": "n", "condition": "$a", "verdict": "clean"}]),
        ),
        (
            "strings",
            json!([{"id": "x", "name": "n", "condition": "$a", "strings": ["no"]}]),
        ),
        (
            "undefined",
            json!([{"id": "x", "name": "n", "condition": {"all": ["$a", "$b"]}, "strings": {"$a": {"text": "a"}}}]),
        ),
        (
            "wildcard",
            json!([{"id": "x", "name": "n", "condition": {"any": ["$z*"]}, "strings": {"$a": {"text": "a"}}}]),
        ),
        (
            "hex",
            json!([{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D ?Z"}}}]),
        ),
        (
            "hexgroup",
            json!([{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D | 5A"}}}]),
        ),
        (
            "jump",
            json!([{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"hex": "4D [x] 5A"}}}]),
        ),
        (
            "empty",
            json!([{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"text": ""}}}]),
        ),
        (
            "nostring",
            json!([{"id": "x", "name": "n", "condition": "$a", "strings": {"$a": {"nope": 1}}}]),
        ),
        (
            "atleast",
            json!([{"id": "x", "name": "n", "condition": {"at_least": 0, "of": "them"}, "strings": {"$a": {"text": "a"}}}]),
        ),
        (
            "andor",
            json!([{"id": "x", "name": "n", "condition": {"and": []}, "strings": {"$a": {"text": "a"}}}]),
        ),
        (
            "at",
            json!([{"id": "x", "name": "n", "condition": {"at": "$q", "offset": 0}, "strings": {"$a": {"text": "a"}}}]),
        ),
        (
            "count",
            json!([{"id": "x", "name": "n", "condition": {"count": "$a", "min": "2"}, "strings": {"$a": {"text": "a"}}}]),
        ),
        (
            "size",
            json!([{"id": "x", "name": "n", "condition": {"filesize_max": 1.5}}]),
        ),
        (
            "op",
            json!([{"id": "x", "name": "n", "condition": {"near": "$a"}, "strings": {"$a": {"text": "a"}}}]),
        ),
        ("badcond", json!([{"id": "x", "name": "n", "condition": 5}])),
        (
            "dup",
            json!([{"id": "x", "name": "n", "condition": {"filesize_min": 1}}, {"id": "x", "name": "m", "condition": {"filesize_min": 1}}]),
        ),
        ("notobj", json!(["just a string"])),
    ]
}

#[test]
fn rules_validate() {
    let tmp = Tmp::new("rules-validate");
    let mut files = vec![s(&write(
        &tmp.join("rules-good.json"),
        extra_rules().to_string(),
    ))];
    let bad = bad_rules();
    for (name, body) in &bad {
        files.push(s(&write(
            &tmp.join(format!("rules-{name}.json")),
            json!({"rules": body}).to_string(),
        )));
    }
    files.push(s(&tmp.join("missing.json")));
    let mut args = vec!["rules", "--validate"];
    args.extend(files.iter().map(String::as_str));
    let out = av(&tmp, &args).run();
    assert_eq!(out.code, 2);
    assert_eq!(out.stdout.matches("FAIL").count(), bad.len() + 1);
    golden(SUITE, "rules_validate", &norm(&tmp).apply(&out.shown()));
}

#[test]
fn rules_validate_yara() {
    let tmp = Tmp::new("rules-validate-yara");
    let good = write(&tmp.join("good.yar"), YARA);
    let warn = write(
        &tmp.join("warn.yara"),
        r#"rule W { strings: $a = "ab" condition: $a }"#,
    );
    let bad = write(&tmp.join("bad.yar"), "rule Broken { condition: nope }");
    let mut all = String::new();
    for f in [good, warn, bad] {
        let out = av(&tmp, &["rules", "--validate", &s(&f)]).run();
        all.push_str(&format!(
            "=== {}\n{}",
            f.file_name().unwrap().to_string_lossy(),
            out.shown()
        ));
    }
    golden(SUITE, "rules_validate_yara", &norm(&tmp).apply(&all));
}

// -------------------------------------------------------------------- hash
#[test]
fn hash() {
    let tmp = Tmp::new("hash");
    let t = tree();
    let out = av(
        &tmp,
        &[
            "hash",
            &s(&t.join("eicar.com")),
            &s(&t.join("clean/empty")),
            &s(&tmp.join("missing")),
            &s(&t.join("clean")),
        ],
    )
    .run();
    let n = norm(&tmp);
    golden(SUITE, "hash", &n.apply(&out.shown()));
    if !WINDOWS {
        golden(SUITE, "hash-stderr", &n.apply(&out.stderr));
    }
}

// --------------------------------------------------------------- quarantine
fn scrub(n: &Norm) -> Norm {
    n.clone()
        .re(r"[0-9a-f]{32}", "<id>")
        .re(r#""quarantined_at": "[^"]+""#, r#""quarantined_at": "<t>""#)
}

fn ids(vault: &Path) -> Vec<String> {
    // the listing order is the vault's (newest first), read straight from it
    let out = guard(&["av", "--vault", &s(vault), "quarantine", "list"]).run();
    assert_eq!(out.code, 0, "{}", out.stderr);
    parse_json(&out.stdout)
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn quarantine_flow() {
    let tmp = Tmp::new("quarantine");
    let work = tmp.join("files");
    copy_tree(&tree().join("samples"), &work.join("samples"));
    copy_tree(&tree().join("arch"), &work.join("arch"));
    std::fs::copy(tree().join("eicar.com"), work.join("eicar.com")).unwrap();
    let vault = tmp.join("vault");
    let v = s(&vault);
    let n = scrub(&norm(&tmp).path(&work, "WORK"));

    let scan = av(&tmp, &["--vault", &v, "scan", &s(&work), "--quarantine"]).run();
    assert_eq!(scan.code, 1, "{}", scan.stderr);
    assert!(scan.stdout.contains("quarantined"));
    let mut left: Vec<String> = walk(&work)
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    left.sort();

    let list = av(&tmp, &["--vault", &v, "quarantine", "list"]).run();
    assert_eq!(list.code, 0);
    let mut items: Vec<Value> = parse_json(&list.stdout).as_array().unwrap().clone();
    assert!(items.iter().all(|e| e.get("key").is_none()));
    items.sort_by_key(|e| e["original_path"].as_str().unwrap_or_default().to_string());
    let listing = n.apply(&canon_json(&Value::Array(items)));

    // restore in place, to a new place, refuse to overwrite, then delete
    let ids = ids(&vault);
    let r0 = av(&tmp, &["--vault", &v, "quarantine", "restore", &ids[0]]).run();
    assert!(
        r0.code == 0 && r0.stdout.starts_with("restored "),
        "{}",
        r0.stderr
    );
    let dest = tmp.join("out").join("x.bin");
    let r1 = av(
        &tmp,
        &[
            "--vault",
            &v,
            "quarantine",
            "restore",
            &ids[1],
            "--to",
            &s(&dest),
        ],
    )
    .run();
    assert_eq!(
        (r1.code, r1.stdout.clone()),
        (0, format!("restored {}\n", s(&dest)))
    );
    let r2 = av(
        &tmp,
        &[
            "--vault",
            &v,
            "quarantine",
            "restore",
            &ids[2],
            "--to",
            &s(&dest),
        ],
    )
    .run();
    assert_eq!(r2.code, 2);
    let del = av(&tmp, &["--vault", &v, "quarantine", "delete", &ids[2]]).run();
    assert_eq!(del.code, 0);
    assert_eq!(n.apply(&del.stdout), "deleted <id>\n");

    golden(
        SUITE,
        "quarantine_flow",
        &format!(
            "{}\n=== left in place\n{}\n=== list\n{}=== restore onto an existing file\n{}",
            n.apply(&scan.shown()),
            left.join("\n"),
            listing,
            n.apply(&r2.shown_all())
        ),
    );
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(d).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        }
        out.push(p);
    }
    out
}

#[test]
fn quarantine_errors() {
    for (i, args) in [
        vec!["list"],
        vec!["delete", "00000000000000000000000000000000"],
        vec!["restore", "../../etc"],
        vec!["restore", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"],
        vec!["delete", "zz"],
    ]
    .into_iter()
    .enumerate()
    {
        let tmp = Tmp::new("quarantine-errors");
        let mut a = vec![
            "--vault".to_string(),
            s(&tmp.join("v")),
            "quarantine".into(),
        ];
        a.extend(args.iter().map(|x| x.to_string()));
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let out = av(&tmp, &a).run();
        golden(
            SUITE,
            &format!("quarantine_errors-{i}"),
            &norm(&tmp).apply(&out.shown_all()),
        );
    }
}

#[test]
fn quarantine_integrity_check() {
    let tmp = Tmp::new("quarantine-integrity");
    let (vault, work) = (tmp.join("v"), tmp.join("w"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::copy(tree().join("eicar.com"), work.join("eicar.com")).unwrap();
    let r = av(
        &tmp,
        &["--vault", &s(&vault), "scan", &s(&work), "--quarantine"],
    )
    .run();
    assert_eq!(r.code, 1);
    let item = std::fs::read_dir(&vault)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "bin"))
        .unwrap();
    let data = std::fs::read(&item).unwrap();
    std::fs::write(&item, [b"tampered".as_slice(), &data[8..]].concat()).unwrap();
    let id = item.file_stem().unwrap().to_string_lossy().into_owned();
    let out = av(&tmp, &["--vault", &s(&vault), "quarantine", "restore", &id]).run();
    assert_eq!(out.code, 2);
    golden(
        SUITE,
        "quarantine_integrity_check",
        &scrub(&norm(&tmp)).apply(&out.shown_all()),
    );
}

/// A vault the Python build wrote (tests/fixtures/legacy-vault): installs
/// upgraded from it must still list and restore what it quarantined.
#[test]
fn restores_a_vault_the_python_build_wrote() {
    let tmp = Tmp::new("legacy-vault");
    let vault = tmp.join("vault");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-vault"),
        &vault,
    );
    let v = s(&vault);
    let list = guard(&["av", "--vault", &v, "quarantine", "list"])
        .exe(&bin())
        .run();
    assert_eq!(list.code, 0, "{}", list.stderr);
    let items = parse_json(&list.stdout);
    let items = items.as_array().unwrap();
    assert_eq!(items.len(), 2);
    for (i, e) in items.iter().enumerate() {
        let id = e["id"].as_str().unwrap();
        let dest = tmp.join(format!("out/{i}"));
        let r = guard(&[
            "av",
            "--vault",
            &v,
            "quarantine",
            "restore",
            id,
            "--to",
            &s(&dest),
        ])
        .exe(&bin())
        .run();
        assert_eq!(r.code, 0, "{}", r.stderr);
        let got = std::fs::read(&dest).unwrap();
        assert!(got.starts_with(&eicar()));
        assert_eq!(
            hex(&sha2::Sha256::digest(&got)),
            e["sha256"].as_str().unwrap()
        );
    }
}

// ------------------------------------------------------------------- usage
#[test]
fn usage_errors() {
    for args in [
        vec![],
        vec!["bogus"],
        vec!["scan"],
        vec!["scan", ".", "--bogus"],
        vec!["hash"],
        vec!["quarantine"],
        vec!["quarantine", "nope"],
        vec!["quarantine", "restore"],
        vec!["rules", "--validate"],
        vec!["scan", "--signatures"],
        vec!["--vault"],
    ] {
        let tmp = Tmp::new("usage");
        let out = av(&tmp, &args).run();
        assert_eq!(out.code, 2, "{args:?}: {}", out.stderr);
    }
}

#[test]
fn help() {
    for args in [vec!["-h"], vec!["scan", "-h"], vec!["quarantine", "-h"]] {
        let tmp = Tmp::new("help");
        let out = av(&tmp, &args).run();
        assert_eq!(out.code, 0);
        assert!(
            out.stdout.starts_with("usage: guard av"),
            "{args:?}: {}",
            out.stdout
        );
    }
}

#[test]
fn abbreviated_options() {
    let tmp = Tmp::new("abbrev");
    let out = av(
        &tmp,
        &[
            "scan",
            &s(&tree().join("samples")),
            "--js",
            "--no-h",
            "--fail",
        ],
    )
    .run();
    assert_eq!(out.code, 1);
    golden(SUITE, "abbreviated_options", &report(&out, &norm(&tmp)));
}
