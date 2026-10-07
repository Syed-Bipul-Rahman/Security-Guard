# Bundled community YARA rules

Guard compiles these rule sets into the `guard` binary (gzipped, see
`cli/build.rs`) and loads them on every engine start, next to the JSON rules
in `data/av-rules.json` and any `.yar` files in `~/.guard/av`. Each file is its
own namespace, so a hit's rule id is `yara:<file>.<rule>`, for example
`yara:reversinglabs.Win32_Ransomware_GandCrab`. Hits are reported as
suspicious; none of these rules sets `verdict = "malicious"`.

| File | Source | License | Rules |
| --- | --- | --- | --- |
| `reversinglabs.yar` | [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) `e0a0be5` | MIT | 309 |
| `signature-base.yar` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) `94a1c48` | Detection Rule License 1.1 | 1,740 |
| `eset.yar` | [eset/malware-ioc](https://github.com/eset/malware-ioc) `17baf44` | BSD 2-Clause | 115 |
| `gcti.yar` | [chronicle/GCTI](https://github.com/chronicle/GCTI) `1c5fd42` | Apache 2.0 | 91 |
| `binaryalert.yar` | [airbnb/binaryalert](https://github.com/airbnb/binaryalert) `a9c0f06` | Apache 2.0 | 79 |

The license texts are in `LICENSES.txt`, and `guard av rules --licenses`
prints them from the binary. The Detection Rule License asks that alerts name
the rule's author, so every signature-base rule's description ends with
`(author: ...)`, which Guard shows with each hit.

## Why these

They are the sources YARA Forge (https://github.com/YARAHQ/yara-forge) rates
highest whose licenses allow shipping the rules inside Guard. YARA Forge's own
packages mix in sources with share-alike, non-commercial or no license at all,
and Elastic's rules (Elastic License 2.0) are excluded for the same reason
YARA Forge excludes them.

## How the files were made

Snapshot of 2026-10-07, following YARA Forge's "core" package rules:

1. Every rule from the source files: `yara/**/*.yara` (ReversingLabs),
   `**/*.yar` (ESET), `YARA/**/*.yara` (GCTI), `rules/public/**/*.yara`
   (BinaryAlert), `yara/*.yar` (signature-base).
2. Whole files left out, because they are slow to compile or are not malware
   detections: ReversingLabs' certificate blocklist, and signature-base's
   vulnerable-driver, web-shell, log-file and Log4j rules (paths matching
   `certificate/|^vuln|vulndriver|vuln_drivers|configured_vulns|webshell|_logs?(_sigs)?\.yar$|^log_|log4j`).
3. signature-base rules with a `score` below 65 (no score counts as 75), or
   last modified before 2019-12-03 (2,500 days, YARA Forge core's age limit).
4. Rules that flag clean files: signature-base's `SUSP_shellpop_Bash` (a
   reverse-shell one-liner quoted in a SECURITY.md) and
   `PUA_Crypto_Mining_CommandLine_Indicators_Oct21` (miner options in text or
   base64), and ESET's `skip20_sqllang_hook` (it matches common compiler
   code in Windows' own System32 DLLs).
5. Rules that don't compile in yara-x on their own (they need the external
   variables `filename`, `filepath` or `extension`, or an `include`) and
   duplicate rule names within a source (first one kept).
6. Each source written as one file with plyara: the kept rules plus the
   private rules they use, with their imports.

Before bundling, the full candidate set (5,953 rules) scanned 125,000 files
with no hit: `/usr/bin`, `/usr/lib`, `/usr/local/lib`, `/usr/share`, the Cargo
registry and this repository's `core`, `data`, `docs` and `testdata`. The
false-positive tests in `cli/tests/detection.rs` (an adversarial benign corpus,
system binaries, the Python standard library and the whole repository) run
with these rules on every CI run, on Linux, macOS and Windows; they found the
rules in step 4.

## Cost and opting out

Compiling the 2,334 rules adds about 3 seconds to each engine start (one
`guard av scan`, `guard scan`, or the start of `guard watch`). Set
`GUARD_COMMUNITY_RULES=0` to leave them out, or silence one rule with an
allowlist entry `yara:<file>.<rule>`.
