#!/usr/bin/env bash
# guard-triage-linux.sh - Guard Linux endpoint/server triage (read-only IR sweep).
#
# Mirrors the Windows guard-triage.ps1. Detects the intrusion behaviors seen on
# the server: host recon, an exploit "validator" for CVE-2025-55182 downloaded
# into a system dir, plus the usual persistence/backdoor footholds.
#
# ALL checks in one run -> ONE report file per host:
#     guard-triage-linux_<host>_<timestamp>.txt
#
# READ-ONLY. Changes nothing. Run as root for full coverage:
#     sudo bash guard-triage-linux.sh [--days N] [--out DIR]
#
# NOTE: CVE-2025-55182 is detected by observed IOCs/behavior, not by knowledge of
# the vuln internals. Judge findings by content, not by name (attacker masquerades).

set -u
LC_ALL=C

DAYS=14
OUTDIR="${HOME:-/root}"
while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS="$2"; shift 2 ;;
    --out)  OUTDIR="$2"; shift 2 ;;
    -h|--help) echo "usage: $0 [--days N] [--out DIR]"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; shift ;;
  esac
done

STAMP="$(date +%Y%m%d_%H%M%S)"
HOST="$(hostname 2>/dev/null || echo unknown)"
REPORT="${OUTDIR%/}/guard-triage-linux_${HOST}_${STAMP}.txt"
mkdir -p "$OUTDIR" 2>/dev/null || true

# tee everything to the report
exec > >(tee "$REPORT") 2>&1

hr(){ printf '%s\n' "======================================================================"; }
sec(){ printf '\n==================== %s ====================\n' "$1"; }

CRIT=0; WARN=0
crit(){ CRIT=$((CRIT+1)); printf '  [CRITICAL] %s\n' "$1"; }
warn(){ WARN=$((WARN+1)); printf '  [warn] %s\n' "$1"; }
ok(){ printf '  [ok] %s\n' "$1"; }

# ---- IOCs / patterns --------------------------------------------------------
# Recon commands the attacker ran
RECON_PATTERNS='authorized_keys|/etc/passwd|/etc/shadow|uname -a|hostname -I|\bwhoami\b|\bid\b *$|/etc/os-release'
# Exploit + download-to-system-bin behavior
EXPLOIT_PATTERNS='cve-2025-55182|ce-2025-55182|wget[^|]*-O[ ]*/usr/bin|wget[^|]*-O[ ]*/usr/local/bin|curl[^|]*-o[ ]*/usr/bin|curl[^|]*-o[ ]*/(s)?bin|chmod \+x /usr/bin|/tmp/[^ ]*\.sh|/dev/shm/'
# Reverse-shell / staging patterns
SHELL_PATTERNS='bash -i|nc -e|ncat -e|/dev/tcp/|python[0-9]* -c .*socket|base64 -d *\| *(ba)?sh|curl[^|]*\| *(ba)?sh|wget[^|]*\| *(ba)?sh|perl -e.*Socket'
# Known incident network IOCs (from the GitHub supply-chain case; reuse here)
NET_IOCS='auth-confirm-ten\.vercel\.app|45\.139\.104\.115|carte-avantage\.com'
# System bin dirs that SHOULD be package-owned
SYS_BINDIRS="/usr/bin /bin /usr/sbin /sbin"
LOCAL_BINDIRS="/usr/local/bin /usr/local/sbin /opt"
TMP_DIRS="/tmp /var/tmp /dev/shm"

pkg_owner(){ # 0 if file belongs to a package, 1 if not / unknown
  local f="$1"
  if command -v dpkg >/dev/null 2>&1; then dpkg -S "$f" >/dev/null 2>&1 && return 0; fi
  if command -v rpm  >/dev/null 2>&1; then rpm  -qf "$f" >/dev/null 2>&1 && return 0; fi
  return 1
}

hr
echo "GUARD LINUX TRIAGE"
echo "Host    : $HOST"
echo "User    : $(id -un 2>/dev/null) (uid $(id -u 2>/dev/null))"
echo "OS      : $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
echo "Kernel  : $(uname -a 2>/dev/null)"
echo "Run at  : $(date) (UTC $(date -u +%FT%TZ))"
echo "Window  : last ${DAYS} day(s)"
[ "$(id -u)" -ne 0 ] && echo "WARNING : not root - some checks (other users' files, logs) will be limited."
hr

# =============================================================================
sec "[1] SHELL HISTORY: recon + exploit commands"
# =============================================================================
HIST_FILES="$(ls -1 /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history 2>/dev/null)"
if [ -z "$HIST_FILES" ]; then echo "  (no readable history files)"; fi
for h in $HIST_FILES; do
  [ -r "$h" ] || continue
  hits_recon="$(grep -nEi "$RECON_PATTERNS"  "$h" 2>/dev/null)"
  hits_expl="$(grep -nEi  "$EXPLOIT_PATTERNS" "$h" 2>/dev/null)"
  hits_shell="$(grep -nEi "$SHELL_PATTERNS"  "$h" 2>/dev/null)"
  if [ -n "$hits_expl" ]; then
    crit "exploit/download-to-bin commands in $h:"
    printf '%s\n' "$hits_expl" | sed 's/^/      /'
  fi
  if [ -n "$hits_shell" ]; then
    crit "reverse-shell / pipe-to-shell commands in $h:"
    printf '%s\n' "$hits_shell" | sed 's/^/      /'
  fi
  if [ -n "$hits_recon" ]; then
    n="$(printf '%s\n' "$hits_recon" | wc -l | tr -d ' ')"
    warn "$n recon command line(s) in $h (host enumeration):"
    printf '%s\n' "$hits_recon" | sed 's/^/      /' | head -30
  fi
done

# =============================================================================
sec "[2] SUSPICIOUS BINARIES (system dirs + tmp)"
# =============================================================================
# 2a. the exact CVE artifact anywhere
found="$(find / -xdev \( -name '*cve-2025-55182*' -o -name '*ce-2025-55182*' \) 2>/dev/null)"
if [ -n "$found" ]; then crit "CVE-2025-55182 artifact(s) on disk:"; printf '%s\n' "$found" | sed 's/^/      /'; fi

# 2b. files in SYSTEM bin dirs that no package owns (these SHOULD be owned)
echo "  Checking system bin dirs for unowned/recent files..."
for d in $SYS_BINDIRS; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f -mtime -"$DAYS" 2>/dev/null | while IFS= read -r f; do
    if ! pkg_owner "$f"; then
      printf '  [CRITICAL] unowned file in %s (should be package-managed): %s  [%s]\n' \
        "$d" "$f" "$(stat -c '%y %s bytes owner=%U' "$f" 2>/dev/null)"
    fi
  done
done

# 2c. executables freshly dropped in tmp / shm
for d in $TMP_DIRS; do
  [ -d "$d" ] || continue
  find "$d" -type f -perm -u+x -mtime -"$DAYS" 2>/dev/null | while IFS= read -r f; do
    printf '  [warn] executable in %s: %s  [%s]\n' "$d" "$f" "$(stat -c '%y %s bytes' "$f" 2>/dev/null)"
  done
done

# 2d. recent files in local bin/opt (expected unowned; review anyway)
for d in $LOCAL_BINDIRS; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 2 -type f -mtime -"$DAYS" 2>/dev/null | sed 's/^/  [review] recent local bin: /'
done

# =============================================================================
sec "[3] PERSISTENCE (cron, systemd, rc, shell profiles)"
# =============================================================================
echo "  -- cron --"
for c in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$c" ] || continue
  bad="$(grep -nEi "$EXPLOIT_PATTERNS|$SHELL_PATTERNS|$NET_IOCS" "$c" 2>/dev/null)"
  if [ -n "$bad" ]; then crit "suspicious cron entry in $c:"; printf '%s\n' "$bad" | sed 's/^/      /';
  else printf '  [ok] %s\n' "$c"; fi
done

echo "  -- systemd units modified in window --"
find /etc/systemd/system /lib/systemd/system /run/systemd/system -name '*.service' -mtime -"$DAYS" 2>/dev/null | while IFS= read -r u; do
  ex="$(grep -nE 'ExecStart' "$u" 2>/dev/null | grep -Ei "$EXPLOIT_PATTERNS|$SHELL_PATTERNS|/tmp/|/dev/shm/")"
  if [ -n "$ex" ]; then crit "suspicious systemd unit $u:"; printf '%s\n' "$ex" | sed 's/^/      /';
  else printf '  [review] recently-modified unit: %s\n' "$u"; fi
done

echo "  -- shell profiles / rc files modified in window --"
for p in /etc/profile /etc/bash.bashrc /etc/rc.local /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile; do
  [ -f "$p" ] || continue
  if find "$p" -mtime -"$DAYS" 2>/dev/null | grep -q .; then
    bad="$(grep -nEi "$EXPLOIT_PATTERNS|$SHELL_PATTERNS|$NET_IOCS|curl|wget" "$p" 2>/dev/null)"
    if [ -n "$bad" ]; then warn "recently-modified $p contains download/exec lines:"; printf '%s\n' "$bad" | sed 's/^/      /';
    else printf '  [review] recently modified: %s\n' "$p"; fi
  fi
done

echo "  -- ld.so.preload (rootkit hook) --"
if [ -s /etc/ld.so.preload ]; then crit "/etc/ld.so.preload is non-empty (possible LD_PRELOAD rootkit):"; sed 's/^/      /' /etc/ld.so.preload; else ok "/etc/ld.so.preload empty/absent"; fi

# =============================================================================
sec "[4] SSH: authorized_keys + recent auth"
# =============================================================================
for ak in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$ak" ] || continue
  cnt="$(grep -cvE '^\s*(#|$)' "$ak" 2>/dev/null)"
  mod="$(stat -c '%y' "$ak" 2>/dev/null)"
  printf '  authorized_keys: %s  (%s key(s), modified %s)\n' "$ak" "$cnt" "$mod"
  # show key comment/type for review; flag if modified within window
  sed 's/^/        key: /' "$ak" 2>/dev/null | awk '{print $1, $2, $NF}' | sed 's/^/      /'
  if find "$ak" -mtime -"$DAYS" 2>/dev/null | grep -q .; then warn "authorized_keys MODIFIED within window: $ak"; fi
done
echo "  -- recent accepted logins --"
for L in /var/log/auth.log /var/log/secure; do
  [ -r "$L" ] || continue
  grep -E 'Accepted (password|publickey)' "$L" 2>/dev/null | tail -15 | sed 's/^/      /'
done

# =============================================================================
sec "[5] PROCESSES + NETWORK"
# =============================================================================
echo "  -- processes executing from tmp/shm/deleted --"
if [ -d /proc ]; then
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe="$(readlink -f /proc/$pid/exe 2>/dev/null)" || continue
    cmd="$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120)"
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/home/*|/root/*)
        crit "process $pid runs from suspicious path: $exe ($cmd)" ;;
      *"(deleted)"*)
        # A deleted-inode exe is BENIGN after a package/kernel update for system
        # paths (reboot clears it). Only condemn if the deleted binary lived in a
        # user/temp path (handled above). Judge by PATH, not the (deleted) flag.
        case "$exe" in
          /usr/*|/lib/*|/lib64/*|/bin/*|/sbin/*|/opt/*|/snap/*)
            printf '  [note] pid %s runs a replaced/deleted system binary: %s (normal after an update; reboot to clear)\n' "$pid" "$exe" ;;
          *)
            crit "process $pid runs a DELETED non-system binary: $exe ($cmd)" ;;
        esac ;;
    esac
  done
fi
echo "  -- listening + established sockets --"
if command -v ss >/dev/null 2>&1; then ss -tunap 2>/dev/null | sed 's/^/      /' | head -40
elif command -v netstat >/dev/null 2>&1; then netstat -tunap 2>/dev/null | sed 's/^/      /' | head -40; fi
echo "  -- connection-flood check (DoS / brute force) --"
if command -v ss >/dev/null 2>&1; then
  # count connections per peer IP; a single peer with many is a flood signal
  flood="$(ss -tn 2>/dev/null | awk 'NR>1{split($5,a,":"); if(a[1]!="")print a[1]}' | sort | uniq -c | sort -rn | awk '$1>=20{print}')"
  synf="$(ss -tn state syn-recv 2>/dev/null | awk 'NR>1{split($5,a,":"); if(a[1]!="")print a[1]}' | sort | uniq -c | sort -rn | awk '$1>=20{print}')"
  if [ -n "$synf" ]; then
    crit "SYN-flood: peer(s) with >=20 half-open connections (possible DoS):"
    printf '%s\n' "$synf" | sed 's/^/      /'
  elif [ -n "$flood" ]; then
    warn "peer(s) with >=20 open connections (review - flood or busy client):"
    printf '%s\n' "$flood" | sed 's/^/      /'
  else
    ok "no single-peer connection flood"
  fi
fi

# =============================================================================
sec "[6] IOC SWEEP (logs + web access to /auth/sign-in)"
# =============================================================================
echo "  -- incident network IOCs in logs --"
for L in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
  [ -r "$L" ] || continue
  m="$(grep -nEi "$NET_IOCS|$EXPLOIT_PATTERNS" "$L" 2>/dev/null | tail -20)"
  [ -n "$m" ] && { crit "IOC/exploit strings in $L:"; printf '%s\n' "$m" | sed 's/^/      /'; }
done
echo "  -- web server access logs: exploit hits on /auth/sign-in --"
for L in /var/log/nginx/*access*.log /var/log/apache2/*access*.log /var/log/httpd/*access*.log; do
  [ -r "$L" ] || continue
  m="$(grep -aE '/auth/sign-in' "$L" 2>/dev/null | grep -aiE 'curl|wget|python|go-http|validator|cve|sqlmap|nikto|\.\./|%2e%2e' | tail -20)"
  [ -n "$m" ] && { warn "suspicious /auth/sign-in requests in $L:"; printf '%s\n' "$m" | sed 's/^/      /'; }
done

# =============================================================================
sec "[7] VERDICT: $HOST"
# =============================================================================
printf '  Critical findings : %d\n' "$CRIT"
printf '  Warnings          : %d\n' "$WARN"
if [ "$CRIT" -gt 0 ]; then
  echo "  >>> INTRUSION ARTIFACTS FOUND. Preserve, isolate this host from the network,"
  echo "      rotate ALL credentials/SSH keys it could reach, and escalate to IR."
elif [ "$WARN" -gt 0 ]; then
  echo "  >>> No critical artifacts, but review the warnings above (recon/oddities)."
else
  echo "  >>> No intrusion artifacts of these patterns found on this host."
fi
echo
echo "Report written -> $REPORT"
echo "Judge every finding by CONTENT/HASH, not by name - the attacker masquerades."
