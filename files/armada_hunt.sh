#!/bin/sh
# ARMADA_HUNT_SELF  (marker: the hunter excludes files/processes containing this string)
#
# ARMADA "guard" implant + kworkerd bot + libproc.so LD_PRELOAD rootkit - IOC hunt.
# Read-only. POSIX sh. Meant to run under a STATIC busybox: a static binary never
# loads /etc/ld.so.preload, so the rootkit cannot hide anything from it. The
# system's own (dynamic, possibly hooked) ls/cat are used only for cross-view diffs.
#
# Output lines:  HIT|type|detail   SUSPECT|type|detail   INFO|type|detail
#
# Env:
#   IOC_HASHES       space separated sha256 IOCs
#   HUNT_MODE        static | degraded
#   BB_BIN           dir of busybox applet symlinks (static mode; becomes PATH)
#   HUNT_DIR         hunter work dir (excluded from results)
#   SCAN_HOME        true|false  recurse /root and /home
#   SCAN_CONTAINERS  true|false  scan docker/podman/containerd overlay layers
#   CONTAINER_GLOBS  override container layer globs
#   DYN_LS / DYN_CAT override system tools used for cross-view (testing)

[ -n "${BB_BIN:-}" ] && PATH=$BB_BIN && export PATH
HUNT_MODE=${HUNT_MODE:-degraded}
HUNT_DIR=${HUNT_DIR:-/nonexistent-armada-hunt}
SCAN_HOME=${SCAN_HOME:-true}
SCAN_CONTAINERS=${SCAN_CONTAINERS:-true}
IOC_HASHES=$(printf '%s' "${IOC_HASHES:-}" | tr 'A-F' 'a-f')
CONTAINER_GLOBS=${CONTAINER_GLOBS:-"/var/lib/docker/overlay2/*/diff /var/lib/containers/storage/overlay/*/diff /home/*/.local/share/containers/storage/overlay/*/diff /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs /var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs"}

if [ -z "${DYN_LS:-}" ]; then for c in /bin/ls /usr/bin/ls; do [ -x "$c" ] && DYN_LS=$c && break; done; fi
if [ -z "${DYN_CAT:-}" ]; then for c in /bin/cat /usr/bin/cat; do [ -x "$c" ] && DYN_CAT=$c && break; done; fi

W=$(mktemp -d 2>/dev/null) || W=/tmp/.armada_hunt_w.$$
mkdir -p "$W" 2>/dev/null
trap 'rm -rf "$W"' EXIT INT TERM

# Strings that only appear in guard / the bot / the rootkit loader
IOC_RE='kworkerd|/\.d/tor|/\.d/i2pd|/tmp/\.ar([^A-Za-z0-9]|$)|/d/[A-Za-z0-9_-]+/init\.sh|libproc\.so|\.2f3a9c1e|ARMADA_|/\.guard|HYDRA_SOCKS|RK_(PID|PORTS|FILES)'

hit()     { printf 'HIT|%s|%s\n' "$1" "$2"; }
suspect() { printf 'SUSPECT|%s|%s\n' "$1" "$2"; }
info()    { printf 'INFO|%s|%s\n' "$1" "$2"; }
pr()      { tr -cd '\40-\176'; }
selfpath() { case "$1" in "$HUNT_DIR"|"$HUNT_DIR"/*|"$W"|"$W"/*) return 0 ;; esac; return 1; }

shafile() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | cut -c1-64
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'; fi
}
known_bad() { [ -n "$1" ] || return 1; for _k in $IOC_HASHES; do [ "$1" = "$_k" ] && return 0; done; return 1; }
finfo() {
  [ -f "$1" ] || { printf '(dir/other)'; return; }
  _h=$(shafile "$1"); _s=$(stat -c %s "$1" 2>/dev/null); _m=$(stat -c %y "$1" 2>/dev/null | cut -d. -f1)
  _kb=""; known_bad "$_h" && _kb=" KNOWN-BAD-HASH"
  printf 'sha256=%s size=%s mtime=%s%s' "$_h" "$_s" "$_m" "$_kb"
}
# True when we (static) can see a path but the system's dynamic ls cannot -> rootkit
xhidden() {
  [ "$HUNT_MODE" = static ] && [ -n "$DYN_LS" ] || return 1
  "$DYN_LS" -d -- "$1" >/dev/null 2>&1 && return 1
  return 0
}
xtag() { xhidden "$1" && printf ' HIDDEN-FROM-SYSTEM-TOOLS(rootkit)'; }
fhit() { hit "$1" "$2 $(finfo "$2")$(xtag "$2")"; }

# Self-healing launcher script written by guard
is_launcher() {
  [ -f "$1" ] || return 1
  grep -qF 'exec "$d/.guard" $ARGS' "$1" 2>/dev/null && return 0
  grep -qF 'ARGS="' "$1" 2>/dev/null && grep -qE '^C=".*/guard"$' "$1" 2>/dev/null && return 0
  return 1
}
judge_ref() { # $1=type $2=where $3=referenced script (already root-prefixed)
  if is_launcher "$3"; then hit "$1" "$2 -> launcher $3 ($(finfo "$3"))$(xtag "$3")"
  else suspect "$1" "$2 -> $3 (not confirmed as launcher)"; fi
}

# ---------------------------------------------------------------------------
# File-system checks. $1 = root prefix ("" = host, else container layer dir)
# $2 = 1 for container layer
# ---------------------------------------------------------------------------
check_root() {
  R=$1; CT=$2

  # 1. Known paths (guard, bot, rival artefacts guard cleans up, rootkit lib)
  for f in /dev/shm/.guard /var/tmp/.guard /tmp/.guard \
           /root/.kworkerd /root/.kworkerd.keep /root/.kworkerd.new \
           /var/tmp/.kworkerd.keep /var/tmp/.kworkerd.new /dev/shm/.kworkerd.keep /dev/shm/.kworkerd.new \
           /root/.ar /root/.ar.keep /var/tmp/.ar /var/tmp/.ar.keep /dev/shm/.ar /dev/shm/.ar.keep /tmp/.ar \
           /var/tmp/init.sh /dev/shm/init.sh /tmp/.hct /tmp/.k /tmp/.k/salt /usr/lib/libproc.so; do
    { [ -e "$R$f" ] || [ -L "$R$f" ]; } && fhit file "$R$f"
  done
  for f in "$R"/tmp/.hlm??????; do [ -e "$f" ] && fhit file "$f"; done

  # 2. LD_PRELOAD rootkit registration
  f="$R/etc/ld.so.preload"
  if [ -e "$f" ]; then
    c=$(head -c 400 "$f" 2>/dev/null | tr '\n' ' ' | pr)
    if grep -q 'libproc\.so' "$f" 2>/dev/null; then hit rootkit "$f contents=[$c]$(xtag "$f")"
    elif [ -s "$f" ]; then suspect preload "$f contents=[$c] (verify each library is legitimate)$(xtag "$f")"; fi
    for lib in $(cat "$f" 2>/dev/null); do
      [ -f "$R$lib" ] && info preload-lib "$R$lib $(finfo "$R$lib")"
    done
  fi

  # 3. Implant working directories /var/lib/.X /var/tmp/.X /dev/shm/.X /tmp/.X
  for d in "$R"/var/lib/.* "$R"/var/tmp/.* "$R"/dev/shm/.* "$R"/tmp/.*; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    case "$d" in */.|*/..) continue ;; esac
    selfpath "$d" && continue
    n=0
    for s in slug payload.enc key guard.pid full.pid boot.id record.json installed c2 lock hash salt; do
      [ -e "$d/$s" ] && n=$((n + 1))
    done
    [ "$n" -ge 3 ] && hit statedir "$d ($n implant state files)$(xtag "$d")"
    [ "$n" -eq 2 ] && suspect statedir "$d (2 implant-like state files)"
    [ -f "$d/payload.enc" ] && fhit payload "$d/payload.enc"
    [ -f "$d/guard" ] && fhit binary "$d/guard"
    [ -f "$d/run" ] && is_launcher "$d/run" && hit launcher "$d/run"
    [ -f "$d/.d/tor" ] && fhit tor-binary "$d/.d/tor"
    [ -f "$d/.d/i2pd.conf" ] && fhit i2pd-config "$d/.d/i2pd.conf"
    [ -f "$d/.d/.c" ] && grep -q '^SocksPort 127\.0\.0\.1:9151' "$d/.d/.c" 2>/dev/null && hit tor-config "$d/.d/.c (SocksPort 127.0.0.1:9151)"
    [ -f "$d/c2" ] && info c2 "$d/c2: $(head -c 300 "$d/c2" | pr)"
    [ -f "$d/slug" ] && info slug "$d/slug: $(head -c 100 "$d/slug" | pr)"
    [ -f "$d/record.json" ] && info record "$d/record.json: $(head -c 300 "$d/record.json" | pr)"
  done

  # 4. Per-user hidden cache dir used by guard
  homes="$R/root $(ls -d "$R"/home/* 2>/dev/null | tr '\n' ' ')"
  [ "$CT" = 0 ] && homes="$homes $(awk -F: '$6 != "" && $6 != "/" {print $6}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
  for hd in $homes; do
    c="$hd/.cache/.2f3a9c1e"
    [ -e "$c" ] || continue
    hit cachedir "$c: $(ls -A "$c" 2>/dev/null | tr '\n' ' ')$(xtag "$c")"
    [ -f "$c/guard" ] && fhit binary "$c/guard"
    [ -f "$c/run" ] && is_launcher "$c/run" && hit launcher "$c/run"
  done

  # 5. systemd units (guard: "System Service Manager"; bot: oneshot wget|curl dropper)
  for u in $(find "$R/etc/systemd/system" "$R/run/systemd/system" "$R/lib/systemd/system" \
                  "$R/usr/lib/systemd/system" -maxdepth 2 -name '*.service' 2>/dev/null); do
    [ -f "$u" ] || continue
    if grep -q '^Description=System Service Manager$' "$u" 2>/dev/null; then
      x=$(sed -n 's#^ExecStart=/bin/sh \([^ ]*\).*#\1#p' "$u" | head -n 1)
      if [ -n "$x" ]; then judge_ref systemd "$u" "$R$x"; else suspect systemd "$u (description match)"; fi
    fi
    grep -qF 'sh $F; rm -f $F' "$u" 2>/dev/null && \
      hit systemd-dropper "$u: $(grep -m1 '^ExecStart=' "$u" | pr | cut -c1-300)$(xtag "$u")"
    grep -qE "$IOC_RE" "$u" 2>/dev/null && \
      hit systemd-ioc "$u: $(grep -m1 -E "$IOC_RE" "$u" | pr | cut -c1-300)"
  done

  # 6. cron + shell/boot autostart hooks (Debian/Ubuntu + RHEL/CentOS/Alma layouts)
  for f in "$R"/etc/crontab "$R"/etc/cron.d/* "$R"/var/spool/cron/crontabs/* "$R"/var/spool/cron/* \
           "$R"/etc/crontabs/* "$R"/etc/cron.hourly/* "$R"/etc/cron.daily/* \
           "$R"/etc/rc.local "$R"/etc/rc.d/rc.local "$R"/etc/profile "$R"/etc/profile.d/* \
           "$R"/etc/bash.bashrc "$R"/etc/bashrc "$R"/etc/update-motd.d/* \
           "$R"/root/.profile "$R"/root/.bashrc "$R"/root/.bash_profile "$R"/root/.ssh/rc \
           "$R"/home/*/.profile "$R"/home/*/.bashrc "$R"/home/*/.bash_profile "$R"/home/*/.ssh/rc; do
    [ -f "$f" ] || continue
    is_launcher "$f" && hit launcher "$f$(xtag "$f")"
    grep -nE "$IOC_RE" "$f" 2>/dev/null | while IFS= read -r l; do
      hit persistence "$f:$(printf '%s' "$l" | pr | cut -c1-300)"
    done
    grep -nE '@reboot( root)? /bin/sh [^ ]+' "$f" 2>/dev/null | while IFS= read -r l; do
      x=$(printf '%s\n' "$l" | sed -n 's#.*@reboot\( root\)\{0,1\} /bin/sh \([^ ]*\).*#\2#p')
      judge_ref cron "$f:$l" "$R$x"
    done
    grep -nE '^\[ -x [^ ]+ \] && /bin/sh [^ ]+ >/dev/null 2>&1 &$|^/bin/sh [^ ]+ &$' "$f" 2>/dev/null |
    while IFS= read -r l; do
      x=$(printf '%s\n' "$l" | sed -n 's#.*/bin/sh \([^ ]*\).*#\1#p')
      judge_ref autostart "$f:$l" "$R$x"
    done
    case "$f" in */.ssh/rc) suspect ssh-rc "$f: $(head -c 200 "$f" | tr '\n' ';' | pr)" ;; esac
  done

  # 7. Recursive content scan: launcher script / guard / bot binaries anywhere likely
  if [ "$CT" = 1 ]; then
    paths="$R/etc $R/tmp $R/var/tmp $R/dev/shm $R/root $R/home $R/usr/local/bin $R/usr/local/sbin"
  else
    paths="$R/etc $R/tmp $R/var/tmp $R/dev/shm $R/usr/local/bin $R/usr/local/sbin $(ls -d "$R"/var/lib/.[!.]* 2>/dev/null | tr '\n' ' ')"
    [ "$SCAN_HOME" = true ] && paths="$paths $R/root $R/home"
  fi
  for d in $paths; do
    [ -d "$d" ] || continue
    # 7a. text: guard launcher script
    find "$d" -xdev \( -path /proc -o -path "$HUNT_DIR" -o -path "$W" \
         -o -path "$R/home/*/.local/share/containers" \) -prune \
         -o -type f -size -2048k -exec grep -lsF -e 'exec "$d/.guard" $ARGS' {} + 2>/dev/null |
    while IFS= read -r f; do
      selfpath "$f" && continue
      grep -qF ARMADA_HUNT_SELF "$f" 2>/dev/null && continue
      [ "$(head -c 4 "$f" 2>/dev/null | tail -c 3)" = "ELF" ] && continue   # handled in 7b
      hit launcher "$f$(xtag "$f")"
    done
    # 7b. ELF: guard / bot builds (catches new variants with unknown hashes).
    # NULs -> newlines first: busybox grep stops at NUL bytes inside a line.
    find "$d" -xdev \( -path /proc -o -path "$HUNT_DIR" -o -path "$W" \
         -o -path "$R/home/*/.local/share/containers" \) -prune \
         -o -type f -size +10k -size -20480k -print 2>/dev/null |
    while IFS= read -r f; do
      [ "$(head -c 4 "$f" 2>/dev/null | tail -c 3)" = "ELF" ] || continue
      selfpath "$f" && continue
      if tr '\0' '\n' < "$f" 2>/dev/null | grep -aqF -e ARMADA_GUARD_CTL -e ARMADA_PORTSTEAL \
           -e 'libproc.so,%s,.d' -e 'exec "$d/.guard" $ARGS'; then
        hit binary "$f (ELF with ARMADA strings) $(finfo "$f")$(xtag "$f")"
      fi
    done
  done

  # 8. Hash sweep in staging dirs
  if [ -n "$IOC_HASHES" ]; then
    find "$R/tmp" "$R/var/tmp" "$R/dev/shm" "$R/root" "$R/usr/local/bin" "$R/usr/local/sbin" "$R/usr/lib/libproc.so" \
         $(ls -d "$R"/var/lib/.[!.]* 2>/dev/null) -xdev -maxdepth 4 -type f -size +10k -size -20480k 2>/dev/null |
    while IFS= read -r f; do
      selfpath "$f" && continue
      h=$(shafile "$f")
      known_bad "$h" && hit hash "$f sha256=$h$(xtag "$f")"
    done
  fi
}

# ---------------------------------------------------------------------------
# Host-only: processes
# ---------------------------------------------------------------------------
check_procs() {
  rk_n=0; rk_pids=""
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    comm=$(cat "$p/comm" 2>/dev/null) || continue
    cmdraw=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$cmdraw" in *ARMADA_HUNT_SELF*|*"$HUNT_DIR"*) continue ;; esac
    exe=$(readlink "$p/exe" 2>/dev/null)
    cmd=$(printf '%s' "$cmdraw" | pr | cut -c1-300)

    # Real kworkers are kernel threads: no exe link, empty cmdline
    case "$comm" in kworker*) [ -n "$exe" ] && hit process "pid=$pid fake kernel thread comm=$comm exe=$exe cmd=$cmd" ;; esac
    case "$cmd" in kworker*|\[kworker*) [ -n "$exe" ] && hit process "pid=$pid fake kworker argv exe=$exe" ;; esac
    case "$comm" in kworkerd*) hit process "pid=$pid comm=$comm exe=$exe cmd=$cmd" ;; esac
    case "$cmd" in
      *--payload=*--key=*|*--daemon\ --name=*|*--beacon=*) hit process "pid=$pid guard args: $cmd" ;;
    esac
    case "$exe" in
      /memfd:*) hit process "pid=$pid runs from memfd exe=$exe comm=$comm cmd=$cmd" ;;
      */.d/tor*) hit process "pid=$pid bundled tor exe=$exe cmd=$cmd" ;;
      */.guard*|*/.kworkerd*|*/.2f3a9c1e/*|*/.ar|*/.ar\ *) hit process "pid=$pid exe=$exe cmd=$cmd" ;;
      /tmp/*|/var/tmp/*|/dev/shm/*) suspect process "pid=$pid exe in tmp: $exe cmd=$cmd" ;;
    esac
    case "$exe" in /memfd:*|/tmp/*|/var/tmp/*|/dev/shm/*|*" (deleted)")
      h=$(shafile "$p/exe")
      known_bad "$h" && hit process "pid=$pid exe=$exe KNOWN-BAD-HASH sha256=$h" ;;
    esac
    if grep -q 'libproc\.so' "$p/maps" 2>/dev/null; then
      rk_n=$((rk_n + 1)); [ "$rk_n" -le 10 ] && rk_pids="$rk_pids $pid($comm)"
    fi
    e=$(tr '\0' '\n' < "$p/environ" 2>/dev/null |
        grep -oE '^(ARMADA_[A-Z_]+|GUARD_(PAYLOAD|KEY|URL|BEACON|RECORD|SLUG)|RK_(PID|PORTS|FILES)|HYDRA_SOCKS)=|^LD_PRELOAD=.*libproc[^:]*' |
        tr '\n' ' ' | pr)
    [ -n "$e" ] && hit process "pid=$pid comm=$comm exe=$exe implant env: $e"
  done
  [ "$rk_n" -gt 0 ] && hit rootkit-loaded "libproc.so mapped into $rk_n processes, e.g.$rk_pids"
}

# ---------------------------------------------------------------------------
# Host-only: listening sockets (tor SOCKS 127.0.0.1:9151, bot socks :1080)
# ---------------------------------------------------------------------------
listen_set() { # $1 = cat binary
  for t in tcp tcp6; do "$1" /proc/net/$t 2>/dev/null | awk -v t=$t 'NR>1 && $4=="0A" {print t" "$2" "$10}'; done
  for t in udp udp6; do "$1" /proc/net/$t 2>/dev/null | awk -v t=$t 'NR>1 && $4=="07" {print t" "$2" "$10}'; done
}
sock_owner() { # inode -> "pid(comm)"
  for fd in /proc/[0-9]*/fd/*; do
    [ "$(readlink "$fd" 2>/dev/null)" = "socket:[$1]" ] || continue
    _p=${fd%/fd/*}; printf '%s(%s) ' "${_p#/proc/}" "$(cat "$_p/comm" 2>/dev/null)"
  done
}
check_listeners() {
  listen_set cat | sort -u > "$W/l1"
  while read -r proto addr inode; do
    case "$addr" in
      0100007F:23BF) hit listener "$proto 127.0.0.1:9151 (bundled tor SOCKS) owner=$(sock_owner "$inode")" ;;
      00000000:0438|00000000000000000000000000000000:0438)
        suspect listener "$proto *:1080 (bot !socks default) owner=$(sock_owner "$inode")" ;;
    esac
  done < "$W/l1"
}

# ---------------------------------------------------------------------------
# Host-only cross-view (static vs system dynamic tools) -> rootkit hiding
# ---------------------------------------------------------------------------
xview() {
  [ "$HUNT_MODE" = static ] || return 0
  [ -n "$DYN_LS" ] && [ -n "$DYN_CAT" ] || { suspect xview "system ls/cat not found; cross-view skipped"; return 0; }

  # processes
  ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort > "$W/p1"
  "$DYN_LS" /proc 2>/dev/null | grep -E '^[0-9]+$' | sort > "$W/pd"
  ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort > "$W/p2"
  if [ -s "$W/pd" ]; then
    grep -xFf "$W/p2" "$W/p1" | grep -vxFf "$W/pd" | while read -r pid; do
      [ -n "$pid" ] || continue
      hit rootkit-hidden-process "pid=$pid comm=$(cat /proc/$pid/comm 2>/dev/null) exe=$(readlink /proc/$pid/exe 2>/dev/null) cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | pr | cut -c1-200)"
    done
  else
    hit rootkit-hidden-process "system ls shows no processes in /proc while static view does"
  fi

  # directory entries
  for d in / /etc /usr/lib /usr/lib64 /lib /lib64 /tmp /var/tmp /dev/shm /root /root/.cache /var/lib \
           /usr/local/bin /usr/local/sbin /etc/systemd/system /etc/cron.d /etc/profile.d \
           /home/* /home/*/.cache; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    case "$d" in /) pfx="" ;; *) pfx=$d ;; esac
    ls -A "$d" 2>/dev/null | sort > "$W/a"
    "$DYN_LS" -A "$d" 2>/dev/null | sort > "$W/b" || continue
    ls -A "$d" 2>/dev/null | sort > "$W/c"
    [ -s "$W/b" ] || [ ! -s "$W/a" ] || { hit rootkit-hidden-file "$d: system ls shows empty dir, static view does not"; continue; }
    grep -xFf "$W/c" "$W/a" | grep -vxFf "$W/b" | while IFS= read -r n; do
      [ -n "$n" ] || continue
      selfpath "$pfx/$n" && continue
      hit rootkit-hidden-file "$pfx/$n $(finfo "$pfx/$n")"
    done
  done

  # listening sockets
  listen_set "$DYN_CAT" | sort -u > "$W/ld"
  listen_set cat | sort -u > "$W/l2"
  if [ -s "$W/ld" ] || [ ! -s "$W/l1" ]; then
    grep -xFf "$W/l2" "$W/l1" | grep -vxFf "$W/ld" | while read -r proto addr inode; do
      [ -n "$addr" ] || continue
      port=$(printf '%d' "0x${addr##*:}" 2>/dev/null)
      hit rootkit-hidden-port "$proto $addr (port $port) inode=$inode owner=$(sock_owner "$inode")"
    done
  else
    suspect rootkit-hidden-port "system cat shows no listening sockets while static view does"
  fi
}

main() {
  info mode "$HUNT_MODE"
  check_root "" 0
  check_procs
  check_listeners
  xview
  if [ "$SCAN_CONTAINERS" = true ]; then
    nl=0
    for L in $CONTAINER_GLOBS; do
      [ -d "$L" ] || continue
      nl=$((nl + 1))
      check_root "$L" 1
    done
    info containers "$nl container layer(s) scanned"
  fi
}

main 2>/dev/null | sort -u
exit 0
