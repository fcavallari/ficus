#!/bin/bash
# mac-triage.sh: the read-only "am I pwned?" checks of this skill (references/checks-macos.md), run in one go, writing
# ONE report file for the person to share and an agent (or Security Ops) to read.
#
#   bash mac-triage.sh [-o REPORT_FILE]
#
# What it never does: use sudo, change or delete anything, read a secret. It does not read keychains, ssh keys, shell
# history, environment variables, cookies, cloud CLI configs or documents (references/off-limits.md), and it prints no
# process command lines (only paths) and no launch-item arguments beyond the first two. A check that fails or needs
# rights it does not have is written as "COULD NOT CHECK: <why>", never as a pass.
#
# Runs on the macOS that ships bash 3.2, so no bash 4 features. Run it as yourself, not as root.

set -u
umask 077
export LC_ALL=C

VERSION=1
OUT=''
usage() { printf 'usage: bash mac-triage.sh [-o REPORT_FILE]\n  Writes one read-only report; default %s\n' "~/am-i-pwned-report-<UTC time>.txt"; }
while [ $# -gt 0 ]; do
  case $1 in
    -o) [ $# -ge 2 ] || { usage >&2; exit 2; }; OUT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Darwin ] || { echo "mac-triage.sh runs on macOS only. For Windows or Linux, ask the agent to map the checks by category." >&2; exit 1; }
[ "$(id -u)" != 0 ] || { echo "Run this as yourself, not with sudo or as root: the checks must not run with elevated rights." >&2; exit 1; }
[ -n "$OUT" ] || OUT=$HOME/am-i-pwned-report-$(date -u +%Y%m%dT%H%M%SZ).txt
[ ! -e "$OUT" ] || { echo "$OUT already exists; not overwriting it. Pick another with -o." >&2; exit 1; }
: > "$OUT" || { echo "cannot write $OUT" >&2; exit 1; }

say() { printf '%s\n' "$*" >> "$OUT"; }
section() { say ''; say "=== $* ==="; }
note() { say "# $*"; }
cant() { say "COULD NOT CHECK: $*"; }

# run LABEL CMD...: the command's output under a label; a failure is reported, not hidden. Output is capped.
# With NO_MATCH_OK=1 (a pipeline that ends in grep, or asks about something that may not exist) an empty output with
# exit 1 means "nothing found", not "could not check". CAP=n raises the 200-line cap of one check.
run() {
  local label=$1 tmp rc cap=${CAP:-200}
  shift
  tmp=$(mktemp "${TMPDIR:-/tmp}/mac-triage.XXXXXX") || { cant "$label (no temporary file)"; return; }
  "$@" > "$tmp" 2>&1
  rc=$?
  say "\$ $label"
  if [ ! -s "$tmp" ]; then
    if [ $rc -eq 0 ] || { [ $rc -eq 1 ] && [ "${NO_MATCH_OK:-}" = 1 ]; }; then say "(no output)"
    else cant "$label (exit $rc, no output)"; fi
  else
    head -n "$cap" "$tmp" >> "$OUT"
    [ "$(wc -l < "$tmp")" -le "$cap" ] || say "# ... output cut at $cap lines"
    # Output with a failing exit: an error message (a grep that found something exits 0, one that found nothing prints nothing).
    if [ $rc -ne 0 ] && ! { [ $rc -eq 1 ] && [ "${NO_MATCH_OK:-}" = 1 ]; }; then cant "$label (exit $rc; the output above may be an error)"; fi
  fi
  rm -f "$tmp"
}

# pipeline LABEL SHELL_TEXT: the same for a pipeline, run through sh -c.
pipeline() { NO_MATCH_OK=1 run "$1" /bin/sh -c "$2"; }

# A process comm column holds a path that can contain spaces: print pid, ppid, user, etime and the whole path.
PS_PATHS='ps -axo pid,ppid,user,etime,comm | awk '"'"'NR > 1 { c = $5; for (i = 6; i <= NF; i++) c = c " " $i; print $1 "\t" $2 "\t" $3 "\t" $4 "\t" c }'"'"

# ---------------------------------------------------------------------------------------------------------------------
say "am-i-pwned mac-triage v$VERSION"
say "generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "user: $(id -un) (uid $(id -u))"
say "Read-only. No sudo. No secrets read. Every 'COULD NOT CHECK' line is a check that did not run, not a pass."

section "0 Access (what the checks below can and cannot see)"
if sqlite3 -readonly "$HOME/Library/Application Support/com.apple.TCC/TCC.db" 'select 1' >/dev/null 2>&1; then
  say "Full Disk Access: yes (Terminal can read the privacy database)"
else
  say "Full Disk Access: NO. The privacy-grant and quarantine checks will say COULD NOT CHECK. Grant Terminal Full Disk Access in System Settings, Privacy & Security, and run it again, or leave them for Security Ops."
fi

section "1 Posture"
run 'sw_vers' sw_vers
run 'fdesetup status' fdesetup status
run 'csrutil status' csrutil status
run 'spctl --status' spctl --status
run 'firewall' /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
run 'XProtect version' defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString
run 'screen lock' sysadminctl -screenLock status
pipeline 'screen saver idle time (seconds; 900 or less is the baseline)' "defaults -currentHost read com.apple.screensaver idleTime 2>&1 || echo 'not set: the system default applies'"
pipeline 'EDR or AV jobs and processes (names only)' "launchctl list | grep -i -E 'crowdstrike|falcon|sentinel|jamf|defender|wdav|carbonblack|sophos|malwarebytes|santa' ; $PS_PATHS | grep -i -E 'crowdstrike|falcon|sentinel|jamf|defender|wdav|carbonblack|sophos|malwarebytes|santa' | cut -f5"

section "2 Accounts"
pipeline 'users with UID 0 or 500+' "dscl . -list /Users UniqueID | awk '\$2 == 0 || \$2 >= 500'"
run 'admin group members' dscl . -read /Groups/admin GroupMembership
pipeline 'hidden state of each person account' 'for u in $(dscl . -list /Users UniqueID | awk '"'"'$2 >= 500 {print $1}'"'"'); do echo "$u hidden=$(dscl . -read /Users/$u IsHidden 2>/dev/null | awk '"'"'{print $2}'"'"')"; done'
run 'recent logins' last -30
pipeline 'remote-access services loaded' "launchctl list | grep -i -E 'sshd|screensharing|ard|smbd|remotemanagement'"
note "Remote Login state needs admin (systemsetup -getremotelogin): ask the person to run it themselves if it matters."

section "3 Persistence"
pipeline 'loaded jobs that are not Apple (label only)' "launchctl list | grep -v -E 'com\\.apple\\.'"
for dir in /Library/LaunchAgents /Library/LaunchDaemons "$HOME/Library/LaunchAgents"; do
  say ''
  say "\$ launch folder $dir (names and modification times)"
  if [ ! -d "$dir" ]; then say "(no such folder)"; continue; fi
  ls -la "$dir" >> "$OUT" 2>&1 || cant "list $dir"
done

# Each plist: label, program, the first two ProgramArguments entries (the program and, say, `-c`; later arguments can hold
# tokens, so they are not read), then what the program is signed by. plutil -p | grep Program would miss the arguments.
trace_binary() {
  local bin=$1
  if [ ! -e "$bin" ]; then say "    program: $bin  (NOT ON DISK)"; return; fi
  say "    program: $bin"
  codesign -dv --verbose=4 "$bin" 2>&1 | grep -E '^(Identifier|TeamIdentifier|Authority|Signature|Platform identifier|CodeDirectory.*flags)' | sed 's/^/      /' >> "$OUT"
  [ "${PIPESTATUS[0]}" -eq 0 ] || say "      (not signed, or codesign could not read it)"
}
say ''
say '$ each launch plist: what it runs, and who signed that'
for dir in /Library/LaunchAgents /Library/LaunchDaemons "$HOME/Library/LaunchAgents"; do
  [ -d "$dir" ] || continue
  for plist in "$dir"/*.plist; do
    [ -f "$plist" ] || continue
    label=$(plutil -extract Label raw -o - "$plist" 2>/dev/null || echo '-')
    prog=$(plutil -extract Program raw -o - "$plist" 2>/dev/null || true)
    n=$(plutil -extract ProgramArguments raw -o - "$plist" 2>/dev/null || echo 0)
    a0=$(plutil -extract ProgramArguments.0 raw -o - "$plist" 2>/dev/null || true)
    a1=$(plutil -extract ProgramArguments.1 raw -o - "$plist" 2>/dev/null || true)
    runatload=$(plutil -extract RunAtLoad raw -o - "$plist" 2>/dev/null || echo '-')
    say "  $plist  label=$label  RunAtLoad=$runatload  arguments=$n"
    [ -z "$a1" ] || say "    argument 1 (of $n; the rest are not read): $(printf '%s' "$a1" | cut -c1-120)"
    target=${prog:-$a0}
    if [ -n "$target" ]; then trace_binary "$target"; else say "    program: (none named)"; fi
  done
done

CAP=1000 pipeline 'login items and background items (sfltool dumpbtm; names, types, paths, developers)' "sfltool dumpbtm 2>&1 | grep -i -E 'name:|developer name:|team identifier:|type:|url:|executable path:|disposition:' | cut -c1-200"
note "sfltool dumpbtm lists every background item and its output differs between macOS versions; if it needs elevation here, ask the person to run it."
pipeline 'crontab (line count, and only the suspicious keywords with line numbers)' "crontab -l 2>/dev/null | wc -l | tr -d ' '; crontab -l 2>/dev/null | grep -n -o -E 'curl|wget|base64|eval|osascript|nc |/tmp/'"
pipeline 'periodic and emond rules (names)' 'ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly /etc/emond.d/rules 2>/dev/null'
pipeline 'login and logout hooks (a hook is a path)' "defaults read com.apple.loginwindow LoginHook 2>&1; defaults read com.apple.loginwindow LogoutHook 2>&1"
run 'sudoers.d (names)' ls -la /etc/sudoers.d
pipeline 'PAM files changed in the last 30 days' "find /etc/pam.d -type f -mtime -30 2>/dev/null"
run 'MDM enrollment' profiles status -type enrollment
run 'system extensions' systemextensionsctl list
pipeline 'loaded non-Apple kernel extensions' "kmutil showloaded --list-only --no-kernel-components 2>/dev/null | grep -v -E 'com\\.apple\\.'"
pipeline 'shell startup files: keyword and line number only, never the line' 'for f in "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.zlogin" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do [ -f "$f" ] && grep -n -o -E "curl|wget|base64|eval|osascript|nohup|python|perl|ruby|nc |/tmp/" "$f" | sed "s|^|$f:|"; done; true'
pipeline 'git hooks path (a path, not a secret)' 'git config --global --get core.hooksPath'

# Hidden or loose executables: only files that are programs or scripts (file(1)), not a stray executable bit.
say ''
say '$ hidden or loose executables in the home folder and in cache and temp folders'
{
  find "$HOME" -maxdepth 2 -name '.*' -type f -perm +111 ! -path '*/.git/*' ! -path '*/node_modules/*' 2>/dev/null
  find /Library/Caches "$HOME/Library/Caches" -maxdepth 3 -type f -perm +111 2>/dev/null | head -50
  find /tmp /var/tmp -maxdepth 2 -type f -perm +111 2>/dev/null
} | while IFS= read -r f; do
  kind=$(file -b "$f" 2>/dev/null | cut -c1-60)
  case $kind in (*Mach-O*|*script*|*executable*) say "  $f  [$kind]" ;; esac
done

section "4 Processes"
CAP=1000 pipeline 'non-system processes: pid, ppid, user, running time, path (no arguments)' "$PS_PATHS | awk -F'\\t' '\$5 !~ /^\\/(System|usr\\/(libexec|sbin|bin)|bin|sbin|Library\\/Apple)\\//'"
pipeline 'processes from temp, cache, Downloads, Trash or hidden folders' "$PS_PATHS | awk -F'\\t' '\$5 ~ /\\/tmp\\/|\\/var\\/folders\\/|\\/Downloads\\/|\\/\\.Trash\\/|\\/\\.[^\\/]+\\//'"
say ''
say '$ processes whose program is no longer on disk'
gone=$(ps -axo pid,ppid,user,etime,comm | awk 'NR > 1 { c = $5; for (i = 6; i <= NF; i++) c = c " " $i; print $1 "\t" c }' | while IFS=$'\t' read -r pid c; do
  case $c in (/*) [ -e "$c" ] || echo "  pid $pid: $c (NOT ON DISK)" ;; esac
done)
if [ -n "$gone" ]; then say "$gone"; else say "(none)"; fi
pipeline 'remote debugging ports (the flag only; command lines are never printed)' "ps -axo command | grep -o -E -- '--remote-debugging-port=[0-9]+'"

section "5 Network"
note "lsof as the user shows only the user's own processes."
pipeline 'listening TCP sockets' "lsof -nP -iTCP -sTCP:LISTEN"
pipeline 'established TCP connections' "lsof -nP -iTCP -sTCP:ESTABLISHED"
pipeline 'DNS resolvers and search domains' "scutil --dns | grep -E 'nameserver|search' | sort -u"
run 'proxy settings' scutil --proxy
pipeline '/etc/hosts entries' "grep -v -E '^#|^\$' /etc/hosts"
pipeline 'resolver overrides' 'ls -la /etc/resolver 2>/dev/null'

section "6 Privacy grants"
run 'granted permissions (needs Full Disk Access)' sqlite3 -readonly "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "select service, client, datetime(last_modified,'unixepoch') from access where auth_value=2 order by last_modified desc"

section "7 Browser (extension IDs and native-messaging host names only)"
for app in 'Google/Chrome' 'Microsoft Edge' 'BraveSoftware/Brave-Browser' 'Arc/User Data'; do
  base="$HOME/Library/Application Support/$app"
  [ -d "$base" ] || continue
  say ''
  say "\$ $app: extension IDs per profile"
  for d in "$base"/*/Extensions; do
    [ -d "$d" ] || continue
    say "  $(basename "$(dirname "$d")"): $(ls "$d" 2>/dev/null | tr '\n' ' ')"
  done
  [ ! -d "$base/NativeMessagingHosts" ] || say "  native-messaging hosts: $(ls "$base/NativeMessagingHosts" 2>/dev/null | tr '\n' ' ')"
done
[ ! -d "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts" ] || say "Firefox native-messaging hosts: $(ls "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts" 2>/dev/null | tr '\n' ' ')"
say "(An extension ID is compared with the Chrome Web Store by the reader; names inside manifests are often __MSG_name__.)"

section "8 Recent change"
pipeline 'persistence files modified in the last 14 days' "find /Library/LaunchAgents /Library/LaunchDaemons \"\$HOME/Library/LaunchAgents\" /etc/periodic /etc/emond.d -type f -mtime -14 2>/dev/null"
run 'recent download and quarantine events (app and time only, never a URL; needs Full Disk Access)' sqlite3 -readonly "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" "select LSQuarantineAgentName, datetime(LSQuarantineTimeStamp+978307200,'unixepoch') from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 40"

section "9 For the person (a device cannot show these; the reader must ask)"
say "- Did you paste a command from a web page into Terminal or Script Editor (a 'fix', 'verify you are human' or 'install' instruction)?"
say "- Did a password prompt appear that you did not start, and did you type your password into it?"
say "A yes to either: treat the machine as likely compromised, and contact Security Ops."
say ''
say "end of report"

chmod 600 "$OUT" 2>/dev/null
printf 'Wrote %s (%s lines). It holds paths, user and program names; read it before you share it. It holds no keys, passwords, history or command lines.\n' "$OUT" "$(wc -l < "$OUT" | tr -d ' ')"
