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

# ---- judging a setting: functions of what was read, so a test can feed them values (MAC_TRIAGE_SOURCE_ONLY=1 sources them) --
# Each prints ok (the usual value), CHANGED (differs from the default in a way malware and adware use), note or unknown.
is_off() { case $1 in 0|false|FALSE|False|NO|no) return 0 ;; *) return 1 ;; esac; }
is_on() { case $1 in 1|true|TRUE|True|YES|yes) return 0 ;; *) return 1 ;; esac; }
judge_firewall() { case $1 in *disabled*|*"State = 0"*) echo CHANGED ;; *enabled*|*"State = 1"*|*"State = 2"*) echo ok ;; *) echo unknown ;; esac; }
judge_spctl() { case $1 in *"assessments enabled"*) echo ok ;; *"assessments disabled"*) echo CHANGED ;; *) echo unknown ;; esac; }
judge_sip() { case $1 in *"Custom Configuration"*|*disabled*) echo CHANGED ;; *enabled*) echo ok ;; *) echo unknown ;; esac; }
judge_bootargs() { case $1 in '') echo ok ;; *amfi_get_out_of_my_way*|*cs_enforcement_disable*|*amfi=*|*rootless=0*) echo CHANGED ;; *) echo note ;; esac; }
judge_age() { if [ "$1" -gt 60 ]; then echo CHANGED; else echo ok; fi; }
judge_sshd() {
  if printf '%s\n' "$1" | grep -q -i -E '^[[:space:]]*(PermitRootLogin[[:space:]]+yes|PermitEmptyPasswords[[:space:]]+yes|AuthorizedKeysCommand[[:space:]]|ForceCommand[[:space:]]|PermitTunnel[[:space:]]+(yes|point|ethernet)|GatewayPorts[[:space:]]+(yes|clientspecified))'; then echo CHANGED
  elif [ -n "$1" ]; then echo note; else echo ok; fi
}
# An authorization right as JSON (plutil -convert json). The usual admin rights are class user, group admin, password asked.
judge_authdb() {
  case $1 in
    *'"class":"allow"'*|*'"rule":"allow"'*|*'"rule":["allow"'*) echo CHANGED ;;
    *'"class":"user"'*)
      case $1 in *'"authenticate-user":false'*) echo CHANGED ;; *'"group":"admin"'*) echo ok ;; *) echo CHANGED ;; esac ;;
    '') echo unknown ;;
    *) echo ok ;;
  esac
}
# tmo SECONDS CMD...: stop a command that does not finish (a system tool waiting on something), so one check cannot hold the run.
tmo() { local t=$1; shift; perl -e 'alarm shift; exec @ARGV' "$t" "$@"; }
[ -z "${MAC_TRIAGE_SOURCE_ONLY:-}" ] || return 0

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
# One row per program (running now, or run by a launch item): source R or L, signature kind, team, signing ID, path.
SIGFILE=$(mktemp "${TMPDIR:-/tmp}/mac-triage-sig.XXXXXX") || { echo "cannot make a temporary file" >&2; exit 1; }
trap 'rm -f "$SIGFILE"' EXIT

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
  tmo "${RUN_TIMEOUT:-60}" "$@" > "$tmp" 2>&1
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

# Indicators that vendors published for named malware families, generated from src/rules/indicators.json.
# BEGIN GENERATED INDICATORS (scripts/gen-indicators.mjs, from src/rules/indicators.json: edit that file, not this block)
# kind|family|severity|value (kind: team = code-signing team ID, signing = signing identifier)
KNOWN_IDS='team|ChillyHell|high|R868N47FV5
team|ChillyHell|high|F645668Q3H
signing|KANDYKORN|high|HLOADER-5555494485b460f1e2343dffaef9b94d01136320
signing|BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|high|root_startup_loader_arm64
team|Evasive Panda macOS downloader (Monlam watering hole, 2024)|high|2289F6V4BN'
# family|severity|path (a leading ~/ is the home folder, * is a glob, a trailing / is a folder)
KNOWN_PATHS='ChillyHell|high|/Library/LaunchAgents/com.apple.qtop.plist
ChillyHell|high|/Library/LaunchDaemons/com.apple.qtop.plist
ChillyHell|high|~/Library/LaunchAgents/com.apple.qtop.plist
ChillyHell|high|~/Library/com.apple.qtop/
ChillyHell|high|/usr/local/bin/qtop
ChillyHell|med|/tmp/kworker
FlexibleFerret|high|/Library/LaunchAgents/com.driver9990as7tpatch.plist
FlexibleFerret|high|/Library/LaunchDaemons/com.driver9990as7tpatch.plist
FlexibleFerret|high|~/Library/LaunchAgents/com.driver9990as7tpatch.plist
FlexibleFerret|med|/var/tmp/macpatch.sh
FlexibleFerret|med|/var/tmp/CDrivers.zip
FlexibleFerret|med|/var/tmp/CDrivers/
FlexibleFerret|med|~/Library/LaunchAgents/us.zoom.ZoomDaemon.plist
FlexibleFerret|med|/var/tmp/InstallerAlert.app/
FlexibleFerret|med|/var/tmp/versus.app/
Contagious Interview toolchain (BeaverTail, InvisibleFerret, OtterCookie)|high|~/.n2/
Contagious Interview toolchain (BeaverTail, InvisibleFerret, OtterCookie)|high|~/.npl
Contagious Interview toolchain (BeaverTail, InvisibleFerret, OtterCookie)|high|/Volumes/MiroTalk/MiroTalk.app/Contents/MacOS/Jami
Contagious Interview toolchain (BeaverTail, InvisibleFerret, OtterCookie)|med|~/.vscode/vscode-bootstrap.sh
Contagious Interview toolchain (BeaverTail, InvisibleFerret, OtterCookie)|med|~/Library/LaunchAgents/com.onedrive.launcher.plist
KANDYKORN|high|/Users/Shared/FinderTools
KANDYKORN|high|/Users/Shared/.sld
KANDYKORN|high|/Library/Caches/com.apple.safari.ck
KANDYKORN|high|/Applications/Discord.app/Contents/MacOS/.lock
RustBucket|high|/Users/Shared/.pd
RustBucket|high|~/Library/Metadata/System Update
RustBucket|high|/Library/LaunchAgents/com.apple.systemupdate.plist
RustBucket|high|/Library/LaunchDaemons/com.apple.systemupdate.plist
RustBucket|high|~/Library/LaunchAgents/com.apple.systemupdate.plist
HiddenRisk|high|/tmp/.zsh_init_success
HiddenRisk|med|/tmp/growth
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|high|/Library/LaunchAgents/com.telegram2.update.agent.plist
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|high|/Library/LaunchDaemons/com.telegram2.update.agent.plist
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|high|~/Library/LaunchAgents/com.telegram2.update.agent.plist
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|high|/Library/Application Support/Frameworks/Telegram 2
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|high|/Library/CloudKitDaemon/
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|med|/tmp/icloud_helper
BlueNoroff fake-Zoom chain (Huntress; the NimDoor lure)|med|/Users/Shared/.pwd
Evasive Panda macOS downloader (Monlam watering hole, 2024)|high|~/Library/Containers/CalendarFocusEXT/
Evasive Panda macOS downloader (Monlam watering hole, 2024)|high|/Library/LaunchAgents/com.Terminal.us.plist
Evasive Panda macOS downloader (Monlam watering hole, 2024)|high|/Library/LaunchDaemons/com.Terminal.us.plist
Evasive Panda macOS downloader (Monlam watering hole, 2024)|high|~/Library/LaunchAgents/com.Terminal.us.plist
Evasive Panda macOS downloader (Monlam watering hole, 2024)|high|~/Library/SafariBrowser/Safari.app/Contents/MacOS/SafariBrower
MACMA|med|/Library/LaunchAgents/com.UserAgent.va.plist
MACMA|med|/Library/LaunchDaemons/com.UserAgent.va.plist
MACMA|med|~/Library/LaunchAgents/com.UserAgent.va.plist
MACMA|med|~/Library/Preferences/UserAgent/lib/UserAgent
GIMMICK|med|/Library/LaunchAgents/com.*.va.plist
GIMMICK|med|/Library/LaunchDaemons/com.*.va.plist
GIMMICK|med|~/Library/LaunchAgents/com.*.va.plist
GIMMICK|med|/var/root/Library/Preferences/CorelDRAW/CorelDRAW
DazzleSpy|high|~/.local/softwareupdate
DazzleSpy|high|~/.local/security/
DazzleSpy|high|~/.local/security.zip
DazzleSpy|high|/var/folders/*/*/T/airportpaird
DazzleSpy|high|/Library/LaunchAgents/com.apple.softwareupdate.plist
DazzleSpy|high|/Library/LaunchDaemons/com.apple.softwareupdate.plist
DazzleSpy|high|~/Library/LaunchAgents/com.apple.softwareupdate.plist'
# END GENERATED INDICATORS

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
say ''
say '$ security settings that malware and adware switch off. Current state only: it does not say who changed a setting or when, and a managed (MDM) Mac may differ on purpose. "not set" means the default applies.'
setting() { say "  $(printf '%-8s' "$1") $2: $3"; }
dread() { defaults read "$1" "$2" 2>/dev/null || echo -; }
squash() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-110; }
# Software updates, including the data updates that keep XProtect and the malware remover current.
SU=/Library/Preferences/com.apple.SoftwareUpdate
for pair in 'AutomaticCheckEnabled|Check for updates automatically|sec' 'ConfigDataInstall|Install system data files (XProtect and MRT updates)|sec' 'CriticalUpdateInstall|Install security responses and critical updates|sec' 'AutomaticDownload|Download updates automatically|pref' 'AutomaticallyInstallMacOSUpdates|Install macOS updates automatically|pref'; do
  IFS='|' read -r key name kind <<EOF_PAIR
$pair
EOF_PAIR
  v=$(dread "$SU" "$key")
  if [ "$v" = - ]; then setting default "$name" "not set ($key)"
  elif is_off "$v"; then if [ "$kind" = sec ]; then setting CHANGED "$name" "off ($key = $v)"; else setting note "$name" "off ($key = $v): a choice many people make"; fi
  else setting ok "$name" "on ($key = $v)"; fi
done
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1); setting "$(judge_firewall "$fw")" 'Application firewall' "$(squash "$fw")"
setting info 'Firewall stealth mode (off is the default)' "$(squash "$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1)")"
sp=$(spctl --status 2>&1); setting "$(judge_spctl "$sp")" 'Gatekeeper' "$(squash "$sp")"
gk=$(dread /Library/Preferences/com.apple.security GKAutoRearm)
if [ "$gk" = - ]; then setting default 'Gatekeeper turns itself back on (GKAutoRearm)' 'not set'
elif is_off "$gk"; then setting CHANGED 'Gatekeeper turns itself back on (GKAutoRearm)' "off ($gk): a Gatekeeper that was switched off stays off"
else setting ok 'Gatekeeper turns itself back on (GKAutoRearm)' "on ($gk)"; fi
for dom in com.apple.LaunchServices /Library/Preferences/com.apple.LaunchServices; do
  q=$(dread "$dom" LSQuarantine)
  if [ "$q" = - ]; then setting default "Quarantine flag on downloads, $dom (LSQuarantine)" 'not set'
  elif is_off "$q"; then setting CHANGED "Quarantine flag on downloads, $dom (LSQuarantine)" "off ($q): downloads are not flagged, on versions that honour it"
  else setting ok "Quarantine flag on downloads, $dom (LSQuarantine)" "on ($q)"; fi
done
sip=$(csrutil status 2>&1); setting "$(judge_sip "$sip")" 'System Integrity Protection' "$(squash "$sip")"
ar=$(csrutil authenticated-root status 2>&1); setting "$(judge_sip "$ar")" 'Sealed system volume' "$(squash "$ar")"
ba=$(nvram boot-args 2>/dev/null | cut -f2-)
if [ -z "$ba" ]; then setting default 'Boot arguments' 'not set'; else setting "$(judge_bootargs "$ba")" 'Boot arguments (a flag that weakens code-signing enforcement is CHANGED)' "$ba"; fi
lv=$(dread /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation)
if [ "$lv" = - ]; then setting default 'Library validation (DisableLibraryValidation)' 'not set'
elif is_on "$lv"; then setting CHANGED 'Library validation (DisableLibraryValidation)' "disabled ($lv): any library can be loaded into any app"
else setting ok 'Library validation (DisableLibraryValidation)' "on ($lv)"; fi
for dom in system "gui/$(id -u)"; do
  dis=$(tmo 20 launchctl print-disabled "$dom" 2>/dev/null | grep -E '=> (disabled|true)' | grep -i -E 'xprotect|mrt|syspolicy|softwareupdate|amfi|socketfilter|alf|tccd|trustd' | sed 's/^[[:space:]]*//')
  if [ -z "$dis" ]; then setting ok "Apple security services disabled in launchd ($dom)" 'none'
  else setting CHANGED "Apple security services disabled in launchd ($dom)" "$(squash "$dis")"; fi
done
al=$(dread /Library/Preferences/com.apple.loginwindow autoLoginUser)
if [ "$al" = - ]; then setting ok 'Automatic login' 'off'; else setting CHANGED 'Automatic login' "on for $al: anyone at the keyboard gets in"; fi
gu=$(dread /Library/Preferences/com.apple.loginwindow GuestEnabled)
if [ "$gu" = - ]; then setting default 'Guest account at the login window' 'not set'
elif is_on "$gu"; then setting CHANGED 'Guest account at the login window' "on ($gu)"; else setting ok 'Guest account at the login window' "off ($gu)"; fi
ssh=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | grep -v -E '^[[:space:]]*(#|$)' | grep -i -E '^[[:space:]]*(PermitRootLogin|PermitEmptyPasswords|PasswordAuthentication|AuthorizedKeysCommand|ForceCommand|PermitTunnel|GatewayPorts)[[:space:]]')
if [ -z "$ssh" ]; then setting ok 'SSH server settings that matter (sshd_config)' 'none set (the defaults apply)'
else setting "$(judge_sshd "$ssh")" 'SSH server settings that matter (sshd_config)' "$(squash "$ssh")"; fi
for right in system.privilege.admin system.preferences system.preferences.security system.install.software; do
  rec=$(tmo 20 security authorizationdb read "$right" 2>/dev/null | plutil -convert json -o - - 2>/dev/null)
  setting "$(judge_authdb "$rec")" "Authorization right $right (who may do it, and whether a password is asked)" "$(squash "$(printf '%s' "$rec" | grep -o -E '"(class|group|authenticate-user|rule)":("[^"]*"|true|false|\[[^]]*\])' | tr '\n' ' ')")"
done
if [ -e "/Library/Security/Trust Settings/Admin.plist" ]; then setting note 'Custom root certificates trusted by every user' "present, modified $(stat -f '%Sm' -t '%Y-%m-%d' '/Library/Security/Trust Settings/Admin.plist' 2>/dev/null): ask the person what it is, and to list the trusted roots themselves (command in references/security-settings.md)"
else setting ok 'Custom root certificates trusted by every user' 'none (no Admin.plist)'; fi
yara=/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara
if [ -e "$yara" ]; then
  age=$(( ( $(date +%s) - $(stat -f %m "$yara") ) / 86400 ))
  setting "$(judge_age "$age")" 'XProtect signatures last updated' "$age days ago (more than 60 is CHANGED: an unverified threshold; updates normally arrive within weeks)"
else setting unknown 'XProtect signatures last updated' 'XProtect.yara not found'; fi
setting info 'XProtect Remediator version' "$(squash "$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info CFBundleShortVersionString 2>&1)")"
pipeline 'XProtect and MRT updates installed, latest six (name, version, install date)' "perl -e 'alarm 60; exec @ARGV' system_profiler SPInstallHistoryDataType 2>/dev/null | awk '/^    [A-Za-z0-9_.-]+:\$/ { name = \$1; sub(/:\$/, \"\", name) } /^      Version:/ { ver = \$2 } /^      Install Date:/ { if (name ~ /XProtect|MRT/) { d = \$0; sub(/^ *Install Date: */, \"\", d); rows[++n] = name \" \" ver \", \" d } } END { for (i = (n > 6 ? n - 5 : 1); i <= n; i++) print rows[i] }'"
note 'Not readable without admin: systemsetup -getremotelogin (Remote Login). Ask the person to run it if it matters.'

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


# Who signed each program running now (or run by a launch item), outside the system folders. The signature is read with
# codesign -dv, not verified, and a revoked certificate cannot be seen offline. On Apple Silicon nothing runs fully
# unsigned (the linker signs ad hoc), so an ad-hoc signature is the signal there, and where the program sits says what it means.
launch_programs() {
  local dir plist prog a0
  for dir in /Library/LaunchAgents /Library/LaunchDaemons "$HOME/Library/LaunchAgents"; do
    [ -d "$dir" ] || continue
    for plist in "$dir"/*.plist; do
      [ -f "$plist" ] || continue
      prog=$(plutil -extract Program raw -o - "$plist" 2>/dev/null || true)
      a0=$(plutil -extract ProgramArguments.0 raw -o - "$plist" 2>/dev/null || true)
      printf '%s\n' "${prog:-$a0}"
    done
  done
}
# kind: platform (Apple), team (a developer team), adhoc (no developer identity), noteam (signed, no team ID), unsigned, unreadable.
sig_row() {
  local out team sid kind
  out=$(codesign -dv --verbose=4 "$1" 2>&1)
  team=$(printf '%s\n' "$out" | sed -n 's/^TeamIdentifier=//p' | head -n 1)
  sid=$(printf '%s\n' "$out" | sed -n 's/^Identifier=//p' | head -n 1)
  if printf '%s\n' "$out" | grep -q 'not signed at all'; then kind=unsigned
  elif printf '%s\n' "$out" | grep -q '^Platform identifier='; then kind=platform
  elif printf '%s\n' "$out" | grep -q '^Signature=adhoc'; then kind=adhoc
  elif [ -n "$team" ] && [ "$team" != 'not set' ]; then kind=team
  elif [ -n "$sid" ]; then kind=noteam
  else kind=unreadable; fi
  printf '%s\t%s\t%s\t%s\n' "$kind" "${team:--}" "${sid:--}" "$1"
}
NOT_SYSTEM='^/(System|usr/(libexec|sbin|bin)|bin|sbin|Library/Apple)/'
running=$(ps -axo pid,ppid,user,etime,comm | awk 'NR > 1 { c = $5; for (i = 6; i <= NF; i++) c = c " " $i; print c }' | grep '^/' | grep -v -E "$NOT_SYSTEM" | sort -u | head -n 600)
launched=$(launch_programs | grep '^/' | grep -v -E "$NOT_SYSTEM" | sort -u | head -n 300)
all=$(printf '%s\n%s\n' "$running" "$launched" | grep . | sort -u)
while IFS= read -r p; do
  [ -e "$p" ] || continue
  src=L
  printf '%s\n' "$running" | grep -qxF -- "$p" && src=R
  printf '%s\t%s\n' "$src" "$(sig_row "$p")" >> "$SIGFILE"
done <<EOF_ALL
$all
EOF_ALL
say ''
say '$ running programs outside the system folders, by how they are signed (read, not verified)'
awk -F'\t' '
function tooling(seg,   l) { l = tolower(seg); return (l in T) || l ~ /^go-build/ }
# Where a program sits: the same places as Ficus (src/rules/locations.ts). Strong places are LOOK; developer tooling is context.
function place(p,   rest, n, parts, i, seg, inT) {
  if (p ~ /\/AppTranslocation\//) return "App Translocation";
  if (p ~ /^(\/private)?\/(tmp|var\/tmp|var\/folders)\//) return "temp folder";
  if (p ~ /^\/Users\/Shared\//) return "/Users/Shared";
  if (p ~ /^\/Volumes\//) return "/Volumes";
  if (p ~ /^\/Users\/[^\/]+\/Downloads\//) return "Downloads";
  if (p ~ /^\/Users\/[^\/]+\//) {
    rest = p; sub(/^\/Users\/[^\/]+\//, "", rest);
    n = split(rest, parts, "/");
    inT = 0;
    for (i = 1; i < n; i++) {
      seg = parts[i];
      if (substr(seg, 1, 1) == ".") { if (i == 1) return "home dot-folder"; return (inT || tooling(seg)) ? "tooling folder" : "hidden folder" }
      if (tooling(seg)) inT = 1;
    }
    return "home folder";
  }
  if (p ~ /^\/(opt\/homebrew|usr\/local|nix)\//) return "package-manager folder";
  return "installed";
}
function strong(w) { return w == "temp folder" || w == "/Users/Shared" || w == "App Translocation" || w == "/Volumes" || w == "Downloads" || w == "hidden folder" }
function weak(w) { return w == "home dot-folder" || w == "tooling folder" || w == "package-manager folder" }
BEGIN { split(".git .venv venv .tox .direnv .husky node_modules .pnpm-store .build .terraform .next .cargo .gradle .m2 .cache .npm .yarn target deriveddata", a, " "); for (k in a) T[a[k]] = 1 }
$1 == "R" {
  n[$2]++; total++;
  w = place($5); lookalike = ($4 ~ /^com\.apple\./ && $2 != "platform" && $2 != "team");
  if ($2 == "adhoc" || $2 == "unsigned" || $2 == "noteam" || lookalike || ($2 == "team" && $4 ~ /^com\.apple\./)) {
    kind = ($2 == "adhoc" ? "ad-hoc signed" : $2 == "unsigned" ? "UNSIGNED" : $2 == "noteam" ? "signed with no team ID" : "signed by team " $3);
    if (lookalike) label = "LOOK   "; else if ($2 == "team") label = "CHECK  "; else if (strong(w)) label = "LOOK   "; else if (weak(w)) label = "context"; else label = "note   ";
    line = "  " label " " kind ", " w ": " $5 "  (signing ID " $4 ")" (lookalike ? "; CLAIMS AN APPLE IDENTIFIER without being Apple platform code" : ($2 == "team" ? "; a com.apple.* ID under a developer team: Apple signs a few apps this way, compare the team" : ""));
    list[++m] = line;
  }
}
END {
  printf "  Apple platform %d, developer team %d, ad-hoc %d, signed with no team ID %d, unsigned %d, unreadable %d (of %d)\n", n["platform"], n["team"], n["adhoc"], n["noteam"], n["unsigned"], n["unreadable"], total;
  for (i = 1; i <= m && i <= 100; i++) print list[i];
  if (m > 100) printf "  # ... %d more\n", m - 100;
  if (m == 0) print "  (every running program outside the system folders is Apple platform code or signed by a developer team)";
}' "$SIGFILE" >> "$OUT"
say 'LOOK = ad-hoc or unsigned in a place a normal install does not run from, or claiming an Apple identifier. context = developer tooling (Homebrew, caches, virtualenvs). note = elsewhere.'

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

section "9 Known indicators (published for named malware families; finding none proves nothing)"
say "Looks for the file paths, launch plists and code-signing teams that vendors published for named macOS families (references/known-indicators.md lists them with sources). Command-line words are not looked for here: command lines are off limits. A family renames its files between samples and this list ages, so a miss is not a clean bill of health."
known=0
# Files and folders (this user's home only; a glob's matches are printed with size and time, never read).
while IFS='|' read -r fam sev pat; do
  [ -n "$pat" ] || continue
  case $pat in '~/'*) pat=$HOME/${pat#\~/} ;; esac
  pat=${pat%/}
  hits=$(compgen -G "$pat" 2>/dev/null) || continue
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    known=$((known + 1))
    say "MATCH [$sev] $fam: $hit ($(stat -f '%z bytes, modified %Sm' -t '%Y-%m-%d %H:%M' "$hit" 2>/dev/null))"
  done <<EOF_HITS
$hits
EOF_HITS
done <<EOF_PATHS
$KNOWN_PATHS
EOF_PATHS
# Signing teams and identifiers of the programs launch items run and of the processes running now: the table section 4 built.
checked=0
while IFS=$'\t' read -r src kind team sid prog; do
  [ -n "$prog" ] || continue
  checked=$((checked + 1))
  while IFS='|' read -r idkind fam sev val; do
    [ -n "$val" ] || continue
    if { [ "$idkind" = team ] && [ "$team" = "$val" ]; } || { [ "$idkind" = signing ] && [ "$sid" = "$val" ]; }; then
      known=$((known + 1))
      say "MATCH [$sev] $fam: $prog is signed with the published $idkind $val"
    fi
  done <<EOF_IDS
$KNOWN_IDS
EOF_IDS
done < "$SIGFILE"
say "checked the signatures of $checked programs outside the system folders"
[ "$known" -gt 0 ] || say "(no published indicator found)"

section "10 For the person (a device cannot show these; the reader must ask)"
say "- Did you paste a command from a web page into Terminal or Script Editor (a 'fix', 'verify you are human' or 'install' instruction)?"
say "- Did a password prompt appear that you did not start, and did you type your password into it?"
say "A yes to either: treat the machine as likely compromised, and contact Security Ops."
say ''
say "end of report"

chmod 600 "$OUT" 2>/dev/null
printf 'Wrote %s (%s lines). It holds paths, user and program names; read it before you share it. It holds no keys, passwords, history or command lines.\n' "$OUT" "$(wc -l < "$OUT" | tr -d ' ')"
