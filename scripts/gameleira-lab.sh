#!/bin/bash
# gameleira-lab.sh: writes an eslogger capture for learning Gameleira, with an answer key beside it.
#
#   scripts/gameleira-lab.sh synthetic [-o FILE | --stdout | --answers]
#   scripts/gameleira-lab.sh live      [-o FILE | --answers]
#   scripts/gameleira-lab.sh --help
#
# synthetic  builds the capture by hand: invented user `learner` (uid 502), invented pids, tokens and team IDs, fixed
#            times. No noise, the same bytes on every run, safe on any machine. Pure bash (3.2 or later).
# live       runs harmless versions of the same attack steps on this Mac while `sudo eslogger` records, so the capture
#            has the real background noise of a Mac around them. See --help for what it does to the machine.
#
# Either way the answer key (FILE with .jsonl replaced by .answers.tsv) lists, for each step, the rule it should set
# off, the severity, how the row appears in the queue, a marker to find it by and a note on what the step imitates.
# Default FILE: scratch/gameleira-lab-<mode>.jsonl in the repo (scratch/ is gitignored).

export LC_ALL=C

usage() {
  cat <<'EOF'
Usage:
  gameleira-lab.sh synthetic [-o FILE | --stdout | --answers]
  gameleira-lab.sh live      [-o FILE | --answers]

synthetic  Write a hand-built capture that sets off every Gameleira rule, with no noise.
           --stdout prints the capture, --answers prints the answer key; -o FILE writes both
           (FILE and FILE minus .jsonl plus .answers.tsv). Default: scratch/gameleira-lab-synthetic.jsonl.

live       Run harmless versions of the attack steps on this Mac while `sudo eslogger` records.
           macOS only; run it as yourself, not with sudo (it asks for your password for eslogger only).
           It shows a dialog (type anything, or wait), macOS will likely show a "Background Items Added"
           notification for the lab's launch agent, and everything it creates is removed at the end, also on
           Ctrl-C. The capture holds every process's environment and your user name: review it before sharing.
           --answers prints the answer key without running anything. Default: scratch/gameleira-lab-live.jsonl.

Load the .jsonl into Gameleira and check what you find against the .answers.tsv.
EOF
}

die() {
  printf 'gameleira-lab: %s\n' "$*" >&2
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

# ev_exec SECONDS handle path kind signing_id team_id cwd fds(tty|pipe) ARGS...
#   The event carries the process before the exec and, as its target, the process after it.
ev_exec() {
  local sec=$1 h=$2 before args cwd script fds
  proc_obj "$h"; before=$PROC_OUT
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

# answer step rule severity queue marker note: one row of the answer key.
answer() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >&4
}
answer_header() {
  printf 'step\trule\tseverity\tqueue\tmarker\tnote\n' >&4
}

# ---- the synthetic story ----------------------------------------------------------------------------------------
synthetic_story() {
  answer_header
  local LAUNCHD TERMINAL LOGIN ZSH c
  new_proc LAUNCHD 1 1021 /sbin/launchd platform com.apple.launchd '' '' -3600 0 0
  new_proc TERMINAL 6100 8100 /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal platform com.apple.Terminal '' "$LAUNCHD" -3000
  new_proc LOGIN 6120 8120 /usr/bin/login platform com.apple.login '' "$TERMINAL" -2990
  new_proc ZSH 6130 8130 /bin/zsh platform com.apple.zsh '' "$LOGIN" -2980
  P_RESP[ZSH]=$TERMINAL

  ev_fork 1.0 "$ZSH" 7001 9001; c=$LAST
  ev_exec 1.1 "$c" /bin/ls platform com.apple.ls '' /Users/learner tty ls -la
  ev_exit 1.2 "$c"
}

# ---- command line -----------------------------------------------------------------------------------------------
REPO=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)

[ -n "${GAMELEIRA_LAB_SOURCE_ONLY:-}" ] && return 0

main() {
  local mode=${1:-} out='' to=files
  case $mode in
    -h|--help|help) usage; exit 0 ;;
    synthetic|live) shift ;;
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
  [ -n "$out" ] || out=$REPO/scratch/gameleira-lab-$mode.jsonl
  local answers=${out%.jsonl}.answers.tsv
  [ "$answers" != "$out" ] || answers=$out.answers.tsv

  if [ "$mode" = live ]; then
    die "live mode is not written yet"
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
