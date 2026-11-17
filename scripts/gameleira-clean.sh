#!/bin/bash
# gameleira-clean.sh: pseudonymizes an eslogger capture before it leaves the Mac it was recorded on.
#
#   scripts/gameleira-clean.sh clean  -i RAW [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE]
#   scripts/gameleira-clean.sh record        [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE] [-t SECONDS]
#   scripts/gameleira-clean.sh --help
#
# Names, hosts, accounts and credentials become placeholders; what the rules need to see stays. The real values go in a
# key file on this Mac, so the cleaning can be undone here and nowhere else. record runs `sudo eslogger` and cleans its
# stream as it comes: the raw capture only ever exists in a pipe.
#
# Test hooks (environment): GAMELEIRA_CLEAN_NO_LOCAL_SEEDS=1 leaves this Mac's names out; GAMELEIRA_CLEAN_KEY_DIR is the
# default key folder; GAMELEIRA_CLEAN_FAKE_UID stands in for `id -u`, GAMELEIRA_CLEAN_FAKE_OS for `uname -s`;
# GAMELEIRA_CLEAN_RECORDER is a bash command record runs, as you and without sudo, instead of eslogger;
# GAMELEIRA_CLEAN_SOURCE_ONLY=1 defines the functions and runs nothing.
#
# Needs only what macOS has: bash 3.2, /usr/bin/jq (macOS 15 and later; GAMELEIRA_CLEAN_JQ names another), awk.
# The program that does the cleaning is gameleira-clean.jq, next to this file.

export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CLEAN_PROGRAM=$HERE/gameleira-clean.jq
JQ=${GAMELEIRA_CLEAN_JQ:-/usr/bin/jq}
KINDS="user realname name volume host email seed data"
KEY_HEADER=$'kind\tplaceholder\treal'
# The recorder, with the event list from the README's Capturing section. It runs as root under STOP_WRAPPER, through
# SUDO_CMD (empty: as you, for the tests).
RECORDER=(eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove)
SUDO_CMD=sudo
ES_PID=
CLEANER_PID=
RAW_DIR=

usage() {
  cat <<'EOF'
Usage:
  gameleira-clean.sh clean  -i RAW [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE]
  gameleira-clean.sh record        [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE] [-t SECONDS]

clean   Read the capture RAW (JSONL, a pretty-printed export or a JSON array) and write the cleaned capture as JSONL.
        RAW is never changed or deleted: remove it yourself once you are happy with the result.
        With -i - the capture (JSONL) is read from standard input, in one pass: a program's name is then only known
        as one from the moment it runs, not from its first appearance as it is for a file.
record  Record with eslogger and write the cleaned capture as it goes; the raw stream is never written to disk.
        Run it as yourself: it asks for your password for sudo eslogger only. Ctrl-C (or -t) stops it, and the
        events eslogger has already sent are cleaned and written before it ends.

This Mac's account names (uid 500 and up) and full names, computer, local host and host names, serial number and
platform UUID are cleaned wherever they appear, in both modes.

  -o FILE       The cleaned capture; - for standard output. Default: capture.cleaned.jsonl here. Made, with its folder, if missing.
  -k KEYFILE    Keep real values here. An existing key is loaded first, so captures of one Mac share placeholders.
                Default: ~/Library/Application Support/Gameleira/keys/<name of FILE>.key.tsv, which must not exist yet.
                The key holds real names: keep it on this Mac. It is made readable by you only.
  -D DOMAIN     Your company's own domain, cleaned as an internal host. Repeat for more.
  -S SEEDFILE   More values to clean, one per line: kind, a tab, the value (kinds: user realname name volume host email seed data).
  -t SECONDS    record only: stop after this long (Ctrl-C also stops it).

At the end a summary is printed on standard error.
EOF
}

die() {
  printf 'gameleira-clean: %s\n' "$*" >&2
  exit 1
}

usage_error() {
  printf 'gameleira-clean: %s\n\n' "$*" >&2
  usage >&2
  exit 2
}

# ---- temporary files ----------------------------------------------------------------------------------------
TMP_FILES=()

cleanup() {
  [ -z "$ES_PID" ] || stop_capture   # the script is ending with eslogger still recording (an error, a signal)
  rm -f "${TMP_FILES[@]}"
  [ -z "$RAW_DIR" ] || rm -rf "$RAW_DIR"
}

# new_tmp: a private (0600) temporary file; its name is in TMP_OUT, and it is removed when the script ends.
new_tmp() {
  TMP_OUT=$(umask 077; mktemp "${TMPDIR:-/tmp}/gameleira-clean.XXXXXX") || die "cannot make a temporary file"
  TMP_FILES[${#TMP_FILES[@]}]=$TMP_OUT
}

# ---- the config ---------------------------------------------------------------------------------------------
# What the jq program is told besides the capture. Seeds, domains and the loaded key can name real people, so they go in
# a private file for jq's --slurpfile and never in its arguments: eslogger records every exec's arguments.
#   DOMAINS      the -D values (an array)
#   SEED_FILE    the -S file, or empty
#   LOADED_KEY   the key file to load, or empty
#   KEEP_FILE    the prescan's list of program names (a JSON array), or empty
CONFIG_JQ='
def kinds: ($kinds | split(" "));
# The lines that are not blank, each with its index in the file ({key, value}), so an error names the real line.
def lines($text): $text | split("\n") | to_entries | map(.value |= rtrimstr("\r") | select(.value | length > 0));
def trim: sub("^\\s+"; "") | sub("\\s+$"; "");
# A seed value: what follows the first tab, without surrounding whitespace (a stray space would never match).
def seed_value: split("\t") | .[1:] | join("\t") | trim;
{
  seeds: [lines($seeds)[]
    | .key as $i
    | (.value | split("\t")) as $f
    | (.value | seed_value) as $v
    | if ($f | length) < 2 or (kinds | index($f[0])) == null or $v == ""
      then error("line \($i + 1) of the seed file is not a known kind, a tab and a value")
      # The same value composed and decomposed (NFC, NFD): dscl gives one, files and apps may write the other.
      else {kind: $f[0], value: $v}
        + ([$nfd, $nfc | split("\n") | .[$i] // "" | rtrimstr("\r") | seed_value | select(. != "" and . != $v)] | unique
           | if length > 0 then {forms: .} else {} end) end],
  domains: [inputs | select(length > 0) | ascii_downcase | ltrimstr(".")],
  key: (lines($key) as $rows
    | if ($rows | length) == 0 then []
      elif $rows[0].value != $header then error("the key file does not start with the header \"kind, placeholder, real\"")
      else [$rows[1:][]
        | (.key + 1) as $n
        | (.value | split("\t")) as $f
        | if ($f | length) != 3 or (kinds | index($f[0])) == null
          then error("line \($n) of the key file is not kind, placeholder, real")
          else {kind: $f[0], placeholder: $f[1],
                real: ($f[2] | (try fromjson catch null) | if type == "string" then . else error("line \($n) of the key file has a real value that is not a JSON string") end)}
               # An account name, full name, host or seed composed and decomposed, as for -S.
               + (.key as $i | ($f[2] | try fromjson catch null) as $real
                  | [$knfd, $knfc | split("\n") | .[$i] // "" | rtrimstr("\r") | split("\t") | .[2] // "null"
                     | (try fromjson catch null) | strings | select(. != $real)] | unique
                  | if length > 0 and ({"user": true, "realname": true, "host": true, "seed": true}[$f[0]]) then {forms: .} else {} end) end]
      end),
  keep: ($keep[0] // [])
}'

# unicode_forms FILE FROM TO: FILE (the seed file or the loaded key) in another Unicode normalization (UTF-8-MAC is
# macOS's NFD), or nothing where iconv cannot convert. printf is a builtin, so the values never become a process's
# arguments.
unicode_forms() {
  local text
  [ -n "$1" ] || return 0
  text=$(iconv -f "$2" -t "$3" < "$1" 2>/dev/null) && printf '%s\n' "$text"
  return 0
}

# write_config FILE: the config JSON, from DOMAINS, SEED_FILE and LOADED_KEY.
write_config() {
  local file=$1 err
  err=$(printf '%s\n' "${DOMAINS[@]}" | "$JQ" -n -R -c --arg kinds "$KINDS" --arg header "$KEY_HEADER" \
    --rawfile seeds "${SEED_FILE:-/dev/null}" --rawfile key "${LOADED_KEY:-/dev/null}" \
    --rawfile nfd <(unicode_forms "$SEED_FILE" UTF-8 UTF-8-MAC) --rawfile nfc <(unicode_forms "$SEED_FILE" UTF-8-MAC UTF-8) \
    --rawfile knfd <(unicode_forms "$LOADED_KEY" UTF-8 UTF-8-MAC) --rawfile knfc <(unicode_forms "$LOADED_KEY" UTF-8-MAC UTF-8) \
    --slurpfile keep "${KEEP_FILE:-/dev/null}" "$CONFIG_JQ" 2>&1 >"$file") ||
    die "cannot read the seed or key file: ${err#jq: error (at <unknown>): }"
}

# ---- the stream ---------------------------------------------------------------------------------------------
# What stands between jq's stderr and the world: a K line goes to the key file the moment it is read, the S line to the
# stats file, anything else (jq's own complaints) to this script's stderr. It never prints to stdout: that is the capture.
SPLIT_AWK='
BEGIN { key = ENVIRON["GAMELEIRA_CLEAN_KEYFILE"]; stats = ENVIRON["GAMELEIRA_CLEAN_STATSFILE"] }
substr($0, 1, 2) == "K\t" { print substr($0, 3) >> key; close(key); next }
substr($0, 1, 2) == "S\t" { print substr($0, 3) > stats; close(stats); next }
{ print > "/dev/stderr" }'

# run_cleaner CONFIG KEYFILE STATSFILE: raw lines on stdin, cleaned lines on stdout. Returns jq's exit status.
# jq's stderr goes to awk through an fd swap, in one pipeline the shell waits for: with process substitution bash 3.2
# cannot wait for awk, and the key and stats could be read before awk had written them.
run_cleaner() {
  local config=$1 keyfile=$2 statsfile=$3 rc
  {
    "$JQ" -n -R -c --unbuffered --slurpfile cfg "$config" -f "$CLEAN_PROGRAM" 2>&1 1>&3 3>&- |
      GAMELEIRA_CLEAN_KEYFILE=$keyfile GAMELEIRA_CLEAN_STATSFILE=$statsfile awk "$SPLIT_AWK"
    rc=${PIPESTATUS[0]}
  } 3>&1
  return "$rc"
}

# prescan CONFIG: raw lines on stdin; on stdout, the names of the programs the capture runs (a JSON array), which
# write_config puts in `keep` so they are kept from their first appearance. jq's own messages are dropped: they could
# quote the capture.
prescan() {
  "$JQ" -n -R -c --slurpfile cfg "$1" -f "$CLEAN_PROGRAM" 2>/dev/null
}

# The capture as one event per line: a pretty-printed export or a JSON array is turned into lines first. If that stops on
# a parse error, the exit status goes to NORM_STATUS_FILE; jq's own message is dropped, it would quote the capture.
normalize() {
  "$JQ" -c 'if type == "array" then .[] else . end' < "$1" 2>/dev/null
  printf '%s' "$?" > "$NORM_STATUS_FILE"
}

# needs_normalizing FILE: true when the first line that is not blank is just `{`, or starts with `[`.
needs_normalizing() {
  local first
  first=$(grep -m1 -v '^[[:space:]]*$' < "$1")
  first=${first//[[:space:]]/}
  [ "$first" = "{" ] || [ "${first#\[}" != "$first" ]
}

# ---- this Mac's own names -----------------------------------------------------------------------------------
# Each tool's output is tagged by kind and read by one awk: the values go from a pipe to the seed file and are never any
# process's arguments (eslogger records those). U: `dscl` name and uid; R: `dscl` name and full name; H: a host name;
# S: the serial number or platform UUID. An account counts from uid 500, as macOS numbers people's accounts.
LOCAL_SEEDS_AWK='
function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function emit(kind, v) {
  v = trim(v); gsub(/\t/, " ", v)
  if (v != "" && !((kind SUBSEP tolower(v)) in seen)) { seen[kind SUBSEP tolower(v)] = 1; print kind "\t" v }
}
{ tag = substr($0, 1, 1); line = substr($0, 3); name = line; sub(/[ \t].*$/, "", name); rest = trim(substr(line, length(name) + 1)) }
tag == "U" && rest ~ /^[0-9]+$/ && rest + 0 >= 500 { acct[name] = 1; emit("user", name) }
tag == "R" && (name in acct) && tolower(rest) != tolower(name) { emit("realname", rest) }
tag == "H" { emit("host", line) }
tag == "S" { emit("seed", line) }'

# local_seeds FILE: this Mac's names as seed lines (kind, a tab, the value). A name a tool does not have (HostName is
# often not set) is left out.
local_seeds() {
  local k v
  {
    dscl . -list /Users UniqueID 2>/dev/null | awk '{ print "U\t" $0 }'
    dscl . -list /Users RealName 2>/dev/null | awk '{ print "R\t" $0 }'
    for k in ComputerName LocalHostName HostName; do
      v=$(scutil --get "$k" 2>/dev/null) && printf 'H\t%s\n' "$v"
    done
    ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null |
      awk -F'"' '$2 == "IOPlatformSerialNumber" || $2 == "IOPlatformUUID" { print "S\t" $4 }'
  } | awk "$LOCAL_SEEDS_AWK" > "$1"
}

# Whether a capture is of this Mac: the account names of the local seed file (the first file) against the home folders
# (/Users/<name>/, not Shared) of the capture on stdin. Prints yes (one is a local account), no (none is) or none (the
# capture names no home folder). It never prints a name. With GAMELEIRA_CLEAN_HOMES_FILE set (standard input, which is
# read once) it passes every line through to stdout unchanged, checks the first 1000, and writes the answer to that file.
HOMES_AWK='
BEGIN { side = ENVIRON["GAMELEIRA_CLEAN_HOMES_FILE"] }
FILENAME == ARGV[1] { if (split($0, f, "\t") >= 2 && f[1] == "user") acct[tolower(f[2])] = 1; next }
side != "" { print; fflush() }
side != "" && (found || FNR > 1000) { next }
{
  s = $0
  gsub(/\\\//, "/", s)   # eslogger writes a slash as \/
  while (match(s, "/Users/[^/\"]+/")) {
    n = tolower(substr(s, RSTART + 7, RLENGTH - 8)); s = substr(s, RSTART + RLENGTH - 1)
    if (n != "shared") { homes = 1; if (n in acct) { found = 1; if (side == "") exit; break } }
  }
}
END { r = (found ? "yes" : homes ? "no" : "none"); if (side != "") print r > side; else print r }'

other_mac_warning() {
  printf "gameleira-clean: this capture's home folders name no account of this Mac; names outside paths are only caught with -S\n" >&2
}

# warn_if_other_mac IN LOCALSEEDS NORMALIZE: warns when the first 1000 events of the file IN name home folders, and none
# of them is an account of this Mac: then the capture is probably of another Mac, whose names outside paths only -S
# can give.
warn_if_other_mac() {
  local seen
  if [ -n "$3" ]; then
    seen=$("$JQ" -c 'if type == "array" then .[] else . end' < "$1" 2>/dev/null | head -n 1000 | awk "$HOMES_AWK" "$2" -)
  else
    seen=$(head -n 1000 < "$1" | awk "$HOMES_AWK" "$2" -)
  fi
  [ "$seen" != no ] || other_mac_warning
}

# ---- recording ----------------------------------------------------------------------------------------------
# How the recorder is stopped without a second sudo: one `sudo -n /bin/sh -c "$STOP_WRAPPER" sh CTL RECORDER...` runs
# this as root. It opens the stop channel CTL (a FIFO this script holds open, so the open does not block), starts a
# watcher, and becomes the recorder (exec, so the recorder's pid is $$). The watcher waits for a line or end-of-file on
# CTL: a line when this script stops the recording, end-of-file when this script is gone however it ended (its end of
# the FIFO closes with it). Then it sends SIGINT, so eslogger flushes, then SIGTERM, then SIGKILL, 5 s apart, so a root
# eslogger is never left recording. SIGHUP is ignored, by eslogger too: a closed terminal stops the recording through
# this script or the channel, not by killing eslogger mid-write. The watcher's sleeps run only while it stops.
STOP_WRAPPER='ctl=$1; shift
exec 3< "$ctl" || exit 1
trap "" HUP
me=$$
(
  read -r line <&3
  for sig in INT TERM KILL; do
    kill -s "$sig" "$me" 2>/dev/null || exit 0
    i=0
    while [ "$i" -lt 10 ]; do kill -0 "$me" 2>/dev/null || exit 0; /bin/sleep 0.5; i=$((i + 1)); done
  done
) </dev/null >/dev/null 2>&1 &
exec 3<&-
exec "$@"'

# start_recording CONFIG KEYFILE STATSFILE OUT: the recorder writes into a pipe (a FIFO in a private folder, so the raw
# stream is never on disk) and the cleaner reads it into OUT (- for standard output). ES_PID is the recorder (the sudo
# running STOP_WRAPPER), CLEANER_PID the cleaner, and fd 4 this script's end of the stop channel, which no child keeps.
# jq and awk start with SIGINT and SIGHUP ignored (ignored signals survive exec): a terminal's Ctrl-C reaches the whole
# foreground group, and they must read to the end of the pipe once the recorder has stopped, so the last events are
# written rather than lost.
start_recording() {
  local fifo ctl
  RAW_DIR=$(umask 077; mktemp -d "${TMPDIR:-/tmp}/gameleira-clean.XXXXXX") || die "cannot make a temporary folder"
  fifo=$RAW_DIR/raw
  ctl=$RAW_DIR/stop
  mkfifo -m 600 "$fifo" "$ctl" || die "cannot make a pipe in $RAW_DIR"
  # Read and write: a FIFO opened only for writing would wait for the reader, sudo, which may never come.
  exec 4<>"$ctl" || die "cannot open $ctl"
  if [ "$4" = - ]; then
    ( trap '' INT HUP; run_cleaner "$1" "$2" "$3" < "$fifo" ) 4>&- &
  else
    ( trap '' INT HUP; run_cleaner "$1" "$2" "$3" < "$fifo" > "$4" ) 4>&- &
  fi
  CLEANER_PID=$!
  if [ -n "$SUDO_CMD" ]; then
    "$SUDO_CMD" -n /bin/sh -c "$STOP_WRAPPER" sh "$ctl" "${RECORDER[@]}" > "$fifo" 4>&- &
  else
    /bin/sh -c "$STOP_WRAPPER" sh "$ctl" "${RECORDER[@]}" > "$fifo" 4>&- &
  fi
  ES_PID=$!
}

# wait_for PID SECONDS: waits, without polling, until the child PID ends (returns 0), SECONDS pass (1; empty: no limit)
#   or Ctrl-C, TERM or HUP arrives (2; the trap counts them in SIGNALS). Never polls with ps or sleep: eslogger records
#   every program this script runs, and ps is a recon tool the rules flag. A timer child signals USR1 when time is up;
#   on TERM it kills its own sleep, so none is left behind: `stop` covers a TERM that comes before `s` is set (a trap
#   runs between commands), one before the trap is set ends the timer before its sleep starts, and SIGKILL reaches a
#   sleep that has not yet exec'd (a forked bash, which would take a TERM as its own trap's and then lose it). The
#   timer does not keep the stop channel (fd 4) open.
SIGNALS=0
wait_for() {
  local timer= before=$SIGNALS result=0
  TIMED_OUT=
  trap 'TIMED_OUT=1' USR1
  if [ -n "$2" ]; then
    ( s= stop=
      trap 'stop=1; [ -z "$s" ] || kill -KILL "$s" 2>/dev/null' TERM
      sleep "$2" & s=$!
      [ -z "$stop" ] || kill -KILL "$s" 2>/dev/null
      [ -n "$stop" ] || wait "$s" 2>/dev/null
      [ -n "$stop" ] || kill -USR1 $$ 2>/dev/null ) </dev/null >/dev/null 2>&1 4>&- &
    timer=$!
  fi
  [ -n "$TIMED_OUT" ] || [ "$SIGNALS" != "$before" ] || wait "$1" 2>/dev/null
  if [ -n "$TIMED_OUT" ]; then result=1; elif [ "$SIGNALS" != "$before" ]; then result=2; fi
  if [ -n "$timer" ]; then kill -TERM "$timer" 2>/dev/null; wait "$timer" 2>/dev/null; fi
  return "$result"
}

# stop_capture: asks the recorder to stop (a line on the stop channel) and waits for it: STOP_WRAPPER sends SIGINT, so
#   eslogger flushes, then SIGTERM and SIGKILL, 5 s apart. No sudo, so no password prompt. More Ctrl-C (or TERM, HUP)
#   is ignored from here on: the stop is under way, and is bounded.
stop_capture() {
  [ -n "$ES_PID" ] || return 0
  trap '' INT TERM HUP
  printf 'stop\n' >&4 2>/dev/null
  wait "$ES_PID" 2>/dev/null
  ES_PID=''
  exec 4>&-
}

# record_until_stopped SECONDS: waits for Ctrl-C (or TERM, HUP), SECONDS (empty: no limit) or the recorder ending by
# itself, then stops the recorder and waits for the cleaner to finish. Returns 1 when the recorder stopped by itself.
record_until_stopped() {
  local by_itself=0
  if [ -z "$STOP" ] && wait_for "$ES_PID" "$1"; then
    by_itself=1
    ES_PID=''
    exec 4>&-   # the watcher, still waiting, reads end-of-file and finds nothing to stop
  else
    stop_capture
  fi
  # A trapped signal ends `wait` early: wait until the cleaner is really gone (kill -0 is a builtin, it runs nothing).
  while kill -0 "$CLEANER_PID" 2>/dev/null; do wait "$CLEANER_PID"; done
  CLEANER_PID=''
  return "$by_itself"
}

# ---- the summary --------------------------------------------------------------------------------------------
print_summary() {
  "$JQ" -r --arg kinds "$KINDS" '
    "events in: \(.eventsIn)",
    "events out: \(.eventsOut)",
    "unreadable lines dropped: \(.unreadable)",
    "events the cleaner could not clean: \(.uncleaned // 0)",
    "events dropped by Endpoint Security: \(.seqGaps)",
    (($kinds | split(" "))[] as $k | "placeholders \($k): \(.placeholders[$k] // 0)"),
    "redacted: \(.redacted)",
    (.shortAccounts // [] | select(length > 0) | "short or common account names: \(join(", "))")' < "$1" >&2
}

# ---- command line -------------------------------------------------------------------------------------------
# canonical PATH: PATH as one spelling of the file it names, whether or not it exists yet: absolute, a symlink at its end
# followed, its folder's symlinks resolved (pwd -P) as far as the folder exists, `.` and `..` in the rest taken out, and
# lower-cased, since macOS volumes ignore case by default (on one that does not, two names that differ only in case are
# refused too).
canonical() {
  local p=$1 t n=0 dir rest= part out=
  case $p in /*) ;; *) p=$PWD/$p ;; esac
  while [ -L "$p" ] && [ "$n" -lt 16 ]; do
    t=$(readlink "$p") || break
    case $t in /*) p=$t ;; *) p=${p%/*}/$t ;; esac
    n=$((n + 1))
  done
  dir=${p%/*}; rest=${p##*/}
  while [ -n "$dir" ] && [ ! -d "$dir" ]; do rest=${dir##*/}/$rest; dir=${dir%/*}; done
  dir=$(cd "${dir:-/}" 2>/dev/null && pwd -P) || dir=${dir:-/}
  dir=${dir%/}
  while [ -n "$rest" ]; do
    case $rest in */*) part=${rest%%/*}; rest=${rest#*/} ;; *) part=$rest; rest= ;; esac
    case $part in
      ''|.) ;;
      ..) if [ -n "$out" ]; then out=${out%/*}; else dir=${dir%/*}; fi ;;
      *) out=$out/$part ;;
    esac
  done
  printf '%s%s\n' "$dir" "$out" | tr '[:upper:]' '[:lower:]'
}

# same_file A B: true when A and B are one file, or would be once written.
same_file() {
  [ "$1" -ef "$2" ] || [ "$(canonical "$1")" = "$(canonical "$2")" ]
}

need_value() {
  [ "$1" -ge 2 ] || usage_error "$2 needs a value"
}

main() {
  local mode in= out=capture.cleaned.jsonl keyarg= seconds= name keydir
  DOMAINS=()
  SEED_FILE=
  LOADED_KEY=

  [ $# -ge 1 ] || { usage >&2; exit 2; }
  case $1 in
    -h|--help) usage; exit 0 ;;
    clean|record) mode=$1; shift ;;
    *) usage_error "unknown command: $1" ;;
  esac
  while [ $# -gt 0 ]; do
    case $1 in
      -h|--help) usage; exit 0 ;;
      -i) [ "$mode" = clean ] || usage_error "-i is for clean; record reads eslogger"
          need_value $# -i; in=$2; shift 2 ;;
      -o) need_value $# -o; out=$2; shift 2 ;;
      -k) need_value $# -k; keyarg=$2; shift 2 ;;
      -D) need_value $# -D; DOMAINS[${#DOMAINS[@]}]=$2; shift 2 ;;
      -S) need_value $# -S; SEED_FILE=$2; shift 2 ;;
      -t) [ "$mode" = record ] || usage_error "-t is for record"
          need_value $# -t; seconds=$2; shift 2
          case $seconds in ''|*[!0-9]*|0) usage_error "-t needs a whole number of seconds" ;; esac ;;
      *) usage_error "unknown argument: $1" ;;
    esac
  done
  [ "$mode" = record ] || [ -n "$in" ] || usage_error "clean needs -i RAW"
  [ -n "$out" ] || usage_error "-o needs a file name"

  # Everything that can fail without touching a file comes first.
  if [ "$mode" = record ]; then
    [ "${GAMELEIRA_CLEAN_FAKE_UID:-$(id -u)}" != 0 ] ||
      die "run record as yourself, not as root (without sudo): it asks for your password for eslogger only"
    [ "${GAMELEIRA_CLEAN_FAKE_OS:-$(uname -s)}" = Darwin ] || die "record runs only on macOS (eslogger is part of macOS); clean -i cleans a capture taken elsewhere"
    if [ -n "${GAMELEIRA_CLEAN_RECORDER:-}" ]; then
      RECORDER=(/bin/bash -c "$GAMELEIRA_CLEAN_RECORDER")
      SUDO_CMD=
    else
      command -v eslogger >/dev/null || die "eslogger not found (it ships with macOS 13 and later)"
    fi
  fi
  [ -x "$JQ" ] || die "no jq at $JQ (macOS 15 and later has /usr/bin/jq; GAMELEIRA_CLEAN_JQ names another)"
  case $("$JQ" --version 2>/dev/null) in
    jq-1.[7-9]*|jq-1.[1-9][0-9]*|jq-[2-9]*) ;;
    *) die "jq 1.7 or later is needed ($JQ is $("$JQ" --version 2>&1))" ;;
  esac
  [ "$mode" = record ] || [ "$in" = - ] || { [ -f "$in" ] && [ -r "$in" ]; } || die "cannot read $in"
  [ -z "$SEED_FILE" ] || { [ -f "$SEED_FILE" ] && [ -r "$SEED_FILE" ]; } || die "cannot read the seed file $SEED_FILE"
  if [ "$mode" = clean ] && [ "$in" != - ] && [ "$out" != - ] && same_file "$out" "$in"; then die "-o and -i are the same file; the capture would be erased"; fi

  # The key: found, or refused, before anything is created.
  local key=$keyarg
  if [ -z "$key" ]; then
    name=stdout
    [ "$out" = - ] || name=${out##*/}
    [ -n "$name" ] && [ "$name" != . ] && [ "$name" != .. ] || usage_error "-o needs a file name"
    keydir=${GAMELEIRA_CLEAN_KEY_DIR:-$HOME/Library/Application Support/Gameleira/keys}
    key=$keydir/$name.key.tsv
    [ ! -e "$key" ] || die "a key already exists at $key; pass -k to reuse it (the same placeholders), or choose another -o"
  fi
  # The key in the capture would put real values in the file that leaves the Mac; the key over the capture would erase it.
  [ "$out" = - ] || ! same_file "$out" "$key" || die "-o and -k are the same file; the key would be written into the capture"
  [ "$mode" = record ] || [ "$in" = - ] || ! same_file "$in" "$key" || die "-k and -i are the same file; the capture would be written over"
  if [ -s "$key" ]; then
    [ "$(head -n 1 < "$key")" = "$KEY_HEADER" ] || die "$key is not a Gameleira key file"
    LOADED_KEY=$key
  fi

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP

  # Everything that can still fail is done before the key is made, so a failed run leaves no key in the way of the next.
  if [ "$out" != - ]; then
    mkdir -p "$(dirname "$out")" || die "cannot make the folder for $out"
  fi
  local old_umask config stats normalize_input= local_file=
  old_umask=$(umask)
  umask 077
  new_tmp; config=$TMP_OUT
  new_tmp; stats=$TMP_OUT
  new_tmp; NORM_STATUS_FILE=$TMP_OUT
  # This Mac's names are seeds too, after the -S file's lines (so an error there still names its own line number).
  if [ "${GAMELEIRA_CLEAN_NO_LOCAL_SEEDS:-}" != 1 ]; then
    new_tmp; local_file=$TMP_OUT
    local_seeds "$local_file"
    new_tmp
    { [ -z "$SEED_FILE" ] || { cat "$SEED_FILE"; printf '\n'; }; cat "$local_file"; } > "$TMP_OUT" ||
      die "cannot write a temporary file"
    SEED_FILE=$TMP_OUT
  fi
  # A file is read twice: first for the names of the programs it runs (from standard input there is one pass only).
  KEEP_FILE=
  if [ "$mode" = clean ] && [ "$in" != - ]; then
    needs_normalizing "$in" && normalize_input=1
    printf '{"prescan":true}\n' > "$config"
    new_tmp; KEEP_FILE=$TMP_OUT
    if [ -n "$normalize_input" ]; then
      normalize "$in" | prescan "$config" > "$KEEP_FILE"
    else
      prescan "$config" < "$in" > "$KEEP_FILE"
    fi || die "cannot read the programs in $in"
    [ ! -s "$local_file" ] || warn_if_other_mac "$in" "$local_file" "$normalize_input"
  fi
  if [ "$mode" = record ] && [ -n "$SUDO_CMD" ]; then
    sudo -v || die "sudo is needed for eslogger"
  fi
  write_config "$config"

  # The key is made, private, before the first event is read, so a capture cut short still has its key.
  mkdir -p "$(dirname "$key")" || die "cannot make the folder for $key"
  [ -s "$key" ] || printf '%s\n' "$KEY_HEADER" > "$key" || die "cannot write $key"
  chmod 600 "$key"
  umask "$old_umask"

  local stopped_by_itself= homes_file= homes=
  if [ "$mode" = record ]; then
    # Ctrl-C, or the terminal closing, stops eslogger only; the cleaner then reads to the end of the pipe.
    STOP=
    trap 'STOP=1; SIGNALS=$((SIGNALS + 1))' INT TERM HUP
    start_recording "$config" "$key" "$stats" "$out"
    if [ -n "$seconds" ]; then
      printf 'gameleira-clean: recording for %s s; Ctrl-C stops it sooner.\n' "$seconds" >&2
    else
      printf 'gameleira-clean: recording; Ctrl-C stops it.\n' >&2
    fi
    record_until_stopped "$seconds" || stopped_by_itself=1
  elif [ "$in" = - ] && [ -s "$local_file" ]; then
    # Standard input is read once: the home-folder check runs in the stream, and only its answer is written down.
    new_tmp; homes_file=$TMP_OUT
    if [ "$out" = - ]; then
      GAMELEIRA_CLEAN_HOMES_FILE=$homes_file awk "$HOMES_AWK" "$local_file" - | run_cleaner "$config" "$key" "$stats"
    else
      GAMELEIRA_CLEAN_HOMES_FILE=$homes_file awk "$HOMES_AWK" "$local_file" - | run_cleaner "$config" "$key" "$stats" > "$out"
    fi
  elif [ "$in" = - ]; then
    if [ "$out" = - ]; then run_cleaner "$config" "$key" "$stats"; else run_cleaner "$config" "$key" "$stats" > "$out"; fi
  elif [ -n "$normalize_input" ]; then
    if [ "$out" = - ]; then
      normalize "$in" | run_cleaner "$config" "$key" "$stats"
    else
      normalize "$in" | run_cleaner "$config" "$key" "$stats" > "$out"
    fi
  elif [ "$out" = - ]; then
    run_cleaner "$config" "$key" "$stats" < "$in"
  else
    run_cleaner "$config" "$key" "$stats" < "$in" > "$out"
  fi

  if [ -n "$stopped_by_itself" ]; then
    if [ -s "$stats" ] && [ "$("$JQ" -r '.eventsIn' < "$stats" 2>/dev/null)" = 0 ]; then
      # Nothing was recorded: leave no key or empty capture in the way of the next run.
      [ -n "$LOADED_KEY" ] || rm -f "$key"
      [ "$out" = - ] || [ -s "$out" ] || rm -f "$out"
      die "eslogger stopped before recording anything (see above; does the terminal have Full Disk Access?)"
    fi
    printf 'gameleira-clean: eslogger stopped by itself (see above)\n' >&2
  fi
  [ -s "$stats" ] || die "the cleaner stopped before the end of the capture (see above); the output is incomplete, and $key holds only the placeholders made so far: pass -k $key to carry on from it, or remove it"
  print_summary "$stats"
  if [ -n "$homes_file" ]; then
    read -r homes < "$homes_file"
    [ "$homes" != no ] || other_mac_warning
  fi
  if [ -n "$normalize_input" ]; then
    case $(cat "$NORM_STATUS_FILE") in 0) ;; *) echo 'input ended with a parse error: yes' >&2 ;; esac
  fi
  if [ "$out" = - ]; then echo 'capture: (standard output)' >&2; else echo "capture: $out" >&2; fi
  echo "key: $key" >&2
  if [ "$mode" = clean ]; then
    if [ "$in" = - ]; then echo 'raw capture, left as it was: (standard input)' >&2; else echo "raw capture, left as it was: $in" >&2; fi
  fi
}

[ -n "${GAMELEIRA_CLEAN_SOURCE_ONLY:-}" ] && return 0

main "$@"
