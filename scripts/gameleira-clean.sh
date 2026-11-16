#!/bin/bash
# gameleira-clean.sh: pseudonymizes an eslogger capture before it leaves the Mac it was recorded on.
#
#   scripts/gameleira-clean.sh clean  -i RAW [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE]
#   scripts/gameleira-clean.sh record        [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE] [-t SECONDS]
#   scripts/gameleira-clean.sh --help
#
# Names, hosts, accounts and credentials become placeholders; what the rules need to see stays. The real values go in a
# key file on this Mac, so the cleaning can be undone here and nowhere else.
#
# Needs only what macOS has: bash 3.2, /usr/bin/jq (macOS 15 and later; GAMELEIRA_CLEAN_JQ names another), awk.
# The program that does the cleaning is gameleira-clean.jq, next to this file.

export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CLEAN_PROGRAM=$HERE/gameleira-clean.jq
JQ=${GAMELEIRA_CLEAN_JQ:-/usr/bin/jq}
KINDS="user realname name volume host email seed data"
KEY_HEADER=$'kind\tplaceholder\treal'

usage() {
  cat <<'EOF'
Usage:
  gameleira-clean.sh clean  -i RAW [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE]
  gameleira-clean.sh record        [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE] [-t SECONDS]

clean   Read the capture RAW (JSONL, a pretty-printed export or a JSON array) and write the cleaned capture as JSONL.
        RAW is never changed or deleted: remove it yourself once you are happy with the result.
record  Record with eslogger and write the cleaned capture as it goes (not built yet).

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
  rm -f "${TMP_FILES[@]}"
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
CONFIG_JQ='
def kinds: ($kinds | split(" "));
def lines($text): $text | split("\n") | map(rtrimstr("\r") | select(length > 0));
{
  seeds: [lines($seeds) | to_entries[]
    | (.value | split("\t")) as $f
    | if ($f | length) < 2 or (kinds | index($f[0])) == null or $f[1] == ""
      then error("line \(.key + 1) of the seed file is not a known kind, a tab and a value")
      else {kind: $f[0], value: ($f[1:] | join("\t"))} end],
  domains: [inputs | select(length > 0) | ascii_downcase | ltrimstr(".")],
  key: (lines($key) as $rows
    | if ($rows | length) == 0 then []
      elif $rows[0] != $header then error("the key file does not start with the header \"kind, placeholder, real\"")
      else [$rows[1:] | to_entries[]
        | (.key + 2) as $n
        | (.value | split("\t")) as $f
        | if ($f | length) != 3 or (kinds | index($f[0])) == null
          then error("line \($n) of the key file is not kind, placeholder, real")
          else {kind: $f[0], placeholder: $f[1],
                real: ($f[2] | (try fromjson catch null) | if type == "string" then . else error("line \($n) of the key file has a real value that is not a JSON string") end)} end]
      end),
  keep: []
}'

# write_config FILE: the config JSON, from DOMAINS, SEED_FILE and LOADED_KEY.
write_config() {
  local file=$1 err
  err=$(printf '%s\n' "${DOMAINS[@]}" | "$JQ" -n -R -c --arg kinds "$KINDS" --arg header "$KEY_HEADER" \
    --rawfile seeds "${SEED_FILE:-/dev/null}" --rawfile key "${LOADED_KEY:-/dev/null}" "$CONFIG_JQ" 2>&1 >"$file") ||
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

# ---- the summary --------------------------------------------------------------------------------------------
print_summary() {
  "$JQ" -r --arg kinds "$KINDS" '
    "events in: \(.eventsIn)",
    "events out: \(.eventsOut)",
    "unreadable lines dropped: \(.unreadable)",
    "events dropped by Endpoint Security: \(.seqGaps)",
    (($kinds | split(" "))[] as $k | "placeholders \($k): \(.placeholders[$k] // 0)"),
    "redacted: \(.redacted)"' < "$1" >&2
}

# ---- command line -------------------------------------------------------------------------------------------
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
  [ "$mode" = clean ] || die "record mode is not built yet"

  # Everything that can fail without touching a file comes first.
  [ -x "$JQ" ] || die "no jq at $JQ (macOS 15 and later has /usr/bin/jq; GAMELEIRA_CLEAN_JQ names another)"
  case $("$JQ" --version 2>/dev/null) in
    jq-1.[7-9]*|jq-1.[1-9][0-9]*|jq-[2-9]*) ;;
    *) die "jq 1.7 or later is needed ($JQ is $("$JQ" --version 2>&1))" ;;
  esac
  [ -f "$in" ] && [ -r "$in" ] || die "cannot read $in"
  [ -z "$SEED_FILE" ] || { [ -f "$SEED_FILE" ] && [ -r "$SEED_FILE" ]; } || die "cannot read the seed file $SEED_FILE"
  if [ "$out" != - ] && [ "$out" -ef "$in" ]; then die "-o and -i are the same file; the capture would be erased"; fi

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
  local old_umask config stats
  old_umask=$(umask)
  umask 077
  new_tmp; config=$TMP_OUT
  new_tmp; stats=$TMP_OUT
  new_tmp; NORM_STATUS_FILE=$TMP_OUT
  write_config "$config"

  # The key is made, private, before the first event is read, so a capture cut short still has its key.
  mkdir -p "$(dirname "$key")" || die "cannot make the folder for $key"
  [ -s "$key" ] || printf '%s\n' "$KEY_HEADER" > "$key" || die "cannot write $key"
  chmod 600 "$key"
  umask "$old_umask"

  local normalize_input=
  needs_normalizing "$in" && normalize_input=1
  if [ -n "$normalize_input" ]; then
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

  [ -s "$stats" ] || die "the cleaner stopped before the end of the capture (see above); the output is incomplete, and $key holds only the placeholders made so far: pass -k $key to carry on from it, or remove it"
  print_summary "$stats"
  if [ -n "$normalize_input" ]; then
    case $(cat "$NORM_STATUS_FILE") in 0) ;; *) echo 'input ended with a parse error: yes' >&2 ;; esac
  fi
  if [ "$out" = - ]; then echo 'capture: (standard output)' >&2; else echo "capture: $out" >&2; fi
  echo "key: $key" >&2
  echo "raw capture, left as it was: $in" >&2
}

[ -n "${GAMELEIRA_CLEAN_SOURCE_ONLY:-}" ] && return 0

main "$@"
