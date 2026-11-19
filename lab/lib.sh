#!/bin/bash
# lib.sh: shared functions for the Ficus malware lab scripts. Source it; it runs nothing. Bash 3.2 compatible.
#
#   . "$(dirname "$0")/lib.sh"
#
# lab_data_dir        where samples, captures and run folders live ($FICUS_LAB_DATA, else a folder outside the repo)
# lab_slug NAME       lowercase, each run of non-alphanumerics becomes one dash: "Crisis (Morcut)" -> crisis-morcut
# lab_sample_url NAME the raw URL of NAME.zip in the objective-see/malware repository, percent-encoded
# lab_events          the eslogger events to record (lab/events.txt) on one line
# lab_run_id NAME     <slug>-<UTC time>-<pid>; two runs in the same second of one process still need the harness's mkdir
# lab_check_name NAME refuses an empty name, one with a slash or "..", one starting with "-" or holding a newline or tab
# lab_sha256 FILE     the SHA-256 of FILE
# lab_die MESSAGE     prints "error: MESSAGE" to stderr and exits 1

LAB_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

lab_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

lab_data_dir() { printf '%s\n' "${FICUS_LAB_DATA:-$HOME/WORK/investigation/MacOSThreats/ficus-lab-data}"; }

lab_slug() {
  printf '%s' "$1" | LC_ALL=C tr 'A-Z' 'a-z' | LC_ALL=C sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'
  printf '\n'
}

lab_sample_url() {
  local name=$1 out="" c i
  local LC_ALL=C
  for ((i = 0; i < ${#name}; i++)); do
    c=${name:i:1}
    case "$c" in
      [A-Za-z0-9._~-]) out="$out$c" ;;
      *) out="$out$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf 'https://github.com/objective-see/malware/raw/main/%s.zip\n' "$out"
}

lab_events() {
  grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$LAB_LIB_DIR/events.txt" | tr '\n' ' ' | sed 's/ $//'
  printf '\n'
}

lab_run_id() {
  printf '%s-%s-%s\n' "$(lab_slug "$1")" "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

lab_check_name() {
  local name=$1
  case "$name" in
    '') lab_die "the name is empty" ;;
    */*) lab_die "the name '$name' contains a slash" ;;
    *..*) lab_die "the name '$name' contains '..'" ;;
    -*) lab_die "the name '$name' starts with a dash" ;;
  esac
  case "$name" in
    *$'\n'*) lab_die "the name contains a newline" ;;
    *$'\t'*) lab_die "the name contains a tab (the manifest is tab-separated)" ;;
  esac
}

lab_sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else sha256sum "$1" | cut -d' ' -f1; fi
}
