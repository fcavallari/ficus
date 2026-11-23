#!/bin/bash
# fetch-bazaar.sh: finds and downloads samples from MalwareBazaar (abuse.ch) and records them in the manifest.
#
#   lab/fetch-bazaar.sh search [--type macho] [--tag TAG] [--limit 30]
#   lab/fetch-bazaar.sh get SHA256 [LABEL]
#
# search  lists recent samples of a file type (default macho; others: dmg, pkg, ...) or with a tag (AMOS, ...), newest first, as a
#         tab-separated table: first_seen, sha256, size, arch, signature, type, tags, name. It downloads nothing.
# get     downloads one sample by sha256 into $FICUS_LAB_DATA/samples/LABEL.zip (LABEL defaults to Bazaar-<signature>-<first 8 of
#         the sha256>) and adds a row to the manifest (lab/manifest.tsv, or $LAB_MANIFEST): recipe manual, window 600, the sample's
#         sha256 and signature in the notes column, source bazaar. Running it again changes nothing.
#
# Needs your abuse.ch Auth-Key in the environment: export ABUSE_CH_KEY=... (never in a file of this repository). The key goes to curl
# on its standard input, so it is on no command line; it is never printed and never written down.
# MalwareBazaar's zips are AES-encrypted with the password "infected", which macOS unzip cannot open: lab-run.sh extracts them in the
# guest with 7zz (the main guest image has it). This script never extracts, opens or runs what it downloads, and nothing on the host
# should. These are live malware samples: fetch only the ones you mean to run, in your own lab.
#
# Exit 0 done, 1 failed (nothing left behind), 2 usage. LAB_CURL overrides curl; LAB_BAZAAR_API the endpoint (for tests).

export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"
CURL=${LAB_CURL:-curl}
API=${LAB_BAZAAR_API:-https://mb-api.abuse.ch/api/v1/}
MANIFEST=${LAB_MANIFEST:-$HERE/manifest.tsv}
HEADER=$'family\tzip\tsha256\trecipe\twindow_s\tnotes\tsource'

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }
bad() { [ -n "$1" ] && echo "error: $1" >&2; usage >&2; exit 2; }

[ $# -ge 1 ] || bad ""
cmd=$1; shift
case "$cmd" in search|get) ;; -h|--help) usage; exit 0 ;; *) bad "unknown command '$cmd'" ;; esac

# Arguments are checked before the key or the network is touched.
if [ "$cmd" = search ]; then
  type=macho; tag=""; limit=30
  while [ $# -gt 0 ]; do
    case "$1" in
      --type) [ $# -ge 2 ] || bad "--type needs a file type"; type=$2; shift ;;
      --tag) [ $# -ge 2 ] || bad "--tag needs a tag"; tag=$2; shift ;;
      --limit) [ $# -ge 2 ] || bad "--limit needs a number"; limit=$2; shift ;;
      *) bad "unknown option $1" ;;
    esac
    shift
  done
  case "$type" in ''|*[!A-Za-z0-9._-]*) bad "--type may hold only letters, digits, dot, dash and underscore" ;; esac
  case "$tag" in *[!A-Za-z0-9._-]*) bad "--tag may hold only letters, digits, dot, dash and underscore" ;; esac
  case "$limit" in ''|*[!0-9]*) bad "--limit must be a number from 1 to 1000" ;; esac
  { [ "$limit" -ge 1 ] && [ "$limit" -le 1000 ]; } || bad "--limit must be a number from 1 to 1000"
else
  [ $# -ge 1 ] && [ $# -le 2 ] || bad "get needs a sha256 and, optionally, a label"
  sha=$(printf '%s' "$1" | tr 'A-F' 'a-f')
  case "$sha" in *[!0-9a-f]*|'') bad "that is not a sha256" ;; esac
  [ "${#sha}" -eq 64 ] || bad "that is not a sha256 (64 hex digits)"
  label=${2:-}
  [ -z "$label" ] || ( lab_check_name "$label" ) 2>&1 || exit 2
fi

[ -n "${ABUSE_CH_KEY:-}" ] || { echo "error: set ABUSE_CH_KEY (your abuse.ch Auth-Key) in the environment" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/fetch-bazaar.XXXXXX") || lab_die "cannot make a temporary folder"
trap 'rm -rf "$work"' EXIT

# api OUTFILE ARGS...: one POST to the API. The key rides in a curl config on stdin, so it is on no command line.
api() {
  local out=$1; shift
  printf 'header = "Auth-Key: %s"\n' "$ABUSE_CH_KEY" | "$CURL" -sS -m 180 -K - -X POST -o "$out" "$@" "$API" || lab_die "the request to MalwareBazaar failed"
}

# status FILE: the query_status of a JSON answer, or empty when it is not JSON.
status() { jq -r '.query_status // empty' "$1" 2>/dev/null; }

if [ "$cmd" = search ]; then
  if [ -n "$tag" ]; then api "$work/search.json" -d query=get_taginfo -d "tag=$tag" -d "limit=$limit"
  else api "$work/search.json" -d query=get_file_type -d "file_type=$type" -d "limit=$limit"; fi
  st=$(status "$work/search.json")
  [ "$st" = ok ] || lab_die "MalwareBazaar answered '${st:-something that is not JSON}'"
  printf 'first_seen\tsha256\tsize\tarch\tsignature\ttype\ttags\tname\n'
  jq -r '.data[]? | [(.first_seen // "-")[0:10], .sha256_hash, ((.file_size // 0) | tostring), (.file_arch // "-"), (.signature // "-"),
    (.file_type // "-"), ((.tags // []) | join(",")), (.file_name // "-")] | @tsv' "$work/search.json"
  exit 0
fi

# --- get ---------------------------------------------------------------------------------------------------------------------------
api "$work/info.json" -d query=get_info -d "hash=$sha"
st=$(status "$work/info.json")
[ "$st" = ok ] || lab_die "MalwareBazaar answered '${st:-something that is not JSON}' for $sha"
sig=$(jq -r '.data[0].signature // "unknown"' "$work/info.json")
echo "sample: $(jq -r '.data[0] | "\(.file_name // "-"), \(.file_type // "-"), \(.file_size // 0) bytes, first seen \(.first_seen // "-"), signature \(.signature // "none"), tags \((.tags // []) | join(","))"' "$work/info.json")"

if [ -z "$label" ]; then
  clean=$(printf '%s' "$sig" | tr -c 'A-Za-z0-9' '-' | sed 's/-*$//')
  label="Bazaar-${clean:-unknown}-${sha:0:8}"
  ( lab_check_name "$label" ) 2>&1 || exit 1
fi

samples="$(lab_data_dir)/samples"
zip="$samples/$label.zip"
mkdir -p "$samples" || lab_die "cannot create $samples"

if [ -s "$zip" ]; then
  echo "already on disk: $zip"
else
  api "$work/sample.zip" -d query=get_file -d "sha256_hash=$sha"
  if [ "$(head -c 2 "$work/sample.zip" 2>/dev/null)" != "PK" ]; then
    st=$(status "$work/sample.zip")
    lab_die "MalwareBazaar did not send a zip${st:+ (it answered '$st')}"
  fi
  mv "$work/sample.zip" "$zip" || lab_die "cannot move the download into place"
  echo "saved: $zip"
fi

zipsha=$(lab_sha256 "$zip")
[ -f "$MANIFEST" ] || printf '%s\n' "$HEADER" > "$MANIFEST"
if awk -F'\t' -v f="$label" 'NR > 1 && $1 == f { found = 1 } END { exit !found }' "$MANIFEST"; then
  echo "already in the manifest: $label"
else
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$label.zip" "$zipsha" manual 600 "bazaar:$sha $sig" bazaar >> "$MANIFEST"
  echo "added to the manifest: $label  (zip sha256 $zipsha; sample sha256 $sha)"
fi
