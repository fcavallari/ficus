#!/bin/bash
# fetch-sample.sh: downloads one sample zip from https://github.com/objective-see/malware and records it in the manifest.
#
#   lab/fetch-sample.sh FAMILY        FAMILY is the folder name as the repository lists it, e.g. "AtomicStealer"
#
# The zip is encrypted (password infect3d) and goes to $FICUS_LAB_DATA/samples/FAMILY.zip. This script never extracts it,
# opens it or runs it, and nothing on the host should: samples are unzipped inside the lab's guest VM only. It adds one row
# to the manifest (lab/manifest.tsv, or $LAB_MANIFEST): family, zip, sha256, recipe (manual), window in seconds (600), notes, source
# (objective-see; fetch-bazaar.sh writes bazaar).
# Running it again changes nothing. These are live malware samples: fetch only the ones you mean to run, in your own lab.
#
# Exit 0 done, 1 failed (nothing left behind), 2 usage. LAB_CURL overrides the curl command.

export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"
CURL=${LAB_CURL:-curl}
MANIFEST=${LAB_MANIFEST:-$HERE/manifest.tsv}
HEADER=$'family\tzip\tsha256\trecipe\twindow_s\tnotes\tsource'

if [ $# -ne 1 ]; then
  echo "usage: fetch-sample.sh FAMILY" >&2
  exit 2
fi
family=$1
lab_check_name "$family"

samples="$(lab_data_dir)/samples"
zip="$samples/$family.zip"
part="$zip.part"
mkdir -p "$samples" || lab_die "cannot create $samples"

if [ -s "$zip" ]; then
  echo "already on disk: $zip"
else
  rm -f "$part"
  "$CURL" -fL -sS --proto '=https' -o "$part" "$(lab_sample_url "$family")" || { rm -f "$part"; lab_die "the download of $family failed"; }
  if [ "$(head -c 2 "$part" 2>/dev/null)" != "PK" ]; then
    rm -f "$part"
    lab_die "what came back for $family is not a zip (is the family name right?)"
  fi
  mv "$part" "$zip" || lab_die "cannot move the download into place"
  echo "saved: $zip"
fi

sha=$(lab_sha256 "$zip")
[ -f "$MANIFEST" ] || printf '%s\n' "$HEADER" > "$MANIFEST"
if awk -F'\t' -v f="$family" 'NR > 1 && $1 == f { found = 1 } END { exit !found }' "$MANIFEST"; then
  echo "already in the manifest: $family"
else
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$family" "$family.zip" "$sha" manual 600 "" objective-see >> "$MANIFEST"
  echo "added to the manifest: $family  sha256 $sha"
fi
