#!/bin/bash
# guest-benign.sh: ordinary activity, run INSIDE the guest, for the lab's benign baseline (lab-run.sh --baseline benign).
#
#   bash guest-benign.sh [--dry-run]
#
# What a person or a developer does in an afternoon, in small: look at the system, check developer tools, make and move files,
# zip and tar, download a page, write a preference, make an SSH key, install a package, open an app, query launchd, run Python.
# Ficus flags some of this (a curl download is a `download` finding, an archive is `archive-staging`): the baseline shows which
# findings are noise on clean behavior, so a real sample's findings can be read against them.
#
# Nothing here is an attack: no pipe from curl into a shell, no decoding, no quarantine stripping, nothing written to a launch
# folder. Every step is allowed to fail (a tool may be missing); the script goes on and prints how many steps worked.
# It refuses to run anywhere that is not a virtual machine (it installs a package as root).

export LC_ALL=C
DRY=0; OK=0; BAD=0
WORK="$HOME/lab-benign"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

is_vm() {
  [ "${FICUS_LAB_ASSUME_VM:-}" = 1 ] && return 0
  [ "$(uname)" = Darwin ] || return 1
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in *VirtualMac*) return 0 ;; esac
  return 1
}
if [ "$DRY" = 0 ] && ! is_vm; then die "this is not a virtual machine; refusing to run. Use --dry-run to look."; fi

# step DESCRIPTION SCRIPT: runs SCRIPT in bash (or only prints it under --dry-run); a failure is counted, not fatal.
step() {
  local desc=$1 body=$2
  if [ "$DRY" = 1 ]; then say "would: $desc"; return 0; fi
  say "step: $desc"
  if W="$WORK" bash -c "$body" >/dev/null 2>&1; then OK=$((OK + 1)); else BAD=$((BAD + 1)); say "  (failed, going on)"; fi
  sleep 1
}

step "recon: look at the system" 'sw_vers; uname -a; whoami; id; hostname; sysctl -n hw.model'
step "developer tools: ask for versions" 'git --version; python3 --version; brew --version'
step "files: make, copy, move, delete" 'mkdir -p "$W" && cd "$W" && echo hello > a.txt && cp a.txt b.txt && mv b.txt c.txt && rm a.txt && ls -la'
step "archives: zip and tar a file and unpack them" 'cd "$W" && echo data > d.txt && /usr/bin/zip -q d.zip d.txt && mkdir -p out && /usr/bin/unzip -q -o d.zip -d out && tar czf d.tgz d.txt && tar xzf d.tgz -C out'
step "download: fetch a page with curl" 'curl -s -m 10 -o "$W/page.html" http://example.com/'
step "preferences: write and read an app preference" 'defaults write com.lab.benign greeting -string hello && defaults read com.lab.benign greeting'
step "ssh key: make a key pair" 'ssh-keygen -q -t ed25519 -N "" -f "$W/key"'
step "package: build an empty installer package and install it" 'pkgbuild --nopayload --identifier com.lab.benign.pkg --version 1.0 "$W/benign.pkg" && sudo -n /usr/sbin/installer -pkg "$W/benign.pkg" -target /'
step "app: open Calculator and close it" 'open -a Calculator && sleep 4 && pkill -x Calculator'
step "launchctl: list the jobs" 'launchctl list | head -n 20'
step "python: run a one-liner" "python3 -c 'import json; print(json.dumps({\"a\": 1}))'"
step "clean up: remove what the steps made" 'rm -rf "$W"; defaults delete com.lab.benign'

if [ "$DRY" = 0 ]; then say "benign activity done: $OK steps ok, $BAD failed"; fi
exit 0
