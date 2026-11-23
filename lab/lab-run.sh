#!/bin/bash
# lab-run.sh: runs one sample (or a baseline) in a fresh pair of VMs and records eslogger for it.
#
#   lab/lab-run.sh [--manual] [--window SECONDS] [--max-bytes N] [--keep-vm] [--image NAME] FAMILY
#   lab/lab-run.sh [--image NAME] --baseline idle|benign
#
# FAMILY is a row of lab/manifest.tsv (see fetch-sample.sh for objective-see samples and fetch-bazaar.sh for MalwareBazaar; the
# row's source column picks how the zip is opened in the guest: unzip for objective-see, 7zz for bazaar). The run: clone the golden guest and the gateway, start them on the
# private cable (lab-net.py), prove the guest reaches only the gateway (check-isolation.sh), start eslogger through `tart exec`
# streaming to the host, copy the zip into the guest and unzip it there, launch it by its recipe, wait for the window, collect the
# guest's post-state and the gateway's pcap, then stop and delete both clones. Samples are never extracted or run on the host.
#
# The run folder $FICUS_LAB_DATA/runs/<name>/<run-id>/ holds capture.jsonl, meta.json, post-state/, gateway.pcap, launcher.log.
# Recipes (the manifest's fourth column): exec:<path> runs a program or script from the unzipped folder; app:<name.app> opens an
# app; pkg:<file> installs a package; dmg:<file> attaches a disk image; manual runs nothing and waits for you (see --manual).
#
#   --manual        open the guest in a window, run no recipe, wait until you press Enter
#   --window N      seconds to record after the launch (default: the manifest's, else 600)
#   --max-bytes N   stop the run if the capture passes N bytes (default 2147483648)
#   --keep-vm       leave the stopped clones in place after the run
#   --image NAME    clone this guest image instead of the default (lab-gold, or $LAB_GUEST_IMAGE): for example lab-gold-lean,
#                   the guest without the developer tools. A local VM name only. meta.json records the image used.
#   --baseline idle   record the guest alone for the window (default 600 s): the noise floor
#   --baseline benign  record the guest while guest-benign.sh does ordinary things, then the rest of the window (default 120 s)
#
# Exit 0 the run finished (a note in meta.json says if eslogger died early), 1 it failed or was aborted (the folder is still
# written), 2 usage. Environment: FICUS_LAB_DATA, LAB_MANIFEST, LAB_TART, LAB_NET, LAB_ISOLATION, LAB_GUEST_IMAGE (lab-gold),
# LAB_GW_IMAGE (lab-gw); for tests: LAB_RUN_ID, LAB_POLL, LAB_AGENT_SLEEP, LAB_ISOLATION_TRIES, LAB_ISOLATION_SLEEP,
# LAB_READY_SLEEP, LAB_STOP_SLEEP.

export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"

TART=${LAB_TART:-tart}
NET=${LAB_NET:-$HERE/lab-net.py}
ISOLATION=${LAB_ISOLATION:-$HERE/check-isolation.sh}
MANIFEST=${LAB_MANIFEST:-$HERE/manifest.tsv}
GUEST_IMAGE=${LAB_GUEST_IMAGE:-lab-gold}
GW_IMAGE=${LAB_GW_IMAGE:-lab-gw}
POLL=${LAB_POLL:-5}
DEFAULT_WINDOW=600
DEFAULT_MAX_BYTES=2147483648
SAMPLE_DIR='$HOME/Downloads/sample'   # inside the guest; single-quoted on purpose

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; }
bad_usage() { [ -n "$1" ] && echo "error: $1" >&2; usage >&2; exit 2; }

MANUAL=0; KEEP=0; WINDOW=""; MAX_BYTES=$DEFAULT_MAX_BYTES; BASELINE=""; FAMILY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --manual) MANUAL=1 ;;
    --keep-vm) KEEP=1 ;;
    --window) [ $# -ge 2 ] || bad_usage "--window needs a number of seconds"; WINDOW=$2; shift ;;
    --max-bytes) [ $# -ge 2 ] || bad_usage "--max-bytes needs a number"; MAX_BYTES=$2; shift ;;
    --image) [ $# -ge 2 ] || bad_usage "--image needs the name of a Tart VM"; GUEST_IMAGE=$2; shift ;;
    --baseline) [ $# -ge 2 ] || bad_usage "--baseline needs idle"; BASELINE=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) bad_usage "unknown option $1" ;;
    *) [ -z "$FAMILY" ] || bad_usage "one family at a time"; FAMILY=$1 ;;
  esac
  shift
done
case "$WINDOW" in *[!0-9]*) bad_usage "--window must be a whole number of seconds" ;; esac
case "$MAX_BYTES" in ''|*[!0-9]*) bad_usage "--max-bytes must be a whole number" ;; esac
# A local VM name only: a slash would make `tart clone` pull a remote image, and a leading dash would read as an option.
case "$GUEST_IMAGE" in ''|-*|*/*|*[[:space:]]*) bad_usage "--image / LAB_GUEST_IMAGE must be the name of a local Tart VM, not '$GUEST_IMAGE'" ;; esac
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }

# --- what to run ---------------------------------------------------------------------------------------------------------
SAMPLE_SHA=""; RECIPE=""; ZIP=""; SOURCE=lab
if [ -n "$BASELINE" ]; then
  [ -z "$FAMILY" ] || bad_usage "a baseline takes no family"
  case "$BASELINE" in
    idle) NAME=baseline-idle; RECIPE=none; baseline_window=$DEFAULT_WINDOW ;;
    benign) NAME=baseline-benign; RECIPE=script:guest-benign.sh; baseline_window=120 ;;
    *) bad_usage "unknown baseline '$BASELINE' (idle or benign)" ;;
  esac
  [ -n "$WINDOW" ] || WINDOW=$baseline_window
else
  [ -n "$FAMILY" ] || bad_usage ""
  ( lab_check_name "$FAMILY" ) 2>&1 || exit 2
  NAME=$FAMILY
  row=$(awk -F'\t' -v f="$FAMILY" 'NR > 1 && $1 == f { print $2 "\t" $3 "\t" $4 "\t" $5 "\t" $7; exit }' "$MANIFEST" 2>/dev/null)
  [ -n "$row" ] || { echo "error: '$FAMILY' is not in $MANIFEST (fetch it with fetch-sample.sh or fetch-bazaar.sh)" >&2; exit 2; }
  IFS=$'\t' read -r zipname SAMPLE_SHA RECIPE manifest_window SOURCE <<EOF
$row
EOF
  SOURCE=${SOURCE:-objective-see}   # a row without the column is an objective-see sample
  case "$SOURCE" in objective-see|bazaar) ;; *) echo "error: '$FAMILY' has an unknown source '$SOURCE' in the manifest (objective-see or bazaar)" >&2; exit 2 ;; esac
  ZIP="$(lab_data_dir)/samples/$zipname"
  [ -f "$ZIP" ] || { echo "error: $ZIP is not on disk (fetch it with fetch-sample.sh)" >&2; exit 2; }
  [ -n "$WINDOW" ] || WINDOW=${manifest_window:-$DEFAULT_WINDOW}
  # A row marked `manual` means "I launch it by hand", so it opens the window and waits like --manual.
  case "$RECIPE" in manual|manual:*) MANUAL=1 ;; esac
fi

# --- the run folder (never reuses one) --------------------------------------------------------------------------------------
SLUG=$(lab_slug "$NAME")
BASE="$(lab_data_dir)/runs/$SLUG"
mkdir -p "$BASE" || lab_die "cannot create $BASE"
ID=${LAB_RUN_ID:-$(lab_run_id "$NAME")}
RUN_ID=$ID; n=1
until mkdir "$BASE/$RUN_ID" 2>/dev/null; do n=$((n + 1)); RUN_ID="$ID-$n"; done
RUN_DIR="$BASE/$RUN_ID"
GUEST="run-$RUN_ID"; GW="gw-$RUN_ID"
CAPTURE="$RUN_DIR/capture.jsonl"
EVENTS=$(lab_events)
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

STATUS=failed; REASON="the run did not finish"; EARLY=false; GUEST_MACOS=unknown
CLONED_GUEST=0; CLONED_GW=0; NET_PID=""; ES_PID=""; GUEST_UP=0; COLLECTED=0

log() { printf '==> %s\n' "$*" >&2; }

write_meta() {
  local bytes=0
  [ -f "$CAPTURE" ] && bytes=$(wc -c < "$CAPTURE" | tr -d ' ')
  jq -n --arg run_id "$RUN_ID" --arg family "$NAME" --arg sha "$SAMPLE_SHA" --arg source "$SOURCE" --arg image "$GUEST_IMAGE" --arg macos "$GUEST_MACOS" \
    --arg events "$EVENTS" --arg recipe "$RECIPE" --argjson window "$WINDOW" --arg started "$STARTED" \
    --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg status "$STATUS" --arg reason "$REASON" --argjson early "$EARLY" --argjson bytes "$bytes" '
    { run_id: $run_id, family: $family, sample_sha256: $sha, source: $source, guest_image: $image, guest_macos: $macos,
      eslogger_events: ($events | split(" ")), network_mode: "fake-internet", recipe: $recipe, window_s: $window,
      started_utc: $started, ended_utc: $ended, status: $status, reason: $reason, eslogger_exited_early: $early, capture_bytes: $bytes }' \
    > "$RUN_DIR/meta.json.tmp" && mv "$RUN_DIR/meta.json.tmp" "$RUN_DIR/meta.json"
}

# fail REASON: ends the run as failed; the EXIT trap does the cleaning up.
fail() { STATUS=failed; REASON=$1; echo "error: $1" >&2; exit 1; }

stop_stream() {
  [ -n "$ES_PID" ] || return 0
  if kill -0 "$ES_PID" 2>/dev/null; then
    "$TART" exec "$GUEST" /bin/sh -c 'sudo pkill -x eslogger' >/dev/null 2>&1
    local i
    for ((i = 0; i < ${LAB_STOP_TRIES:-100}; i++)); do kill -0 "$ES_PID" 2>/dev/null || break; sleep "${LAB_STOP_SLEEP:-0.1}"; done
    if kill -0 "$ES_PID" 2>/dev/null; then pkill -P "$ES_PID" 2>/dev/null; kill "$ES_PID" 2>/dev/null; fi
  fi
  wait "$ES_PID" 2>/dev/null
  ES_PID=""
}

# Post-state from the guest and the pcap from the gateway: after eslogger has stopped, so collecting does not enter the capture.
collect_outputs() {
  [ "$COLLECTED" = 0 ] || return 0
  COLLECTED=1
  if [ "$GUEST_UP" = 1 ]; then
    mkdir -p "$RUN_DIR/post-state"
    "$TART" exec -i "$GUEST" /bin/sh -c 'cat > /tmp/guest-collect.sh' < "$HERE/guest-collect.sh" >/dev/null 2>&1
    "$TART" exec "$GUEST" /bin/sh -c 'sudo bash /tmp/guest-collect.sh' 2>/dev/null |
      awk -v dir="$RUN_DIR/post-state" '/^=== .* ===$/ { name = $2; file = dir "/" name ".txt"; next } name != "" { print > file }'
  fi
  if [ "$CLONED_GW" = 1 ] && [ -n "$NET_PID" ] && kill -0 "$NET_PID" 2>/dev/null; then
    "$TART" exec "$GW" /bin/sh -c 'sudo cat /var/lib/lab/gateway.pcap' > "$RUN_DIR/gateway.pcap" 2>/dev/null || rm -f "$RUN_DIR/gateway.pcap"
  fi
}

cleanup() {
  trap - EXIT INT TERM
  stop_stream
  collect_outputs
  if [ -n "$NET_PID" ] && kill -0 "$NET_PID" 2>/dev/null; then
    kill -TERM "$NET_PID" 2>/dev/null
    local i
    for ((i = 0; i < ${LAB_NET_TRIES:-300}; i++)); do kill -0 "$NET_PID" 2>/dev/null || break; sleep "${LAB_STOP_SLEEP:-0.1}"; done
    kill -9 "$NET_PID" 2>/dev/null
  fi
  [ -z "$NET_PID" ] || wait "$NET_PID" 2>/dev/null
  if [ "$KEEP" = 0 ]; then
    [ "$CLONED_GUEST" = 0 ] || "$TART" delete "$GUEST" >/dev/null 2>&1
    [ "$CLONED_GW" = 0 ] || "$TART" delete "$GW" >/dev/null 2>&1
  fi
  write_meta
  log "run folder: $RUN_DIR (status: $STATUS)"
  [ "$STATUS" = ok ] || exit 1
  exit 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
write_meta

# --- bring the pair up --------------------------------------------------------------------------------------------------------
log "cloning $GUEST_IMAGE and $GW_IMAGE"
"$TART" clone "$GUEST_IMAGE" "$GUEST" || fail "cloning $GUEST_IMAGE failed"
CLONED_GUEST=1
"$TART" clone "$GW_IMAGE" "$GW" || fail "cloning $GW_IMAGE failed"
CLONED_GW=1

log "starting the private cable"
net_args=(--gateway "$GW" --guest "$GUEST")
[ "$MANUAL" = 0 ] || net_args+=(--guest-window)
"$NET" "${net_args[@]}" > "$RUN_DIR/launcher.log" 2>&1 &
NET_PID=$!
ready=0
for ((i = 0; i < ${LAB_READY_TRIES:-90}; i++)); do
  if grep -q '^READY' "$RUN_DIR/launcher.log" 2>/dev/null; then ready=1; break; fi
  kill -0 "$NET_PID" 2>/dev/null || break
  sleep "${LAB_READY_SLEEP:-1}"
done
[ "$ready" = 1 ] || fail "the cable launcher did not start both VMs (see launcher.log)"

for ((i = 0; i < ${LAB_AGENT_TRIES:-90}; i++)); do
  "$TART" exec "$GUEST" /usr/bin/true >/dev/null 2>&1 && { GUEST_UP=1; break; }
  sleep "${LAB_AGENT_SLEEP:-2}"
done
[ "$GUEST_UP" = 1 ] || fail "the guest did not come up (its agent never answered)"

GUEST_MACOS=$("$TART" exec "$GUEST" /bin/sh -c 'cat /etc/lab-golden-image' 2>/dev/null | sed -n 's/^macos=//p' | head -n 1)
GUEST_MACOS=${GUEST_MACOS:-unknown}

log "checking isolation"
iso_ok=0
for ((i = 0; i < ${LAB_ISOLATION_TRIES:-20}; i++)); do
  if "$ISOLATION" "$GUEST" > "$RUN_DIR/isolation.log" 2>&1; then iso_ok=1; break; fi
  sleep "${LAB_ISOLATION_SLEEP:-3}"
done
[ "$iso_ok" = 1 ] || fail "the isolation check failed, so no sample was copied in: $(tr '\n' ' ' < "$RUN_DIR/isolation.log")"

# --- record ----------------------------------------------------------------------------------------------------------------------
log "starting eslogger"
( "$TART" exec "$GUEST" /bin/sh -c "PATH=/usr/bin:/bin:/usr/sbin:/sbin; sudo eslogger $EVENTS" 2> "$RUN_DIR/eslogger.err" |
    jq -c --unbuffered 'select(.event.close == null or .event.close.modified == true)' > "$CAPTURE" ) &
ES_PID=$!
for ((i = 0; i < ${LAB_ES_TRIES:-300}; i++)); do
  [ -s "$CAPTURE" ] && break
  kill -0 "$ES_PID" 2>/dev/null || break
  sleep 0.1
done
[ -s "$CAPTURE" ] || fail "eslogger produced nothing (see eslogger.err; does the guest's eslogger have Full Disk Access?)"

# The start marker goes in after the zip is copied and unzipped, so the harness's own unzip is before it and not part of the sample.
if [ -n "$ZIP" ]; then
  log "copying the sample in and unzipping it in the guest"
  "$TART" exec -i "$GUEST" /bin/sh -c 'cat > /tmp/sample.zip' < "$ZIP" || fail "copying the zip into the guest failed"
  if [ "$SOURCE" = bazaar ]; then
    # MalwareBazaar's zips are AES-encrypted (password "infected"), which macOS unzip cannot open: 7zz does, if the guest image has it.
    "$TART" exec "$GUEST" /bin/sh -c 'PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; command -v 7zz >/dev/null || { echo "7zz is not installed in this guest" >&2; exit 127; }; mkdir -p "$HOME/Downloads/sample" && 7zz x -y -pinfected -o"$HOME/Downloads/sample" /tmp/sample.zip >/dev/null; rc=$?; rm -f /tmp/sample.zip; exit $rc' \
      || fail "extracting the MalwareBazaar zip with 7zz failed in the guest (is 7zz installed? the lean image has none: use the main image)"
  else
    "$TART" exec "$GUEST" /bin/sh -c 'mkdir -p "$HOME/Downloads/sample" && /usr/bin/unzip -q -o -P infect3d -d "$HOME/Downloads/sample" /tmp/sample.zip; rc=$?; rm -f /tmp/sample.zip; exit $rc' \
      || fail "unzip failed in the guest (wrong password, an encryption macOS unzip cannot read, or a damaged zip)"
  fi
  "$TART" exec "$GUEST" /usr/bin/true FICUS_LAB_START "$RUN_ID" >/dev/null 2>&1
  kind=${RECIPE%%:*}; arg=${RECIPE#*:}
  if [ "$MANUAL" = 1 ]; then
    log "manual run: no recipe; the sample is in $SAMPLE_DIR inside the guest"
  else
    log "launching ($RECIPE)"
    case "$kind" in
      # A path without a slash must become ./path: nohup looks such a name up on PATH, and the sample is not there.
      exec) "$TART" exec "$GUEST" /bin/sh -c 'cd "$HOME/Downloads/sample" && case "$1" in /*) p=$1 ;; *) p=./$1 ;; esac && chmod +x "$p" && (nohup "$p" >/dev/null 2>&1 &)' _ "$arg" || fail "launching $arg failed" ;;
      app)  "$TART" exec "$GUEST" /bin/sh -c 'open "$HOME/Downloads/sample/$1"' _ "$arg" || fail "opening $arg failed" ;;
      pkg)  "$TART" exec "$GUEST" /bin/sh -c 'sudo /usr/sbin/installer -pkg "$HOME/Downloads/sample/$1" -target /' _ "$arg" || fail "installing $arg failed" ;;
      dmg)  "$TART" exec "$GUEST" /bin/sh -c 'hdiutil attach -nobrowse "$HOME/Downloads/sample/$1"' _ "$arg" || fail "attaching $arg failed" ;;
      *)    fail "unknown recipe kind '$kind' in '$RECIPE' (exec, app, pkg, dmg, manual)" ;;
    esac
  fi
else
  "$TART" exec "$GUEST" /usr/bin/true FICUS_LAB_START "$RUN_ID" >/dev/null 2>&1
  if [ "$BASELINE" = benign ]; then
    log "running the benign activity script"
    "$TART" exec -i "$GUEST" /bin/sh -c 'cat > /tmp/guest-benign.sh' < "$HERE/guest-benign.sh" || fail "copying the benign script into the guest failed"
    "$TART" exec "$GUEST" /bin/sh -c 'bash /tmp/guest-benign.sh' > "$RUN_DIR/benign.log" 2>&1 || fail "the benign script could not run (see benign.log)"
  fi
fi

if [ "$MANUAL" = 1 ]; then
  echo "The guest is running with a window. Press Enter here when you have finished." >&2
  read -r _ || true
else
  log "recording for $WINDOW seconds"
  deadline=$((SECONDS + WINDOW))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! kill -0 "$NET_PID" 2>/dev/null; then fail "the cable launcher exited during the run"; fi
    if ! kill -0 "$ES_PID" 2>/dev/null; then EARLY=true; REASON="eslogger exited early (the sample may have stopped it)"; log "$REASON"; break; fi
    size=$(wc -c < "$CAPTURE" | tr -d ' ')
    if [ "$size" -gt "$MAX_BYTES" ]; then
      STATUS=aborted-size; REASON="the capture passed $MAX_BYTES bytes"; echo "error: $REASON" >&2; exit 1
    fi
    sleep "$POLL"
  done
fi

"$TART" exec "$GUEST" /usr/bin/true FICUS_LAB_END "$RUN_ID" >/dev/null 2>&1
STATUS=ok
[ "$EARLY" = true ] || REASON=""
