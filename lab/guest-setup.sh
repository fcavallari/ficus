#!/bin/bash
# guest-setup.sh: prepares a Tart macOS guest to become the lab's golden image. Run it INSIDE the guest, as the admin user.
#
#   lab/guest-setup.sh [--dry-run | --bait-only | --skip-rosetta]
#   lab/guest-setup.sh --help
#
# It installs Rosetta, sets the clock to UTC, turns off sleep, Spotlight indexing and automatic updates, plants fake
# "bait" (browser profiles, keychain entries, wallets, dotfiles) for stealers to find, and writes /etc/lab-golden-image.
# Every bait file carries the text LAB-BAIT. None of it is real. Safe to run twice.
#
# It refuses to run anywhere that is not a virtual machine: it changes system settings and writes into the login keychain.

export LC_ALL=C
SCRIPT_VERSION=1
DRY=0; BAIT_ONLY=0; SKIP_ROSETTA=0; FAILED=0

usage() {
  cat <<'EOF'
Usage: guest-setup.sh [--dry-run | --bait-only | --skip-rosetta]

Run inside the Tart guest as the admin user (passwordless sudo needed). The guest needs internet for Rosetta, so run
this before moving it to the fake network.

  --dry-run       print what would happen; change nothing
  --bait-only     only plant the bait files in $HOME (no sudo, no keychain, no system settings)
  --skip-rosetta  leave Rosetta alone (no internet needed)

It refuses to run on a real Mac. Afterwards: shut the guest down, then `tart rename` it to lab-gold.
EOF
}

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; FAILED=1; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# act DESCRIPTION CMD...: runs CMD (or only prints it under --dry-run); a failure is a warning, not an exit.
act() {
  local desc=$1; shift
  if [ "$DRY" = 1 ]; then say "would: $desc"; return 0; fi
  if "$@" >/dev/null 2>&1; then say "ok:    $desc"; else warn "$desc failed: $*"; fi
}

is_vm() {
  [ "${FICUS_LAB_ASSUME_VM:-}" = 1 ] && return 0
  [ "$(uname)" = Darwin ] || return 1
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in *VirtualMac*) return 0 ;; esac
  return 1
}

# bait_file PATH CONTENT: writes a small text file marked LAB-BAIT, never overwriting an existing one.
bait_file() {
  local p=$1 body=$2
  if [ "$DRY" = 1 ]; then say "would: bait $p"; return 0; fi
  if [ -e "$p" ]; then say "skip:  $p exists"; return 0; fi
  mkdir -p "$(dirname "$p")" && printf '%s\n' "$body" > "$p" && say "ok:    bait $p" || warn "bait $p failed"
}

# bait_sqlite PATH SQL: creates a small SQLite file from SQL, never overwriting an existing one.
bait_sqlite() {
  local p=$1 sql=$2
  if [ "$DRY" = 1 ]; then say "would: bait $p"; return 0; fi
  if [ -e "$p" ]; then say "skip:  $p exists"; return 0; fi
  if ! command -v sqlite3 >/dev/null 2>&1; then warn "sqlite3 missing, skipped $p"; return 0; fi
  mkdir -p "$(dirname "$p")" && sqlite3 "$p" "$sql" && say "ok:    bait $p" || warn "bait $p failed"
}

plant_bait() {
  local h=$HOME app="$HOME/Library/Application Support"
  local chrome="$app/Google/Chrome/Default"
  bait_sqlite "$chrome/Login Data" "CREATE TABLE logins(origin_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER); INSERT INTO logins VALUES('https://bank.example.invalid/','lab-user@example.invalid',CAST('v10LAB-BAIT' AS BLOB),0); INSERT INTO logins VALUES('https://mail.example.invalid/','lab-user@example.invalid',CAST('v10LAB-BAIT' AS BLOB),0);"
  bait_sqlite "$chrome/Cookies" "CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB); INSERT INTO cookies VALUES('.example.invalid','session','LAB-BAIT',CAST('v10LAB-BAIT' AS BLOB));"
  bait_sqlite "$chrome/Web Data" "CREATE TABLE autofill(name TEXT, value TEXT); INSERT INTO autofill VALUES('email','lab-user@example.invalid'); CREATE TABLE credit_cards(name_on_card TEXT, card_number_encrypted BLOB); INSERT INTO credit_cards VALUES('LAB-BAIT',CAST('v10LAB-BAIT' AS BLOB));"
  bait_file   "$app/Google/Chrome/Local State" '{"lab":"LAB-BAIT","os_crypt":{"encrypted_key":"LAB-BAIT"}}'
  local ff="$app/Firefox/Profiles/lab.default"
  bait_sqlite "$ff/key4.db" "CREATE TABLE metaData(id TEXT, item1 BLOB); INSERT INTO metaData VALUES('LAB-BAIT',CAST('LAB-BAIT' AS BLOB));"
  bait_sqlite "$ff/cookies.sqlite" "CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT); INSERT INTO moz_cookies VALUES('.example.invalid','session','LAB-BAIT');"
  bait_file   "$ff/logins.json" '{"logins":[{"hostname":"https://mail.example.invalid","encryptedUsername":"LAB-BAIT","encryptedPassword":"LAB-BAIT"}],"nextId":2}'
  bait_file   "$app/Exodus/exodus.wallet/seed.seco" "LAB-BAIT: not a wallet"
  bait_file   "$app/Electrum/wallets/default_wallet" '{"lab":"LAB-BAIT: not a wallet"}'
  bait_file   "$app/atomic/Local Storage/leveldb/000003.log" "LAB-BAIT: not a wallet"
  bait_file   "$h/.aws/credentials" "[default]
# LAB-BAIT: made-up values
aws_access_key_id = LABBAITNOTAREALKEY
aws_secret_access_key = LAB-BAIT-not-a-real-secret"
  bait_file   "$h/.ssh/id_lab_bait" "LAB-BAIT: not a private key"
  bait_file   "$h/.zsh_history" ": 1700000000:0;ssh deploy@example.invalid
: 1700000010:0;echo LAB-BAIT"
  bait_file   "$h/Documents/passwords.txt" "LAB-BAIT: example.invalid / lab-user / not-a-real-password"
  bait_file   "$h/Documents/recovery phrase.txt" "LAB-BAIT: not a real recovery phrase"
  bait_file   "$h/Desktop/notes.txt" "LAB-BAIT: lunch at 12"
}

# The login keychain entries stealers ask `security` for. Needs an unlocked login keychain (the auto-login session).
plant_keychain() {
  if [ "$DRY" = 1 ]; then say "would: add fake login-keychain items (Chrome Safe Storage, lab-fake-service)"; return 0; fi
  security find-generic-password -s "Chrome Safe Storage" >/dev/null 2>&1 \
    || security add-generic-password -a Chrome -s "Chrome Safe Storage" -w "LAB-BAIT-fake-safe-storage-key" >/dev/null 2>&1 \
    || warn "could not add Chrome Safe Storage (is the login keychain unlocked? run this from the guest's desktop Terminal)"
  security find-generic-password -s "lab-fake-service" >/dev/null 2>&1 \
    || security add-generic-password -a lab-fake -s "lab-fake-service" -w "LAB-BAIT-not-a-real-password" >/dev/null 2>&1 \
    || warn "could not add lab-fake-service"
  say "ok:    keychain bait present (checked or added)"
}

system_setup() {
  if [ "$DRY" = 0 ]; then sudo -n true 2>/dev/null || die "passwordless sudo is needed (sudo -n true failed)"; fi
  if [ "$SKIP_ROSETTA" = 1 ]; then say "skip:  Rosetta (--skip-rosetta)"
  elif [ "$DRY" = 0 ] && [ -x /Library/Apple/usr/libexec/oah/libRosettaRuntime ]; then say "skip:  Rosetta already installed"
  else act "install Rosetta (needs internet)" sudo softwareupdate --install-rosetta --agree-to-license; fi
  if [ "$DRY" = 1 ]; then say "would: set time zone UTC"
  elif sudo systemsetup -settimezone UTC >/dev/null 2>&1 || sudo ln -sf /var/db/timezone/zoneinfo/UTC /etc/localtime; then say "ok:    time zone UTC"
  else warn "time zone not set"; fi
  act "never sleep" sudo pmset -a sleep 0 displaysleep 0 disksleep 0
  act "no screen saver" defaults -currentHost write com.apple.screensaver idleTime -int 0
  act "Spotlight indexing off" sudo mdutil -a -i off
  local k
  for k in AutomaticCheckEnabled AutomaticDownload AutomaticallyInstallMacOSUpdates CriticalUpdateInstall ConfigDataInstall; do
    act "software update $k off" sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate "$k" -bool false
  done
  plant_keychain
  if [ "$DRY" = 1 ]; then say "would: write /etc/lab-golden-image"; return 0; fi
  printf 'script_version=%s\nsetup_utc=%s\nmacos=%s\nbuild=%s\n' "$SCRIPT_VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$(sw_vers -productVersion)" "$(sw_vers -buildVersion)" | sudo tee /etc/lab-golden-image >/dev/null \
    && say "ok:    wrote /etc/lab-golden-image" || warn "could not write /etc/lab-golden-image"
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY=1 ;;
      --bait-only) BAIT_ONLY=1 ;;
      --skip-rosetta) SKIP_ROSETTA=1 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
    shift
  done
  if [ "$DRY" = 0 ] && ! is_vm; then die "this is not a virtual machine; refusing to change system settings or the keychain. Use --dry-run to look."; fi
  if [ "$BAIT_ONLY" = 0 ]; then system_setup; fi
  plant_bait
  if [ "$FAILED" = 1 ]; then say "Finished with warnings (see above)."; exit 1; fi
  say "Done. Next: shut the guest down, then run tart rename on it to lab-gold."
}

if [ -z "${FICUS_LAB_SOURCE_ONLY:-}" ]; then main "$@"; fi
