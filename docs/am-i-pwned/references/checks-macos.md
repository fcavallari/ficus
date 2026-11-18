# macOS checks (read-only, no sudo)

`../mac-triage.sh` runs all of these in one go and writes one report file; this page is what each check is for and how to read it, and what to run by hand when the script cannot. Run these as the person, in the order of the skill. If a command prints a permission error, say you could not check it; if it needs elevation, give the person the command to run themselves. Never put `sudo` in front of anything yourself.

Contents: [1 Posture](#1-posture) · [2 Accounts](#2-accounts) · [3 Persistence](#3-persistence) · [4 Processes](#4-processes) · [5 Network](#5-network) · [6 Privacy grants](#6-privacy-grants) · [7 Browser](#7-browser) · [8 Recent change](#8-recent-change) · [Resolving a binary](#resolving-a-binary)

Why these locations: they come from how current Mac stealers and backdoors actually persist and hide (ClickFix-delivered AMOS, MacSync and similar, DPRK-linked Contagious Interview droppers, XCSSET, and older families). A check only earns a place here if its result can be read without opening a secret.

## 1. Posture

```bash
sw_vers
fdesetup status
csrutil status
spctl --status
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString
sysadminctl -screenLock status
```

The security settings malware and adware change (software and security updates, XProtect age, Gatekeeper, quarantine, boot arguments, library validation, launchd, authorization rights) are read by `mac-triage.sh` and explained in `security-settings.md`. By hand, the commands are in that page's table.

An EDR or AV that should be running: look for it in `launchctl list` and `ps` (for example CrowdStrike, SentinelOne, Jamf Protect, Defender). Security controls that are off and the person does not know why are an escalation row.

## 2. Accounts

```bash
dscl . -list /Users UniqueID | awk '$2 == 0 || $2 >= 500'
dscl . -read /Groups/admin GroupMembership
for u in $(dscl . -list /Users UniqueID | awk '$2 >= 500 {print $1}'); do echo "$u hidden=$(dscl . -read /Users/$u IsHidden 2>/dev/null | awk '{print $2}')"; done
last -30
launchctl list | grep -i -E 'sshd|screensharing|ard|smbd|remotemanagement'
```

`systemsetup -getremotelogin` needs admin: hand it to the person if you need Remote Login state. A new admin user, a hidden user, or UID 0 other than root: always escalate.

## 3. Persistence

Enumerate, then resolve each entry to a binary (see "Resolving a binary").

```bash
# Loaded jobs that are not Apple's
launchctl list | grep -v -E 'com\.apple\.'

# Plists in the three launch folders: names and mtimes first
ls -la /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents 2>/dev/null

# For each plist worth a look: what it runs. Not `plutil -p | grep Program`: that prints the line `ProgramArguments => [`
# and none of the entries under it, so the program never shows. Extract the keys; `raw` on an array prints its length.
# Only the first two entries are read (the program, and its first argument such as `-c`): later arguments can hold tokens.
for k in Label Program ProgramArguments ProgramArguments.0 ProgramArguments.1 RunAtLoad KeepAlive; do
  printf '%s: ' "$k"; plutil -extract "$k" raw -o - "<plist>" 2>/dev/null || echo '-'
done

# Login items and background items (may need elevation; if so, give the command to the person)
sfltool dumpbtm

# cron, at, periodic, emond, login hooks, sudoers, PAM
# crontab: line count, and only the suspicious keywords with line numbers; a cron line can hold a token
crontab -l | wc -l; crontab -l | grep -n -o -E 'curl|wget|base64|eval|osascript|nc |/tmp/'
ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly /etc/emond.d/rules 2>/dev/null
defaults read com.apple.loginwindow LoginHook 2>/dev/null; defaults read com.apple.loginwindow LogoutHook 2>/dev/null
ls -la /etc/sudoers.d; find /etc/pam.d -type f -mtime -30 2>/dev/null

# Profiles, system extensions, kernel extensions
profiles status -type enrollment
systemextensionsctl list
kmutil showloaded --list-only --no-kernel-components 2>/dev/null

# Shell rc injections: print only the matching keyword and line number, never the line
grep -n -o -E 'curl|wget|base64|eval|osascript|nohup|python|perl|ruby|nc |/tmp/' ~/.zshrc ~/.zshenv ~/.zprofile ~/.bash_profile ~/.bashrc 2>/dev/null

# Git hooks pointed somewhere else (a path, not a secret)
git config --global --get core.hooksPath
```

Things to look for, each from real intrusions:

- **Apple-looking labels in the wrong place.** A `com.apple.*` plist in `~/Library/LaunchAgents` (Apple never ships there), or in `/Library/Launch*` whose program is not under `/System`, `/usr/libexec` or `/Library/Apple`. Also look-alike names such as `com.finder.helper.plist`, `com.apple.softwareupdate.helper`, `com.apple.xsprinter`. The plist file name and its `Label` can differ; check both.
- **Persistence that runs an interpreter or a loose file**: `ProgramArguments` that start with `sh`, `bash`, `zsh`, `python`, `osascript`, `node`, `perl`, `ruby`, or that point into `/tmp`, `/var/folders`, `/Users/Shared`, `~/Downloads`, `~/Library/Caches`, a hidden folder, or a loose binary directly in the home folder.
- **Hidden executables in the home folder and cache folders**, where stealers drop their agents (`~/.helper`, `~/.agent`, `~/.mainhelper`, `~/.pass`, `~/.zx_*`, hidden folders under `~/Library/Application Support`):

```bash
find ~ -maxdepth 2 -name '.*' -type f -perm +111 ! -path '*/.git/*' ! -path '*/node_modules/*' 2>/dev/null
find /Library/Caches ~/Library/Caches -maxdepth 3 -type f -perm +111 2>/dev/null | head -50
find /tmp /var/tmp -maxdepth 2 -type f -perm +111 2>/dev/null
```

- **Shell rc lines that fetch or decode**: any `curl`, `base64`, `eval` or `osascript` hit in a rc file is a lead. Tell the person the line numbers; they read the lines.
- **login hooks, emond rules, periodic scripts, `/etc/pam.d` and `/etc/sudoers.d` changes**: rare in real malware today but always worth escalating when present and unexplained.

## 4. Processes

```bash
# Path only, never arguments (arguments can hold tokens)
ps -axo pid,ppid,user,etime,comm

# From odd places: temp, cache, Downloads, Trash, hidden folders
ps -axo pid,ppid,user,etime,comm | grep -E '/tmp/|/var/folders/|/Downloads/|/\.Trash/|/\.[^/]+/' 

# Browsers or Electron apps launched with remote debugging (a stealer technique); print only the flag.
# This is the one place full command lines pass through a pipe, and `grep -o` keeps only the flag: never run
# `ps -axo command` on its own.
ps -axo command | grep -o -E -- '--remote-debugging-port=[0-9]+'
```

Signatures of the programs that are running. `mac-triage.sh` does this for every program outside the system folders and the launch items' programs; by hand, resolve a suspect with `codesign -dv --verbose=4` (see *Resolving a binary*). The signature is read, not verified, and a revoked certificate cannot be seen offline, so a signed program is not thereby safe (3CX, ChillyHell and others were signed). The labels the script puts on an ad-hoc or unsigned program:

| Label | Means | What to do |
| --- | --- | --- |
| `LOOK` | Ad-hoc or unsigned, and running from temp, Downloads, `/Users/Shared`, `/Volumes`, App Translocation or a hidden folder buried under a visible one; or its signing ID claims `com.apple.*` without being Apple platform code | Level 2 of the verdict rule (*Process from an unusual path*, *Signing mismatch*). A claimed Apple identifier on a non-platform binary is the *Always* row for `com.apple.*` items |
| `CHECK` | A `com.apple.*` signing ID under a developer team | Apple signs a few apps this way (Xcode, iWork, GarageBand): compare the team with Ficus's `APPLE_TEAM_IDS` in `src/rules/rules.ts` (some are unverified), and say what you could not confirm |
| `context` | Ad-hoc in developer tooling: Homebrew, `~/.cache`, `.cargo`, virtualenvs, `node_modules`, VS Code extensions | Normal on a developer Mac; a finding only next to something else |
| `note` | Ad-hoc elsewhere (for example an extension's helper under Application Support) | Ask whether the person installed it |

Note a process whose binary was deleted from disk (the `comm` path no longer exists: `ls` it). For any suspect, resolve the binary (below) and look at its parent chain (`ps -o ppid=` repeatedly). An interpreter (`python`, `osascript`, `bash`, `curl`, `node`) with a parent you cannot explain is the strongest process signal: it is what a pasted ClickFix command, a malicious VS Code or Xcode project, or a Script Editor applet leaves behind.

## 5. Network

```bash
lsof -nP -iTCP -sTCP:LISTEN
lsof -nP -iTCP -sTCP:ESTABLISHED
scutil --dns | grep -E 'nameserver|search' | sort -u
scutil --proxy
grep -v -E '^#|^$' /etc/hosts
ls -la /etc/resolver 2>/dev/null
```

`lsof` as the user only shows the user's own processes; say so. Listeners on `0.0.0.0` the person did not configure, anything on 22/5900/3389 with remote access off, and raw-IP long-lived connections from a process that should not talk out are the rows to escalate.

## 6. Privacy grants

```bash
sqlite3 -readonly ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select service, client, auth_value, datetime(last_modified,'unixepoch') from access where auth_value=2 order by last_modified desc"
```

Needs Terminal to have Full Disk Access; otherwise say you could not check. Focus on `kTCCServiceAccessibility`, `kTCCServiceScreenCapture`, `kTCCServiceSystemPolicyAllFiles`, `kTCCServiceListenEvent` (Input Monitoring), `kTCCServiceAppleEvents`, camera and microphone, and on a recent `last_modified`. Ask the person whether they plausibly granted each.

## 7. Browser

IDs and names only, never settings or storage.

```bash
for d in ~/Library/Application\ Support/Google/Chrome/*/Extensions; do echo "$d"; ls "$d"; done 2>/dev/null
ls ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts ~/Library/Application\ Support/Mozilla/NativeMessagingHosts 2>/dev/null
```

An extension name is often `__MSG_name__`; the ID is what to compare against the Chrome Web Store. An unexpected native-messaging host (a host that lets an extension run a local program) is worth escalating. Repeat for Edge, Brave, Arc and Firefox if installed.

## 8. Recent change

```bash
find /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents /etc/periodic /etc/emond.d -type f -mtime -14 2>/dev/null
# Download and quarantine events: app name and time only, never the URL
sqlite3 -readonly ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "select LSQuarantineAgentName, datetime(LSQuarantineTimeStamp+978307200,'unixepoch') from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 40"
```

## Resolving a binary

```bash
codesign -dv --verbose=4 "<path>" 2>&1 | grep -E 'Identifier|TeamIdentifier|Authority|flags|Signature|Platform'
spctl --assess --type execute --verbose "<path>" 2>&1
```

Judge by what cannot be chosen (see SKILL.md): `Platform identifier`, `TeamIdentifier`, and the `Authority` chain, not the `Identifier` string. Ad-hoc is context; ad-hoc plus an Apple-looking name, hidden path or temp path is a finding. Apple signs its non-platform apps with more than one team, and the list is not complete: Ficus keeps the ones it has seen in `APPLE_TEAM_IDS` (`src/rules/rules.ts`), where `59GAB85EFG` (the developer-tools team) is marked unverified and the others were read from iWork, GarageBand and iMovie. Compare with that list, and treat a `com.apple.*` identifier under a team not on it as unconfirmed, not as proven spoofing: say what you saw, and let Security Ops decide. A real Apple *platform* binary shows `Platform identifier` and needs no team.
