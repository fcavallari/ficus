# Ficus

Ficus: a macOS process tree viewer for eslogger captures that follows every root, not just the parent PID.

A single-file web app for triaging Apple `eslogger` captures, and Mac Monitor traces exported from it. You drop a capture onto it; it rebuilds the process tree, flags suspicious processes with plain-language, MITRE-tagged explanations, and gives you a queue to confirm or dismiss them. Verdicts are kept per session (one investigation, usually one Mac) in the browser's IndexedDB, so they survive closing the tab. Everything runs locally: the page ships with a Content-Security-Policy of `connect-src 'none'`, so it cannot send a capture anywhere.

## Why “Ficus”?

The name comes from the gameleira ([*Ficus gomelleira*](https://en.wikipedia.org/wiki/Ficus_gomelleira)), a Brazilian fig tree known for its aerial roots. They drop from its branches, reach the ground and thicken into new trunks, until it’s hard to tell which trunk the tree started from.

Process trees on macOS work the same way. A plain ppid view says almost everything descends from launchd, but the real lineage runs through several connections: the original parent, the responsible process, XPC services, exec chains. Ficus follows all of those roots, so you can see where a process actually came from, not just the parent the OS reports.

The name is also a nod to its creator’s Brazilian roots. The gameleira grows across Brazil and is a sacred tree in Afro-Brazilian traditions. The project was first called Gameleira, after the tree’s Portuguese name; it took the genus name, Ficus, to be easier to say.

## Running it

The quickest way is the hosted copy: **https://fcavallari.github.io/ficus/**. It is the same single file, rebuilt from `main` on every push. The Content-Security-Policy travels inside the page, so it still cannot send a capture anywhere; GitHub only serves the file. Sessions saved there stay in that browser, under the `fcavallari.github.io` origin, which every GitHub Pages project of this account shares.

To run it yourself, build once, then serve the result on localhost:

```
npm install
npm run build        # writes dist/index.html, a single self-contained file
npm run serve        # vite preview, http://localhost:4173
```

This is the way that has been tested: the measurements below were taken over HTTP, with sessions persisting in IndexedDB.

You can also open `dist/index.html` straight from Finder (double-click, or Open With a browser). That should work, since the page needs no server, but it has not been verified in every browser. If your browser does not keep sessions when the page is opened from disk (they are gone after you quit and reopen it), use `npm run serve`. Browsers may also give every `file://` page one shared storage origin.

Sessions are stored per origin, so a session made at `file://` is not visible at `http://localhost:4173` or on the hosted copy, and the other way round. Use one and stick to it. Parsed captures are not stored; after reopening a session, re-drop the capture file and your verdicts reattach to it. In Chrome, Edge and other Chromium browsers the session remembers where each capture came from instead, so *Reload all captures* (or *Reload* beside one capture) reads them again. A web page never sees a file's path: what is remembered is the browser's handle to the file, kept in this browser's IndexedDB and not in saved session files. After a browser restart, Chrome asks again for access to each file; a file that was moved or deleted is named, and has to be added again. Safari and Firefox give no handles, so there captures are re-added by hand.

A capture is identified by its first 200 complete lines (plus the first event's sequence number and time), so a capture that is still growing keeps its verdicts when you drop it again later. A capture shorter than 200 complete lines can change identity as it grows: until it has 200 lines, a longer version of the file counts as a new capture. A pretty-printed export (see Mac Monitor below) is identified by its first 200 records instead, since each record spans many lines.

Loaded captures stay in memory up to 300 MB of input file size per page; the least recently used one is dropped first (never the one on screen) and shows “Re-add <file> to continue”. Its verdicts are kept.

## Capturing

Run this on the Mac you are investigating, stop it with Ctrl-C, then drop `capture.jsonl` into a session:

```
sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

- `exec` and `fork` build the tree; `exit` gives process lifetimes.
- `create` and `rename` show what a process wrote (a launch agent plist, a download, an archive). `setextattr` records extended-attribute writes on files (shown under “What it did” in the detail pane). No rule uses them yet; a future rule could check whether a downloaded file got its quarantine flag.
- `btm_*` captures persistence registrations (login items, launch agents and daemons).
- `write` is left out on purpose because it is very noisy; the tool still handles it if it is present.
- Needs `eslogger` schema version 11 for the checks that read a process's stdin, such as `shell-from-pipe`. Older captures load, and the header says which checks may not apply.

### Cleaning a capture before it leaves the Mac

A raw capture holds the account's names, file and folder names, hosts, command lines, environment variables and sometimes secrets. If the Mac belongs to someone else, such as an executive, the capture should not leave it as it is. `scripts/ficus-clean.sh` replaces the identifying values with placeholders and keeps what the rules and the investigator need. It needs only what macOS 15 and later has (bash and `/usr/bin/jq`). The findings stay the same: a test runs the rule engine on a capture and on its cleaned copy and compares them.

Two commands. `record` runs `sudo eslogger` and cleans the stream as it comes, so the raw capture is never written to disk. Run it as yourself, not under `sudo`: the script refuses to run as root and asks for your password once, for its own `sudo`. `clean` cleans a capture you already have.

```bash
scripts/ficus-clean.sh record -o capture.cleaned.jsonl -t 600 -D example.com
scripts/ficus-clean.sh clean -i capture.jsonl -o capture.cleaned.jsonl -D example.com
```

- `-o FILE` is the cleaned capture (`-` for standard output; the default is `capture.cleaned.jsonl` in the current folder).
- `-D DOMAIN` is the company's own domain. Hosts under it are treated as internal. Repeat it for more domains.
- `-S SEEDFILE` lists more values to clean, one per line: a kind, a tab, then the value. The kinds are `user`, `realname`, `name`, `volume`, `host`, `email`, `seed` and `data`.
- `-k KEYFILE` is where the real values are kept (see "The key" below). An existing key is loaded first and added to, so several captures of one Mac share placeholders (`user1` is the same person in each). Without `-k` the key is named after the output file, and it must not exist yet: running again with the same `-o` fails until you pass `-k` or choose another `-o`. With `-o -` the default key is `stdout.key.tsv`. The key can never be the output or the input file, however the path is written.
- `-t SECONDS` (`record` only) stops the recording after that long. Ctrl-C (or `Ctrl-\`) stops it too.

`clean -i` reads a JSONL capture, a pretty-printed export or a JSON array, and always writes JSONL. `-i -` reads standard input. It never changes or deletes the raw file. Delete that yourself when you are happy with the result.

**What is replaced.**

- Account short names (`user1`), full names (`Person 1`), and the names of files, folders and volumes under home folders, `/Users/Shared`, `/Volumes` and the temporary folders (`name1`, `vol1`; a leading dot and a short extension stay). The path segments of a URL are cleaned the same way, and so is the path of a git remote written `git@host:org/repo.git`. User info in a URL is removed. The same name gets the same placeholder in every path, argument and text, `curl -d @file` and `-F name=@file` included (the `@` stays).
- Email addresses (`person1@example.invalid`), and internal hosts (`host1.internal.invalid`): private and link-local addresses, `.local`, `.internal`, `.corp`, `.lan` and `.home.arpa` names, hosts under a `-D` domain, and this Mac's own host names. Public hosts are kept as evidence.
- Recognised credentials become `<redacted>` and are never written to the key: passwords after `dscl -authonly`, `security -w`, `curl -u` and `Authorization` or `Cookie` headers, options named like a password, token, secret or API key with one dash or two (`--password`, `--db-password`, `-password`, `-adminPassword`, `-apiKey`; not `-password -`, which reads it from standard input), the user info of `//user:password@host/share` (as `mount_smbfs` takes it), secret-looking `NAME=value` entries, and AWS, GitHub, Slack, `sk-` and JWT shapes. Environment values are `<redacted>` too, except a few such as `PATH`, `HOME` and `DYLD_*`.
- Data the cleaner cannot judge becomes `data1`, `data2` and so on, with the real value in the key: `curl -d` request bodies, the values of `curl -H` and `wget --header` headers (the header's name stays: `X-Deal: data2`), URL query values (`?id=data1`) and long encoded runs (32 or more characters of base64 or hex). So you can still recover a payload by looking it up on the Mac.
- This Mac's accounts (uid 500 and up), their full names, its computer, local host and host names, serial number and hardware UUID are read as seeds and cleaned wherever they appear, unless `FICUS_CLEAN_NO_LOCAL_SEEDS=1` is set. Cleaning a capture from another Mac warns that names outside paths are only caught with `-S`.

**What is kept.** The rules decide by program name, so the file name of every program and script that ran stays (`python3`, `curl`, a dropper's name), and so do the standard home folders (`Desktop`, `Documents`, `Downloads`, `Library`), the structure folders under `~/Library`, tooling folders such as `node_modules`, `.app` and other bundle names, `com.apple.*` and other bundle IDs, and system paths like `/usr` and `/System`. Words the rules look for, such as `display dialog`, `Chrome Safe Storage`, `launchctl load` and `-authonly`, stay too. In those places a name is kept even when it is the same word as an account name. The summary lists any account name that is short or a common word.

**The key.** The key file holds the real values: names, request bodies, payloads, anything that became `dataN`. It is as sensitive as the raw capture. By default it is `~/Library/Application Support/Ficus/keys/<name of the output>.key.tsv`, readable by you only, and deliberately not next to the capture, so copying the capture's folder does not take it along. Keep it on the Mac. Do not send it with the capture. If you delete it, the cleaning cannot be undone, which is a choice you can make once the investigation is over. Keys made before the project was renamed Ficus are in `~/Library/Application Support/Gameleira/keys/`; pass one with `-k` to reuse it.

**What a cleaned capture can still hold.** The cleaner replaces what it can recognise. These stay as they were, apart from account names, seeds and names already mapped elsewhere in the capture:

- Free text: commit messages, search terms and globs (`mdfind`, `find -name '*Falcon*'`, `grep -r 'Project Falcon'`), dialog and spoken text. Run from a home or another cleaned folder, a whole argument with a space in it becomes a name; elsewhere it stays.
- Other people's logins and names: `sudo -u jane`, `ssh jane@host`, a colleague's name in text. Only this Mac's accounts and full names, and `-S` seeds, are known.
- Public hosts, SaaS tenant hosts among them (`acme.sharepoint.com`, `acme.slack.com`), unless they are under a `-D` domain.
- Names in system and app places: under `/opt`, `/Library/Application Support/<vendor>/…` and other app folders, bundle IDs and launchd labels (`com.acme.falcon.plist`), and environment variable names (`ACME_FALCON_BUCKET`).
- A script's positional arguments (`map_drives.sh / jdoe smb_user SmbPass123`).
- Passwords passed by position or by a one-letter option to tools the cleaner has no table for, such as `networksetup -setairportnetwork en0 Net Passw0rd`, `htpasswd -b file user Passw0rd`, `pwpolicy -p`, `defaults write … Password …` and `launchctl setenv NAME value`, a password piped to `sudo -S` (`echo Passw0rd | sudo -S …`), `wget --post-data` bodies, and the subject and body of a `mailto:` link.

A cleaned capture is pseudonymized, not anonymous. A hand-picked name or a public host can still point to one person or one company, and a value the cleaner does not recognise stays as it was. Read the cleaned file before it goes anywhere.

**Things to know about `record`.**

- It needs ordinary admin `sudo` rights. It runs one `sudo -n /bin/bash -c '<wrapper>'` that starts `eslogger` and stops it through a private pipe. So a sudoers rule that allows only `eslogger` will refuse it, and an endpoint tool may flag a root inline shell. Stopping never asks for a password, and a closed terminal or a killed script also stops `eslogger`. Like `eslogger` itself it needs Full Disk Access for the terminal.
- It asks for your password once (`sudo -v`) and then needs `sudo -n` to work without asking, right after. On a Mac whose sudoers ask every time (`Defaults timestamp_timeout=0`), it cannot start: `sudo -n` refuses (sudo prints its own reason), and the script ends with `ficus-clean: eslogger stopped before recording anything (see above; does the terminal have Full Disk Access?)` and exit status 1, leaving no capture or key behind. `sudo -v && sudo -n true && echo ok` tells you beforehand: it prints `ok` when `record` can start.
- Ctrl-C may take up to about 5 seconds to stop `eslogger`. If `eslogger` ended on SIGTERM, a cut last line can be counted under `unreadable lines dropped` in the summary.
- The config and seed files, which hold the names being hidden, are deleted from `$TMPDIR` as soon as they are read, before the first event; while recording, `$TMPDIR/ficus-clean.*` holds only pipes and empty files. If the script is force-killed (`kill -9`), those are left behind (nothing in them); delete `$TMPDIR/ficus-clean.*` afterwards.
- At the end a summary is printed on standard error: events in and out, lines dropped as unreadable, events Endpoint Security dropped (gaps in `global_seq_num`), placeholders per kind, credentials replaced, and where the capture and the key are.

### Learning lab

`scripts/ficus-lab.sh` writes a capture for learning what Ficus flags, with an answer key beside it.

```
scripts/ficus-lab.sh synthetic     # hand-built, every rule, no noise; safe on any machine
scripts/ficus-lab.sh live          # harmless attack steps on this Mac, recorded by sudo eslogger
```

- **synthetic** builds the capture by hand (an invented user `learner`, invented pids, fixed times) in plain bash. It tells the story of a fake installer that drops a stealer agent, and around it shows every rule at least once, plus the queue's `in chain`, `recon burst`, context-only findings and a launch item with no process. The output is the same on every run; a test checks it against the rule engine.
- **live** runs harmless versions of the same steps as you while `sudo eslogger` records for about a minute, so the steps sit among the real background noise of a Mac. Only `eslogger` runs under sudo, and the terminal needs Full Disk Access. It shows a dialog (type anything, or wait), writes a launch agent (`com.ficus.lab`, runs `exit 0`) and removes it at the end; macOS will likely show a "Background Items Added" notification. Everything else happens in a temporary folder under `/tmp` that is removed at the end, also on Ctrl-C. Nothing real is touched: the keychain lookup asks for an item that does not exist, the password check names an account that does not exist, and `csrutil disable` is refused outside Recovery. A few rules cannot be set off this way (an unsigned binary, a setuid-root copy, the settings changes an admin could actually make); the answer key lists them. The capture holds every process's environment and your user name, so review it before sharing it.
- Both write `scratch/ficus-lab-<mode>.jsonl` and `scratch/ficus-lab-<mode>.answers.tsv` (`-o FILE` to choose; `synthetic --stdout` prints the capture, `--answers` prints only the key). The key has one row per expected finding: `step`, `rule`, `severity`, `queue` (`queued`, `in-chain`, `burst`, `context` or `item`), a `marker` to find the process by (a piece of its command line, or a launch item's plist), and a note on what the step imitates. In a live capture, find `ficus-lab.sh` in the Tree first: every step runs under it.

### Mac Monitor traces

A trace exported from [Mac Monitor](https://github.com/redcanaryco/mac-monitor) 3.0 or later (Export telemetry, or `macmonitor stream ... > trace.jsonl`) loads like an `eslogger` capture: Mac Monitor writes `eslogger`'s JSON with its own enrichments beside it, and Ficus reads the `eslogger` keys and ignores the rest. Both the JSONL export and the pretty JSON export load, and so does a JSON array of events. A file whose first line is only `{`, or which starts with `[`, is read object by object; anything else is read line by line.

- Subscribe to at least `fork`, `exec` and `exit`, and to `create`, `rename` and `btm_launch_item_add` for the persistence rules.
- Mac Monitor's mute set, filters and dropped events leave gaps: a process whose `fork` or `exec` was muted shows up without its parent, as it would in an `eslogger` capture that missed it.
- Mac Monitor numbers the messages of each of its Endpoint Security clients separately, so its sequence numbers do not give one order across a trace. Ficus orders a Mac Monitor trace by `mach_time` instead.
- Mac Monitor's enrichments (its indicators, script contents, `launched_by_parent`) are not shown yet.
- Exports from before 3.0 may not follow `eslogger`'s layout. Open them in Mac Monitor 3 (File > Open Trace...) and export them again.

## Using it

- **Triage** lists the queue (see below). Click a row, or move with `j` / `k`; `c` gives a process the verdict *suspicious*, `b` *benign*, `u` undoes the last verdict you set (back to what it was, with its row selected again), `n` puts the cursor in its note, `t` shows it in the tree, `/` jumps to the search (`Esc` clears it, then hands the keys back to the list). Pressing the verdict a process already has takes it back to unreviewed. The filters are labelled *Verdict* (yours: unreviewed, suspicious, benign) and *Severity* (the rules': high, medium, low), and the footer says which row you are on.
- **Before a row is picked**, the right pane is an overview: how many rows are still unreviewed, the queue split by severity and by verdict (click a line to filter the queue to it), the programs with the most flagged rows (click one to search for it), what the capture can and cannot show, and the keys.
- **With a row picked**, the pane answers three questions in order, with links to jump between them: *Why flagged* (each finding, its technique and evidence), *Launched by* (each root of the process as its own column: original parent, current parent, responsible, oldest first, all coming down into the process; a root that is the same chain as the original parent is named under it instead of drawn twice) and *What it did*. Its header shows the severity and your verdict as two separate marks. *Details* lists the pid and parent pid, the parent, the command line, the signature, and the first and last time the capture recorded something of the process, with a count of what it recorded. *What it did* lists the processes it started and a timeline: every recorded event of the process (fork, exec, the forks it made, file events, launch item registrations, exit) in capture order, with each finding on the event it cites. *Include descendants* adds the events of every process under it. A timeline only lists what is in the capture: event types the viewer does not model, and times the capture did not record, are never filled in.
- **Tree** shows every process. The parent mode picks which root to follow: *Original parent* (who forked it), *Current parent* (who it sits under now, so an orphan is under launchd) or *Responsible* (the app that caused it). Unflagged processes are folded into grey “unflagged” rows with counts; the checkbox unfolds them. Search keeps the matches and their ancestors. The selected process's ancestors and the rows under it are tinted. Arriving from Triage (`t`, or *Show in tree*) opens the process and what it started, puts the keys on the tree, and adds *Back to Triage*, which returns to the row you came from even after you have moved on in the tree.
- **Capture coverage**, under the counts, opens to say what the capture cannot show and which checks that silences: exec events without file-descriptor data (eslogger schema before v11), event types the capture command asks for that are absent, program changes seen without their exec, processes known only by pid, unreadable lines, and event types the viewer does not model. An absent event type is reported as absent, never as proof that nothing happened.
- **Save session**, beside the session name, saves the session (verdicts, notes, routine marks) as JSON while you work in Triage or Tree, with the options chosen on the Suspicious tab. A line under it says whether the file will hold full command lines or redacted ones. The file is named `<session>.<hash>.ficus-session.json`, where the hash comes from the session's id, so two sessions with the same name get different files. In Chrome, Edge and other Chromium browsers, the first save asks for a folder (Chrome will not let a page write into your home folder, Desktop, Documents or Downloads themselves, so pick or make a folder inside one of them); later saves go into it (replacing that session's previous save), and *Change folder* picks another. Safari and Firefox cannot write into a folder, so there the file is downloaded.
- **Report for security**, beside Save session (and, before a row is picked, on the Triage overview as *Report flagged processes for security*), downloads two files for the security team: `<session>.<hash>.ficus-report.md` to read, and `<session>.<hash>.ficus-report.json` (format `ficus-report`, version 1) for their tools. The Markdown is rendered from the JSON, so the two say the same thing. Both hold every flagged row of every loaded capture, reviewed or not: rows marked benign and rows hidden as routine are included and marked, since the verdicts are the user's view and secops may overrule them. Each row has its findings with evidence and MITRE IDs, the command line, program and signature, where the process came from, its launch items and a summary of what it did. Processes the user marked although no rule flagged them get their own section; low-signal findings kept out of the queue appear as counts per rule; each capture's coverage notes say what it could not see. A capture that is not loaded cannot be reported: the overview warns first, and the report names it and lists only the verdicts set on it. Redaction is the same choice as Save session's (the checkbox on the overview or the Suspicious tab). It replaces every argument after the program name and the evidence that quotes a command line; program paths, process names, file paths and launch item paths stay, since they are the evidence. Notes are included as written. Environment variables are never included.
- **Reopening a session** from the home page first looks in that save folder (Chromium only) for a saved copy of the session: a file with the session's hash or name whose content has the same session id or, failing that, the same session name. If the copy differs from what the browser holds (other verdicts, notes, routine marks or captures), the session's row offers *Reimport and open*, which replaces the session's verdicts, notes, routine marks and captures with the file's and keeps its name, or *Open without it*. The offer says how many reviewed processes and routine marks each side has, and warns when the file is older than the browser's latest change. After a browser restart, Chrome asks again for access to the folder; if you refuse, the session opens as it is.
- **Suspicious** lists the processes given that verdict in every capture of the session and exports the session as JSON, or imports one. The export includes the full command line of each verdict, and command lines can hold secrets (a password passed to `dscl -authonly`); tick “Redact command-line arguments” to replace every argument after the program name. Environment variables are left out unless you ask. Exports made by earlier builds (format `gameleira-session` or `eslogger-viewer-session`) still import, and Reopening a session still finds a copy saved as `.gameleira-session.json`.

## Rules

The rules are data: each has an id, a severity, a plain explanation and MITRE ATT&CK IDs. The full list, with the exact matching logic, is in [`src/rules/rules.ts`](src/rules/rules.ts), and every finding also states in the app which trigger it matched. Summary:

| id | Severity | What it catches |
|---|---|---|
| `fake-prompt` | high | `osascript` whose arguments contain `display dialog` (or JavaScript for Automation's `displayDialog`) or `hidden answer`: a fake system password prompt (T1056.002). |
| `osascript-script` | med | `osascript` running a script file from a temporary, Downloads, shared, hidden, mounted-volume or translocated location, or reading its script from a pipe with no file on disk (T1059.002, or T1059.007 with `-l JavaScript`). |
| `keychain-access` | high, med or low | `security` against the keychain. High: `find-generic-password` or `find-internet-password` with `-g` or `-w` for a browser's or app's “Safe Storage” key or a crypto wallet entry, or `dump-keychain -d`. Med: any other `find-*-password -g` or `-w`. Low, context only: attribute lookups, `unlock-keychain`, `export`, `dump-keychain` without `-d` (T1555.001). |
| `security-setting-change` | high or med | Commands that weaken a protection or redirect traffic. High: `spctl --master-disable`, `--global-disable`, `--disable` naming no rule, `--add` (T1562.001, T1553.001); `csrutil disable`, `csrutil authenticated-root disable`, `csrutil enable --without` (T1562.001); `security add-trusted-cert` that trusts a root (T1553.004). Med: `spctl --disable` naming a rule; `add-trusted-cert -r deny` or `-r unspecified` (T1553); `security authorizationdb write` (T1548); `networksetup` setting a web, secure web, automatic, SOCKS proxy or DNS servers, or turning a proxy on (T1557). The text says when the command only works on older macOS or from Recovery, so it may be an attempt. |
| `dscl-authonly` | high | `dscl ... -authonly` (or `authonly`): verifying a password the attacker just phished with a fake prompt (T1056.002). |
| `persistence-item` | high or med | A launch item registered with the background task manager (`btm_launch_item_add`). High if it runs a shell or interpreter (python, perl, ruby, osascript, node, php), runs from a place a user process can write to (a temporary folder, `/Users/Shared`, Downloads, a mounted volume, a hidden or dot-folder, `~/Library/Caches`), ran unsigned or ad-hoc signed in this capture, or is a loose program (not an app bundle) anywhere in a home folder. Also high when the plist is named `com.apple.…` (in a user's `~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons`) but the item runs something outside Apple's folders (`/System`, `/usr` except `/usr/local`, `/bin`, `/sbin`, `/Library/Apple`) that is not a platform binary in the capture. Med otherwise, for example a per-user updater app in `~/Library`, or anything under `/Applications` or a system folder. The evidence says which reason applied. MITRE follows the item type: launch agent T1543.001, launch daemon T1543.004, login item, app or user item T1547.015. |
| `persistence-plist` | high | A process (one that exec'd, or one that only forked) wrote or renamed a `.plist` into a `LaunchAgents` folder (`~/Library`, `/Library`) or `/Library/LaunchDaemons`, and no registration event attaches its finding to that same process (T1543.001 or T1543.004, by folder). |
| `launchctl-load` | high | `launchctl load`, `bootstrap` or `submit`: starting a launch job right now (T1569.001). |
| `quarantine-strip` | high | `xattr -c` (also in clusters such as `-cr`), or `xattr -d com.apple.quarantine`: removing the flag that makes Gatekeeper check a download (T1553.001). |
| `payload-decode` | med | `openssl ... -d` (but not the digest commands such as `dgst`, where `-d` is debug), or `base64 -d`: unpacking a hidden payload (T1140). |
| `shell-from-pipe` | med | stdin is a pipe and no script file runs: a shell with no arguments or `-s` and no `-c`, or `python`, `perl` or `ruby` with no inline code and no script: the `curl ... \| bash` pattern, with no script on disk to inspect. `--version`/`--help` and similar probes do not count, but a ruby `-v` probe followed by `-` still reads the piped script. Needs `eslogger` schema 11 (T1059.004, T1059.006 for Python, T1059 for Perl and Ruby). |
| `shell-under-app` | med | A shell launched, when it was born, by an app inside a `.app` bundle other than terminals and editors (T1059.004). |
| `download` | med | `curl` writing to a file (`-o`/`--output`, `-O`/`--remote-name`), `wget` with a URL (it saves a file by default, unless `-O` points at `-` or `/dev/null`; `-o` is only the log), or either one that created a file (T1105). |
| `credential-store-copy` | med or high | A process created (or renamed into place) a credential store in a temporary, Downloads, shared or hidden folder, or ran `cp`, `ditto`, `rsync`, `scp`, `zip`, `tar`, `sqlite3` or `cat` with one among its arguments. Credential stores: the login keychain and anything in a `Library/Keychains` folder, a browser's `Login Data`, `Cookies`, `Web Data`, `Local State`, `Cookies.binarycookies` or `Local Extension Settings`, Firefox's `key4.db`, `logins.json` and `cookies.sqlite`, and the Notes database (`NoteStore.sqlite`). A file created in a browser's own profile folder, on a mounted volume or in a dot-folder directly in home is not flagged. High if the program is unsigned, ad-hoc signed or runs from a strong odd place, or if a copy tool also names a staging place; med otherwise. Backup tools and Migration Assistant do this legitimately (T1555.001 for keychains, T1555.003 for browsers, T1005, T1074.001 for staging). |
| `archive-staging` | med or high | `ditto -c`, `zip`, or `tar` in create mode. High if a path it names is in a temporary, Downloads, shared, volume, translocated or hidden location; med otherwise (T1560.001). |
| `odd-location-exec` | high, med or low | A program or its script run from a place a normal install does not run from. Strong places: `/tmp`, `/var/tmp`, `/var/folders`, `/Users/Shared`, `~/Downloads`, `/Volumes`, App Translocation, and a hidden folder below a visible one in a home folder. For a program there: high if unsigned or ad-hoc signed, med if signed without a team ID, low if team-signed; a script there is med. Weak places: a dot-folder directly in home (`~/.cargo`, `~/.local`), a hidden folder inside a project build or tooling folder (`.git`, `node_modules`, `.build`, `.terraform`, `.venv`, `target`, ...), Go's build folder: med if unsigned, else low. Low findings are context only (T1204.002). |
| `unsigned` | med | A non-Apple binary with no code signature at all. A trait of the binary, not a technique, so it cites no MITRE ID. |
| `apple-masquerade` | high or med | Code wearing an Apple name it does not have. Two forms: a program that is not a platform binary but carries a `com.apple.…` signing ID, ad-hoc signed or under another team's certificate (a signing ID is the signer's own choice); or a program that is not Apple's (Apple's own code is a platform binary, or a `com.apple.*` signing ID with a real signature and either no team ID or one of Apple's own team IDs, which is what Xcode, iWork and similar apps carry; Apple uses several teams and the list is built in, so an Apple app signed by a team not on it would be flagged. A `com.apple.*` ID under any other team's certificate is a spoof, never trusted) creating or renaming into place a `com.apple.…` plist (hidden `.com.apple.…` too) in `~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons`. A signing ID alone is high; a plist is high in a user's `~/Library/LaunchAgents` or when the writer is unsigned or ad-hoc, med otherwise. Apple's installers write these plists legitimately, and are never flagged (T1036.005, T1543.001 for agents, T1543.004 for daemons). |
| `adhoc` | low | A non-Apple binary that is ad-hoc signed, so it has no developer identity. Common for Homebrew and locally built tools, so it is context only. Also a trait. |
| `orphaned` | low | A process whose parent exited so it now sits under launchd (pid 1), though it was started by something else (not `xpcproxy`): the double fork that detaches a daemon (T1036.009). |
| `uid-mismatch` | high, med or low | A process whose own effective user or group id differs from its real one. Climbing: a user's process running with root's (or another account's) privileges, from a setuid or setgid binary or a `setuid()` call. High for a non-Apple binary (including a copy that only borrows an Apple signing ID); med for an Apple platform binary that is not a known setuid tool; low for Apple's own setuid tools (`ps`, `sudo`, `su`, `crontab` and others). Dropping: a root process running with a user's effective id (`loginwindow`, or a vendor daemon acting for the logged-in user) gave its privileges up and can take them back, and so did one whose real group is wheel but whose effective group is another; always low, titled "Dropped privileges". A process whose real and effective user is root and only has another effective group already holds every privilege; always low, titled "Root with another effective group". Each image the process ran is judged on its own and the worst counts. Low is context only unless the process is in a flagged chain (T1548.001). |
| `recon` | low | `ps` (T1057); `networksetup`, `scutil` (T1016); `airport` (T1016.002); `csrutil`, `spctl` (T1518.001); `whoami`, `id` (T1033); `system_profiler`, `sw_vers`, `sysctl`, `ioreg`, `uname`, `hostname`, `scutil --get` (T1082). Forms that change a setting are not recon. Queued only in a flagged chain or a recon burst; otherwise shown as context in the detail pane (see below). |

## What the queue means

The queue on the Triage tab lists the processes (and the launch items no process owns) the rules flagged. Each row says why, with the evidence from the capture. A flag is a lead to look at, not a verdict: you decide, and give the process the verdict suspicious or benign. Severity and verdict are kept apart: severity is the rules' view of the evidence, the verdict is yours. (Saved sessions and exports store the suspicious verdict as `confirmed` and medium as `med`, as earlier builds did, so they still import.)

- **Severity (high, med, low)** is how strongly the strongest finding on that row suggests something worth your time. High is things almost no ordinary software does, such as a fake password dialog or a launch agent that runs a shell. Low is weak signals that matter mainly in company. Rows are sorted high first, then by time.
- **Trait findings** (`unsigned`, `adhoc`) describe the binary, not an attack technique, and say so instead of showing a MITRE ID.
- **`in chain`** on a row means the process did nothing alarming itself, or only a low-signal thing, but it descends from a process with a med or high finding. A `whoami` is nothing on its own; under a shell that was fed from a pipe it is probably part of the same intrusion. Look at the parent first. A launch item registered by an app (or by its instigator) puts that app's descendants in a chain only when the item is high.
- **`recon burst`** marks a row queued because it was one of 3 or more different recon tools run under the same parent within 60 seconds (any 60-second window; every tool in it is queued). A burst of one tool, such as `ps` six times from a monitoring app, is not a burst.
- **Context-only** findings are the low-signal ones (`recon`, `adhoc`, low `odd-location-exec`, low `keychain-access`) on processes that are not in a flagged chain or a burst. They would flood the queue (a normal Mac runs `ps` all the time), so they are kept out of it and shown only in that process's detail pane.
- **Launch items.** The detail pane shows the item's type (launch agent, daemon, login item, app, user item), whether the item is a plist or an app, what it runs, and who registered it: the app that registered it if the event names one, otherwise the instigator (the XPC caller that asked for it), otherwise the process that wrote the plist. The finding sits on that process's row. An Apple system process such as `smd` is skipped for that purpose, since it may only be relaying the request for someone else; with no usable process the item is its own row, “persistence: <plist>”, with no process or tree entry. The daemon that reported the event (`backgroundtaskmanagementd`) is shown as the reporter, not the registrant.
- **Routine** is a mark you set on a program (“Treat as routine”) to say you have seen it and it is normal on this machine. It hides every run of that program, in every capture of the session, and the header counts how many queue rows are hidden. A program is identified by its signing ID, team ID and executable path together, so a re-signed or relocated copy counts as a different program and is not hidden. A routine mark never hides a row with a high finding or a persistence finding (marking `cat` routine must not hide the launch agent that `cat` wrote): that row stays, marked “routine program — kept: <reason>”, and the app asks first when marking a program would leave such rows visible. Launch items with no process are never hidden. The mark is reversible from the same button.

## Performance

Targets: an 11,610-event, 28.6 MB capture from drop to the triage screen in under 5 seconds; a 500 MB capture loads without crashing the tab, slower is acceptable. The worker streams the file in 4 MB slices and keeps only the fields the model needs.

Measured on an Apple M5 Max, 48 GB, Node 24, and the in-app browser pane (Chromium) with `dist/index.html` served over HTTP:

| Capture | Where | Result |
|---|---|---|
| a lab capture, 28.6 MB, 11,610 events | browser, from the file input's change event to the triage screen | 0.09 s on first load, 0.3 to 0.5 s on later ones (includes writing the capture record to IndexedDB). Under the 5 s target. |
| a schema v6 sample, 1.5 MB | browser, same measure | about 0.1 s |
| `scratch/big.jsonl`, 516 MB, 208,980 events | browser, same measure | 4.6 s, no crash. Switching from Triage to Tree and back took about 1.2 s and the tree rendered rows; I did not otherwise test interactivity. Tab heap read 69 MB afterwards. |
| `scratch/big.jsonl` | Node: stream lines through `ModelBuilder`, then `analyze` | 1.1 s total (parse 1.0 s, analyze 0.04 s). Peak `heapUsed` 292 MB, peak RSS 587 MB, 232 MB retained after GC. For comparison the 28.6 MB capture alone peaks at 23 MB heap. |

Caveat: `scratch/big.jsonl` is the 28.6 MB capture repeated 18 times with `global_seq_num` offset by `n x 10,000,000` per copy (`node scripts/make-big.mjs [capture.jsonl]`). Every copy repeats the same pids and audit tokens, so the model still sees 4,722 processes, not 18 times as many; the test proves load volume and memory behaviour on very large inputs, not a capture with 500 MB of distinct processes. A real capture with many distinct processes would retain more memory per event. The browser was driven by feeding the file to the page's file input from script, not by a physical drag from Finder. Because the capture fingerprint is taken from the file's head, `big.jsonl` has the same fingerprint as the capture it was made from and replaces it within a session; that is the “a capture that grows keeps its verdicts” behaviour working as designed.

To reproduce: `node scripts/make-big.mjs path/to/capture.jsonl` (writes `scratch/big.jsonl`, 516 MB for that capture, gitignored), load it, then delete it.

## Tests

```
npm test             # builds dist/ first (pretest), then runs the whole suite
npx vitest run test/rules.test.ts   # one file while iterating (needs dist/ only for build.test.ts)
```

A fresh clone runs most of the suite. `test/fixtures/synthetic-lab.jsonl` is a small hand-built capture (eslogger schema 11, an invented user `alice`, invented pids and tokens) that tells the steps of a lab intrusion, plus noise: a download, a script piped into `bash`, a fake password dialog, staging in `/tmp`, an orphaned process, a launch agent written by a shell redirect with its `btm` event, a login item registered by an app in Downloads, a recon burst, a process whose `exec` the capture missed, and a parent that started before the capture. `scripts/make-synthetic-lab.mjs` writes it (`node scripts/make-synthetic-lab.mjs`); a test checks the committed file is exactly what the script produces. The parser, model, rules, session and UI tests run on it.

The tests that check the code against real captures are kept, but they need files that are not in this repo (one is a capture of a private Mac, the others are third-party malware samples): `es-lab.jsonl` and `SpriteTreeSamples/*.json` in the repo's parent directory. When they are missing those tests are skipped and the run prints one note saying so. Set `FIXTURES_DIR` to a directory with the same layout (the `.json` samples are read from `$FIXTURES_DIR/SpriteTreeSamples/`) to run them:

```
FIXTURES_DIR=/path/to/captures npm test
```

`npm run dev` also accepts `?load=<file>` to open a development session named `dev` with a capture from the directory above the repo already loaded. That code is compiled out of the production build, and `test/build.test.ts` checks that it stays out.

## Roadmap

XPC connection edges are planned.

## License

MIT, see [LICENSE](LICENSE).
