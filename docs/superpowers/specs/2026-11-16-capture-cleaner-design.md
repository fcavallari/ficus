# Capture cleaner: pseudonymize a capture before it leaves the Mac

## Intent

Gameleira is used to investigate Macs of people whose data is especially sensitive: senior leads, C-level staff. An `eslogger` capture of such a Mac holds their user name, the names of their documents and folders, internal hostnames, email addresses, and secrets that happen to sit in command lines or environment variables. Once the capture leaves the Mac (to the investigator's laptop, a ticket, a shared drive) the file itself is a leak waiting to happen.

The cleaner runs on the investigated Mac, in the capture pipeline, so the raw capture is never written to disk. It replaces personal content with stable placeholders (`/Users/user1/Documents/name7/name42.pdf`) while keeping the shapes Gameleira's rules depend on, so the cleaned capture triages the same way as the raw one would. A key file mapping each placeholder back to the real value is written on the Mac and stays there: when a finding needs the real name (was it a crash log or a board deck that got zipped?), the investigator or local IT looks it up on the machine.

## Goals

- `scripts/gameleira-clean.sh` records with `sudo eslogger` and writes only a cleaned capture; the raw stream exists only in a pipe.
- It can also clean an existing capture file (`-i FILE`), for captures taken another way.
- The cleaned capture produces the same Gameleira findings as the raw one: same processes, rules, severities and queue status.
- Every placeholder is consistent across the whole capture: the same real value always gets the same placeholder.
- The key file (`kind`, `placeholder`, `real value`) stays on the Mac, readable only by the user who ran the script.
- Needs nothing installed: bash 3.2, `/usr/bin/jq` (ships with macOS 15 and later), and tools in a stock macOS.

## Non-goals

- Anonymization. A determined reader can still infer things from behaviour (which apps run, at what times, uid 501). The goal is that names, documents, hosts and secrets do not travel, not that the Mac cannot be recognized.
- Hiding which software is installed or what ran. App names, bundle IDs, signing IDs, team IDs and the file names of executed programs are evidence and stay.
- Cleaning in the Gameleira page, or changing the viewer. (Session exports already redact command lines; that is unchanged.)
- Encrypting the key file. It is protected by file permissions and by staying on the Mac; deleting it makes the cleaning irreversible.
- Marking the capture as cleaned inside the file (any extra line would count as an unreadable line in the viewer).

## Anti-goals (a failure even if it works)

- A cleaned capture whose findings differ from the raw capture's.
- Any raw line passing through uncleaned, for example when a line fails to parse. The cleaner fails closed: a line it cannot parse is dropped and counted, never copied.
- A recognised credential (password, token, key) written anywhere, including the key file.
- Asking for anything to be installed on the investigated Mac.
- Falling behind `eslogger` silently. A blocked pipe makes Endpoint Security drop events; if that happens, the summary must say so.

## Approaches considered

1. **Shell script around one `jq` program** (picked). jq ships with macOS 15+, the whole script can be read before it runs on an executive's machine, and it follows the pattern of `gameleira-lab.sh` and its tests. Cost: regex-heavy logic is denser in jq than in a general-purpose language.
2. **The same script with `perl` doing the cleaning.** Easier text matching, but Apple has said scripting runtimes will eventually stop shipping with macOS; a privacy tool that one day is missing on the target Mac is a bad failure.
3. **Cleaning in the Gameleira page on export.** Rejected: the raw capture would already have left the Mac, or at least been written to its disk.

A compiled helper (Swift) was also rejected: an unsigned binary on an executive's Mac is exactly what Gameleira flags.

Decided with the user: option 1, and a reversible key kept on the Mac (rather than one-way cleaning with no key).

## Design

### Running it

```
scripts/gameleira-clean.sh record [-o FILE] [-k KEYFILE] [-t SECONDS] [-D DOMAIN]... [-S SEEDFILE]
scripts/gameleira-clean.sh clean -i RAW [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE]
```

- `record` runs as the user (refuses to run as root), uses `sudo` for `eslogger` only, with the event list from the README's Capturing section. It stops on Ctrl-C or after `-t SECONDS`. Ctrl-C stops `eslogger` only (with SIGINT, as `gameleira-lab.sh` does in `stop_capture`); jq then reads to the end of the pipe and exits, so the last events are cleaned and written rather than lost.
- `clean -i RAW` reads JSONL, and also the forms Gameleira reads (a pretty-printed export whose first line is only `{`, or a JSON array). Output is always JSONL. It prints a reminder that the raw file still exists; it never deletes it.
- `-D DOMAIN` (repeatable): the company's own domains, cleaned as internal hosts.
- `-S SEEDFILE`: extra values to clean, one `kind<TAB>value` per line (kinds as in the key file). For a capture cleaned on another Mac than the one recorded, and for tests.
- Default output `capture.cleaned.jsonl` in the current folder; default key `~/Library/Application Support/Gameleira/keys/<output name>.key.tsv`. The key is deliberately not next to the capture, so copying or zipping the capture's folder does not take the key with it. The key file is created `0600`, owned by the user, before recording starts.
- `-k KEYFILE` naming an existing key loads it first and appends to it, so several captures of the same Mac share placeholders (`user1` is the same person in each).
- At the end it prints a summary to the terminal: events in and out, lines dropped as unreadable, events Endpoint Security dropped (gaps in `global_seq_num`, which is consecutive in a complete capture), placeholders created per kind, values replaced as credentials, and where the capture and the key are.

### Seeds

Some identifying values appear outside any path, so the script collects them first and gives them placeholders up front:

- local account short names and full names (accounts with uid 500 or more, from `dscl`);
- computer name, local host name and host name (`scutil`), hardware serial number and platform UUID (`ioreg`);
- anything in `-S SEEDFILE`, and every entry of a key loaded with `-k`.

Seeds, `-D` domains and the loaded key reach jq through a `0600` temporary file (`--rawfile`/`--slurpfile`), never through its arguments: `eslogger` records every exec's arguments, including jq's own.

`clean -i` on a capture whose home folders (`/Users/<name>/`) name no account of this Mac warns that it is probably running on another Mac, so names outside paths (full name, host names) are only caught if given with `-S`. It does not refuse.

### Placeholders

A placeholder stands for one **name** (one path component, a host, an email address, an account), not a whole path, so the same name gets the same placeholder wherever it appears: in any path, in a create event's separate `filename`, in a relative argument, in free text. Kinds and forms:

| kind | form | example |
|---|---|---|
| `user` | `userN` | account short name |
| `realname` | `Person N` | account full name |
| `name` | `nameN`, keeping a leading dot and a short extension of letters and digits | `.name3`, `name42.pdf` |
| `volume` | `volN` | a name under `/Volumes/` |
| `host` | `hostN.internal.invalid` | internal host or IP |
| `email` | `personN@example.invalid` | email address |
| `seed` | `seedN` | serial number, platform UUID, other seeds |
| `data` | `dataN` | a request body, query value or encoded payload (see below) |

Placeholders are numbered per kind in order of first appearance (or continue from a loaded key), so the same input and key always give the same output.

### Precedence

Field exemptions are by field path and win over string cleaning. In order:

1. **Fields left unchanged:** numbers (pids, pid versions, uids and gids, session ids, sequence numbers, code-signing flags), times, team IDs, cdhashes, event types, tty paths, entitlements.
2. **`signing_id`:** only account names and seeds are replaced, as whole dot- or dash-separated parts (`com.alice.tool` becomes `com.user1.tool`); Apple's (`com.apple.*`) are never touched.
3. **Credentials** (below) in every other string.
4. **Data that may be a secret or evidence** (below).
5. **General string cleaning** (below) in every other string.

Walking every string, rather than a list of known fields, means a field nobody thought of (or a Mac Monitor enrichment) cannot carry a name through.

**Replacement is in place:** an argument or environment entry is rewritten, never removed or split, so option parsing by position (`src/rules/args.ts`) sees the same structure.

### Names that are kept

Kept as they are wherever they appear, because the rules or the investigator need them:

- **The file name of every executed program and script:** the last component of every process's `executable.path`, of `exec.script.path`, of `dyld_exec_path`, of a launch item's `executable_path`, and `argv[0]`'s last component. A program name is kept in every other string where it appears too. (Rules decide by program name: `python`, `node`, `curl`, `osascript`, the recon tools; and a dropper's name is evidence.) The folders above it are cleaned like any other.
- The standard home folders: `Desktop`, `Documents`, `Downloads`, `Library`, `Movies`, `Music`, `Pictures`, `Public`, `Applications`, `.Trash`.
- The folders under `~/Library` that are system or app structure: `LaunchAgents`, `Caches`, `Preferences`, `Application Support`, `Containers`, `Group Containers`, `Logs`, `Saved Application State`, `WebKit`, `Cookies`, `HTTPStorages`, and names that are app, vendor or bundle names (below). The builder may extend this list.
- The tooling folder names from `TOOLING_DIRS` in `src/rules/locations.ts`, and `go-build*`.
- Names ending in a bundle suffix (`.app`, `.framework`, `.bundle`, `.plugin`, `.kext`, `.xpc`, `.appex`).
- Reverse-DNS bundle IDs (`com.example.thing`, with or without `.plist`), with account names and seeds inside them replaced as parts.
- Fixed system structure: `/System`, `/usr`, `/bin`, `/sbin`, `/Library`, `/Applications`, `/opt`, `/private/var/db`, `/dev`, and the random folder names under `/var/folders`.

### General string cleaning

1. **Paths.** Every absolute path, `~/` path or `file://` URL inside a string is cleaned name by name. Every name not on the keep list above, in these places, gets a `name` placeholder:
   - anywhere under a home folder (`/Users/<name>/…`, the account name itself becoming `userN`), including `~/Library` (so Office AutoRecovery, Group Containers, QuickLook caches and Mail are covered by default rather than by a list of stores);
   - under `/Users/Shared/`;
   - under `/Volumes/<vol>/` (the volume name becoming `volN`);
   - under the temporary folders: `/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp`, and below `/var/folders/<a>/<b>/T/` and `/C/` (App Translocation keeps its structure; the `.app` inside is kept as a bundle).
   - Elsewhere (system and app locations), names are kept, with account names, seeds and already-mapped names replaced.
2. **Relative names in arguments.** When a process's `cwd` is in one of the cleaned places above, every positional argument and option value that is a relative path (`board.zip`, `Q3 Financials`, `./x/y.pdf`) is cleaned name by name, keeping `.`, `..`, leading dots and extensions. Option names and the program name are not touched. A relative argument whose `cwd` is in a kept place is still checked for names that already have a placeholder.
3. **Create and rename events.** `new_path.filename` is cleaned as the last name of `new_path.dir.path`, with the same placeholder it would get in a full path.
4. **Already-mapped names in free text.** Any name that already has a placeholder is replaced wherever it appears as a whole word or path component (`osascript -e` text, `sh -c` strings, commit messages). Names shorter than 4 characters are only replaced inside paths, emails and hosts, and the summary lists any account name that is a common word or shorter than 4 characters.
5. **Emails** become `personN@example.invalid`.
6. **Internal hosts, anywhere** (in URLs, `ssh host`, `user@host:path`, `git@host:repo`, `nc 10.0.0.5`, environment values): private and link-local IPv4 and IPv6 addresses, names ending in `.local`, `.internal`, `.corp`, `.lan`, `.home.arpa`, names under a `-D` domain, and the host-name seeds. Public hostnames are kept (a command-and-control domain is evidence). In every URL, user info is removed (a credential), query values become `data` placeholders (names kept), and path segments are cleaned like names under a cleaned place.
7. **Account names and seeds** anywhere else, as whole words, case-insensitive; never inside an option name or a kept bundle or program name.

### Credentials

Replaced with `<redacted>` and never written to the key:

- the password after `dscl … -authonly <user>` (the user name is cleaned as a name);
- `security … -w <value>` and `-p <value>` when they carry a value (adding a password), not the bare `-w` flag of `find-*-password`, which the `keychain-access` rule needs;
- `curl` `-u`/`--user`, `-b`/`--cookie`, and the value of `-H`/`--header` when the header is `Authorization`, `Cookie` or `Proxy-Authorization` (header name kept);
- generic `--password`/`--passwd`/`--token`/`--secret`/`--api-key` options (`=value` or next argument), `-p<value>` for `mysql`-style tools, `openssl … -pass`/`-passin`/`-passout`/`-k` values;
- `NAME=value` arguments and environment entries whose name looks secret (`*PASSWORD*`, `*PASSWD*`, `*TOKEN*`, `*SECRET*`, `*API_KEY*`, `*AUTH*`, `*CREDENTIAL*`);
- recognised credential shapes anywhere: AWS access keys (`AKIA…`, `ASIA…`), GitHub (`ghp_`, `gho_`, `ghs_`, `github_pat_`), Slack (`xox[abprs]-`), `sk-`-style API keys, JWTs (`eyJ….….…`), PEM private key blocks.

What must survive for the rules: program names, option letters and long option names, the keychain service names (`Chrome Safe Storage`, wallet names), `-authonly`, `display dialog` and `hidden answer` in `osascript -e` text, `launchctl` subcommands, `xattr -d com.apple.quarantine`, `-d` on `base64` and `openssl`, and every path's shape as above.

### Data that may be a secret or evidence

Decided with the user: mapped in the key, not erased. These values get a `data` placeholder (`dataN`) and their real value goes in the key, so the investigator can still recover a payload or see what was sent out, by looking it up on the Mac:

- `curl` `-d`/`--data*`/`--data-urlencode`/`-F`/`--form` values;
- URL query values (names kept: `?id=dataN`);
- long high-entropy strings: 32 or more characters of base64, base64url or hex that are not a path, a file name, a bundle ID or a field exempt by precedence (a base64 payload in `sh -c '… | base64 -d'`). The placeholder replaces only the matched run, so the text around it stays.

Recognised credentials (above) are checked first and are always `<redacted>`. A credential that no pattern recognises may therefore end up in the key as `data`; that is accepted, because the key never leaves the Mac. The key is as sensitive as the raw capture and the README says so.

**Environment (`exec.env`).** Variable names are kept. Values are replaced with `<redacted>`, except `PATH`, `SHELL`, `TMPDIR`, `HOME`, `PWD`, `OLDPWD`, `LANG`, `LC_*`, `TERM*`, `__CF*` and `DYLD_*` (injection evidence), which get the general cleaning.

**Dropped:** `create.acl` (the viewer does not use it and it can name users and groups).

### The key file

TSV with a header: `kind`, `placeholder`, `real`. A line is appended and flushed the moment a placeholder is created, so a capture cut short still has its key. Recognised credentials never appear in it; `data` values do, so the key is as sensitive as the raw capture.

### Streaming

One `jq -n --unbuffered` program reads raw lines (`-R`), parses each with `fromjson?`, and keeps the placeholder table as state across lines (`foreach`). Each cleaned event goes to stdout; each new key entry goes to the key file, kept apart from jq's own diagnostics (for example by tagging key lines on stderr and filtering them in the script). A line that does not parse is dropped and counted. For `clean -i` on a pretty-printed or array file, the script first turns it into one event per line (jq `-c`), then runs the same program.

### Performance

Measured before writing this design, on 3,000 events from a real capture (about 17 strings per event): a rough jq pass (`walk` over every string, six `gsub`s) ran at about 1,400 events per second, and about 2,300 with a cheap `test` that skips strings with nothing to clean. That capture averaged 85 events per second and peaked at 229 in one second. The real program does more per string, so:

- skip strings that cannot contain anything to clean with one cheap test before any `gsub`;
- measure the finished cleaner on the live lab capture, a real capture and a large one from `scripts/make-big.mjs`; target at least 700 events per second (three times the observed peak) on an Apple silicon Mac;
- if the finished program falls well short, stop and bring it back to the user rather than working around it quietly;
- in every case, report dropped events (sequence gaps) in the summary.

## Testing

In `test/clean-script.test.ts`, running the script with `/bin/bash` (bash 3.2) and `/usr/bin/jq`; the suite skips where `/usr/bin/jq` is missing. Seeds come from a `-S` file and a test-only environment variable stops the script reading this Mac's accounts (like `GAMELEIRA_LAB_FAKE_UID` in the lab script), so results do not depend on the machine.

- **Same findings.** For `test/fixtures/synthetic-lab.jsonl` (user `alice`), for `gameleira-lab.sh synthetic` output (user `learner`, sets off every rule), and for the real captures from `test/fixtures.ts` when present (`realDescribe`): build the model from raw and cleaned, run the rule engine, and compare per pid: rule ids, severities and queue status (queued, burst, in-chain, context).
- **Program names under home.** A fixture with a pipe into `~/.pyenv/shims/python3`, a `node` under `~/.nvm`, Homebrew under home, and a dropper in `~/Downloads`: same findings raw and cleaned, and the program names are still there. (None of the existing fixtures runs a program from a home folder outside `~/Library` and `.app` bundles.)
- **Nothing leaks.** A fixture with planted values: an account name and full name in paths, arguments, cwd, plist URLs, bundle IDs, signing IDs and environment; document and folder names under `Documents`, `Desktop`, `~/Library/Application Support`, `~/Library/Group Containers`, `/Users/Shared`, `/tmp`, `/var/folders/…/T/` and below `/Volumes/<vol>/`; a create event's separate `filename`; relative arguments (`zip -r board.zip "Q3 Financials"` with `cwd` in `Documents`); a mapped name inside `osascript -e` text; an email; internal hosts in a URL, `ssh`, `git@host:repo` and an environment value, and a `-D` domain; a hostname seed; a password after `-authonly`; `curl -u` and an `Authorization` header; an AWS key and a JWT in arguments and environment; a `curl -d` body, a URL query value and a base64 payload in `sh -c`. None of the planted strings may appear anywhere in the cleaned capture (raw bytes, case-insensitive); no recognised credential may appear in the key file; every planted name and data value appears in the key; a cdhash, a hash-named file and a bundle ID are not taken for data.
- **Consistency.** The same real value gets the same placeholder on every line and in every field, and across two runs that share a key (`-k`).
- **Same output every run** for the same input, seeds and key.
- **Fail closed.** A capture with a truncated line and a non-JSON line: those lines are absent from the output, counted in the summary, and no fragment of them appears.
- **Shapes the rules need survive:** `Downloads`, `/Users/Shared`, a hidden folder below a visible one, a tooling folder, `.app` bundles, LaunchAgents plists, `-w` on `find-generic-password`, `Chrome Safe Storage`; and arguments keep their count and positions.
- **Sequence gaps** in the input are reported in the summary.
- Argument errors exit 2, as in `gameleira-lab.sh`.

The `record` path (sudo, eslogger, Ctrl-C) is checked by hand on a Mac, as the lab's live mode is.

## Docs

A README section after "Capturing": why the cleaner exists, the two commands, what is replaced and what is kept, where the key is, that it holds real values (names, request bodies, payloads) and must stay on the Mac, and that deleting it makes the cleaning irreversible, and that a cleaned capture is pseudonymized, not anonymous.

## Left to the builder

- Internal structure of the jq program and the shell script, and how key lines are kept apart from jq's diagnostics.
- The exact keep lists (home and `~/Library` folders, safe environment variables, bundle suffixes) beyond those named here, and the exact credential patterns, as long as the tests above pass.
- How `-t SECONDS` and the summary are implemented.
