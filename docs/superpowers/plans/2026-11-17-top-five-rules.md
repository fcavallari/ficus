# Top Five Detection Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the five best-corroborated new rules from the blog research to Ficus: `credential-store-copy`, `apple-masquerade`, `clickfix-paste-chain`, `risky-parent-spawn`, `dropped-then-executed`.

**Architecture:** Each rule is a new entry in `RULES` (`src/rules/rules.ts`) over the existing capture model; no new event types and no capture-command change. Small helpers live in new focused modules (`credentials.ts`, `context.ts`, `ledger.ts`). The one shared structure is a per-capture file ledger (create/rename destinations and unlinks, keyed by normalized path) used by `dropped-then-executed`.

**Tech Stack:** TypeScript, Vitest, bash (`scripts/ficus-lab.sh`).

**Spec:** `reports/Ficus detection rule sources.md` (rules 1–5 of the shortlist, plus its "Sharpenings" and "Contradictions" sections). Raw notes: `research_notes/Ficus detection rule sources/`. Command strings in the report came through a summarizing fetch tool: the argv patterns below are the plan's decisions, but check any regex against the primary source linked in the report before hard-coding it.

## Global Constraints

- No new dependency, no new eslogger event type, no change to the capture command, session export or report schema.
- Rule ids, default severities and MITRE IDs (`Rule.mitre` lists every ID the rule can cite):
  - `credential-store-copy`: `med`; `T1555.001`, `T1555.003`, `T1005`, `T1074.001`
  - `apple-masquerade`: `high`; `T1036.005`, `T1543.001`, `T1543.004`
  - `clickfix-paste-chain`: `high`; `T1204.004`, `T1059.004`, `T1140`, `T1105`
  - `risky-parent-spawn`: `high`; `T1059.002`, `T1059.004`, `T1204.002`
  - `dropped-then-executed`: `med`; `T1105`, `T1204.002`, `T1070.004`, `T1564.001`
- Drop window for `dropped-then-executed`: a file counts as freshly dropped when it was created or renamed into place at most **15 s** before the exec; run-and-delete means an unlink at most **60 s** after the exec. Both are named constants.
- Every new rule needs, in the same task: a README rules-table row (`| \`id\` | severity | what it catches |`, severity cell contains the default severity, description contains every MITRE ID), exactly one placement in `STAGES` (`src/ui/GuideScreen.tsx`), every MITRE ID in `MITRE_NAMES` (`src/rules/mitre.ts`), and a step in the synthetic lab (`scripts/ficus-lab.sh`, `synthetic_story`) with an `answer` row. `test/readme.test.ts`, the guide-stage test in `test/ui.test.tsx`, `test/rule-cases.test.ts` (MITRE names) and `test/lab-script.test.ts` ("every rule fires at least once") enforce all four, so a rule added to `RULES` without them breaks those tests. Run only the task's own test file until the registration steps are done.
- Existing rules keep their ids, severities and behavior. A process can carry findings from an existing rule and a new one (for example a shell under Script Editor has `shell-under-app` and `risky-parent-spawn`).
- Commit messages end with the line `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Commit only the files a task names; `reports/` and `research_notes/` stay untracked.

## Review Focus

- **Benign look-alikes stay quiet.** The Homebrew-style `curl -fsSL … | bash` stays at `shell-from-pipe` (med) only. → Task 3 test `plain curl piped to bash is not a paste chain`.
- **A browser writing its own cookie database** in its profile folder is not credential theft. → Task 1 test `a browser's own profile is not flagged`.
- **Compilers and build tools running what they just built** (`go run`, `go-build` folders, a toolchain as writer) never flag. → Task 5 tests `go-build output is not a drop` and `toolchain writers are skipped`.
- **Apple-signed software that is not a platform binary** (Xcode and similar: `com.apple.*` signing ID, valid non-ad-hoc signature) is not masquerading. → Task 2 test `a genuine non-platform Apple signature is not flagged`.
- **Gaps in the capture**: missing args, null paths, null times, a parent that was never seen, a ghost process. No crash and no finding. → one test per task named `…tolerates a capture with missing data`.

---

### Task 1: `credential-store-copy`

**Files:**
- Create: `src/rules/credentials.ts`
- Modify: `src/rules/rules.ts` (append the rule to `RULES`), `src/rules/mitre.ts`, `src/ui/GuideScreen.tsx` (stage "Discovery and collection"), `README.md` (rules table), `scripts/ficus-lab.sh` (`synthetic_story`)
- Test: `test/rule-credential-store-copy.test.ts`

**Interfaces:**
- Produces, in `src/rules/credentials.ts`:
  - `export function credentialStore(path: string): string | null`: the label of the credential store a path names (`'login keychain'`, `'browser logins or cookies'`, `'Notes database'`, `'Firefox logins'`, `'saved Wi-Fi/keychain data'`), else null. Matches by basename, case-insensitive, with an optional `-wal`, `-shm` or `-journal` suffix: `login.keychain-db`, `keychain-2.db`, `Login Data`, `Cookies`, `Web Data`, `Local State`, `Cookies.binarycookies`, `cookies.sqlite`, `key4.db`, `logins.json`, `NoteStore.sqlite`, `seed.seco`; and any path containing `/Library/Keychains/` or `/Local Extension Settings/`.
  - `export const COPY_TOOLS: Set<string>`: `cp ditto rsync scp zip tar sqlite3 cat`.
- Consumes: `oddLocation`, `strongPlace`, `resolvePath` (`src/rules/locations.ts`), `isUnsigned`, `isAdhoc`, `cmdline` (`rules.ts`).

- [ ] **Step 1: Write the failing tests** in `test/rule-credential-store-copy.test.ts`, building captures with `capture`, `proc`, `img`, `apple`, `op` from `test/synth.ts` and reading findings through `analyze(...)`:
  - `cp of the login keychain into /tmp is high`: platform `cp` with args `['cp','/Users/u/Library/Keychains/login.keychain-db','/tmp/login.keychain-db']` and a `create` of the destination → finding `credential-store-copy`, severity `high`.
  - `cat of a keychain file is med`: platform `cat` naming `/Users/u/Library/Keychains/login.keychain-db`, no other path → `med`.
  - `an unsigned writer creating Login Data in a hidden folder is high`: unsigned image (`signingId: null`), `create` of `/Users/u/Documents/.k/Login Data` (a hidden folder buried below a visible one) → `high`.
  - `a browser's own profile is not flagged`: `create` of `/Users/u/Library/Application Support/Google/Chrome/Default/Cookies` by a team-signed Chrome image → no `credential-store-copy` finding.
  - `a backup volume is not flagged`: `create` of `/Volumes/Backup/Login Data` → none.
  - `credential-store-copy tolerates a capture with missing data`: an image with `path: null`, `args: null`, and a process with no `fileOps` → no throw, no finding.
- [ ] **Step 2: Run** `npx vitest run test/rule-credential-store-copy.test.ts`. Expected: FAIL (no such rule).
- [ ] **Step 3: Implement** `credentialStore` and `COPY_TOOLS`, then the rule: id `credential-store-copy`, title `Credential store copied`, scope `'process'`, severity `med`, `matchProcess(p, m)`. Evidence per hit: (a) each `create`, or `rename` destination (`toPath`), whose `credentialStore` is non-null and whose `oddLocation` is strong with kind in `temp`, `shared`, `downloads`, `hidden` (not `volume`, not weak kinds); (b) each non-inherited image whose basename is in `COPY_TOOLS` and with any argument (resolved against `img.cwd`) naming a credential store. Severity `high` when the writer's last non-inherited image is unsigned, ad-hoc, or runs from an odd location; or when a (b) hit also has another argument in a strong place; otherwise `med`. The explanation says what was copied and that stealers stage these files before upload; it names the false-positive sources (backup tools, Migration Assistant).
- [ ] **Step 4: Run** the new test file. Expected: PASS.
- [ ] **Step 5: Register.** `MITRE_NAMES`: add `T1555.003` Credentials from Web Browsers, `T1005` Data from Local System, `T1074.001` Local Data Staging (verify the names on attack.mitre.org). Add the stage entry and the README row.
- [ ] **Step 6: Lab step.** In `synthetic_story`, before the `ev_exit 55.0` line: run the learner's shell `cp` of `/Users/learner/Library/Keychains/login.keychain-db` to `$LAB/login.keychain-db` (new pid in 7600+, same `run` pattern as the neighbors) and `answer keychain-copy credential-store-copy high queued 'Keychains/login.keychain-db' '<note>'`. Add `credential-store-copy` to the "Not set off in live mode" comment in `live_answers`.
- [ ] **Step 7: Run** `npm test`. Expected: all green. If a fixture-based expectation changed because the new rule legitimately fired on the synthetic fixture, update that expectation; if it fired wrongly, tighten the rule.
- [ ] **Step 8: Commit** `feat: flag credential stores copied to staging places`

### Task 2: `apple-masquerade`

**Files:**
- Modify: `src/rules/rules.ts` (rule, and `persistence-item` severity), `src/rules/mitre.ts`, `src/ui/GuideScreen.tsx` (stage "Getting past the defences"), `README.md`, `scripts/ficus-lab.sh`
- Test: `test/rule-apple-masquerade.test.ts`

**Interfaces:**
- Consumes: `SYSTEM_DIRS`, `isAdhoc`, `launchTarget`, `persistenceSeverity` (all in `rules.ts`), `LAUNCH_DIR` regex.
- Produces: `export const APPLE_LABEL_PLIST: RegExp` in `rules.ts`, matching `/(?:Users/<u>/Library/LaunchAgents|Library/Launch(?:Agents|Daemons))/.?com.apple.<anything>.plist`, case-insensitive; reused by the `persistence-item` sharpening.

- [ ] **Step 1: Write the failing tests** in `test/rule-apple-masquerade.test.ts`:
  - `ad-hoc code claiming an Apple signing ID is high`: non-platform image, `signingId: 'com.apple.finder.helper'`, `csFlags: 0x2` → `apple-masquerade` high.
  - `a genuine non-platform Apple signature is not flagged`: `signingId: 'com.apple.dt.Xcode'`, `csFlags: 0`, `isPlatform: false` → none.
  - `a platform binary is not flagged`: `apple('/usr/bin/curl', …)` → none.
  - `a non-Apple writer of a com.apple plist in a user's LaunchAgents is high`: unsigned image, `create` of `/Users/u/Library/LaunchAgents/com.apple.updater.plist` → high.
  - `the same plist written by Apple's installer is not flagged`: platform `installd` writing `/Library/LaunchDaemons/com.apple.foo.plist` → none.
  - `a hidden com.apple plist name counts`: `create` of `/Library/LaunchDaemons/.com.apple.x.plist` by a team-signed non-Apple writer → `med`.
  - `a launch item named com.apple that runs a non-Apple program is high`: `persistenceItem({ plistPath: '/Library/LaunchDaemons/com.apple.sync.plist', executablePath: '/Library/Caches/sync', itemType: 4 })` → `persistence-item` evidence mentions the Apple-named plist and severity `high`; the same plist running `/usr/libexec/foo` stays as before.
  - `apple-masquerade tolerates a capture with missing data`.
- [ ] **Step 2: Run** the new test file. Expected: FAIL.
- [ ] **Step 3: Implement the rule**: id `apple-masquerade`, title `Pretends to be Apple`, scope `'image'`, severity `high`. Part (a): the image's signing ID starts `com.apple.`, `!isPlatform` and `isAdhoc` → high, evidence `<path> is ad-hoc signed as <signingId>`. Part (b), evaluated only on the process's first non-inherited image: any `create` or `rename` destination matching `APPLE_LABEL_PLIST` whose writer image is not Apple-signed (not platform, and signing ID not `com.apple.*` with a non-ad-hoc signature) → `high` in a user's `~/Library/LaunchAgents` or when the writer is unsigned or ad-hoc, `med` otherwise.
- [ ] **Step 4: Sharpen `persistence-item`.** In its `matchItem`, when `item.plistPath` matches `APPLE_LABEL_PLIST` and the launch target is not under `/System/`, `/usr/`, `/bin/`, `/sbin/` or `/Library/Apple/` and no captured image at that path is platform, set severity `high` and add `Apple-named plist but runs <target>` to the evidence. Everything else about the rule is unchanged.
- [ ] **Step 5: Run** the new test file. Expected: PASS.
- [ ] **Step 6: Register.** `MITRE_NAMES`: add `T1036.005` Masquerading: Match Legitimate Name or Location. Stage entry, README row.
- [ ] **Step 7: Lab step.** Before the `ev_exit 55.0` line: an unsigned program (`run_as … unsigned`) from `/Users/Shared/` that creates `/Users/learner/Library/LaunchAgents/com.apple.softwareupdate.helper.plist` (`ev_create`); `answer masquerade apple-masquerade high queued 'softwareupdate.helper' '<note>'`. Add to the "Not set off in live mode" comment.
- [ ] **Step 8: Run** `npm test`. Expected: all green (see Task 1, Step 7 for fixture changes).
- [ ] **Step 9: Commit** `feat: flag non-Apple code wearing an Apple name`

### Task 3: `clickfix-paste-chain`

**Files:**
- Create: `src/rules/context.ts`
- Modify: `src/rules/rules.ts` (export `pipeLang`; add the rule), `src/rules/mitre.ts`, `src/ui/GuideScreen.tsx` (stage "Execution"), `README.md`, `scripts/ficus-lab.sh`
- Test: `test/rule-clickfix-paste-chain.test.ts`

**Interfaces:**
- Produces, in `src/rules/context.ts` (Task 4 consumes both):
  - `export function siblings(m: CaptureModel, p: Process): Process[]`: other non-ghost processes with the same non-null `originalParent`, excluding `p`.
  - `export function underAgentShell(m: CaptureModel, p: Process): boolean`: true when the original parent's image at `p.firstSeq` has an argument matching `/\.(?:claude\/shell-snapshots|codex\/shell_snapshots|cursor\/shell-snapshots)\//`. AI-coding agents run `base64 -d` and `curl` through these shells.
  - `export const PASTE_WINDOW_MS = 3000`.
- Consumes: `pipeLang` (now exported), `osascriptArgs`, `parseOpts`, `hasOpt`, `CURL_SPEC`, `timeMs`, `imageAt`.

- [ ] **Step 1: Write the failing tests.** Helper builds one parent shell process and several children (`originalParent` set to the parent's id; images with `time` offsets and `stdinIsPipe: true` for the reader):
  - `a decoder and a piped shell under one parent is a paste chain`: `base64 -d` and `bash -s` (reader) 1 s apart → `clickfix-paste-chain` high on the reader; `shell-from-pipe` also present.
  - `curl -k piped to zsh is a paste chain`: `curl -kfsSL https://x/y` and a piped `zsh` → high.
  - `curl with a custom user agent piped to zsh is a paste chain`: `curl -A 'Mac OS X 10_15_7' -fsSL …`.
  - `plain curl piped to bash is not a paste chain`: `curl -fsSL …` and piped `bash` → only `shell-from-pipe`.
  - `siblings more than 3 s apart are not a chain`.
  - `an osascript fed from a pipe after curl -k is a paste chain`.
  - `a decoder under an AI agent shell is ignored`: parent image args contain `/.claude/shell-snapshots/x.sh`.
  - `clickfix-paste-chain tolerates a capture with missing data`: reader whose `originalParent` is null, or whose `time` is null.
- [ ] **Step 2: Run** the new test file. Expected: FAIL.
- [ ] **Step 3: Implement** `context.ts`, then the rule: id `clickfix-paste-chain`, title `Pasted command: fetch, decode and run`, scope `'image'`, severity `high`. The reader is an image where `pipeLang(img) !== null`, or `basename(path) === 'osascript'` with `stdinIsPipe === true` and `osascriptArgs(rest).source === 'stdin'`; once per process (first matching image). A sibling counts when its first non-inherited image time is within `PASTE_WINDOW_MS` of the reader's and it is: a **decoder** (`base64` with `-d`/`-D`/`--decode`; `openssl` with `enc` and `-d`; `xxd` with `-r`) or a **marked fetcher** (`curl` or `nscurl` with `-k`/`--insecure` or `-A`/`--user-agent` via `parseOpts(…, CURL_SPEC)`; `wget` with `--no-check-certificate`). Skip when `underAgentShell`. Evidence names the reader and the matching sibling command lines.
- [ ] **Step 4: Run** the new test file. Expected: PASS.
- [ ] **Step 5: Register.** `MITRE_NAMES`: add `T1204.004` Malicious Copy and Paste. Stage entry ("Execution"), README row.
- [ ] **Step 6: Lab step.** Under a new shell started from `$TERMINAL` (as `$ZSH2` is): `base64 -d` and a `bash` with stdin kind `pipe` (the way the existing `curl … | bash -s` step makes one) 1 s apart; `answer paste clickfix-paste-chain high queued '<marker unique to the piped bash args>' '<note>'`. Add to the live-mode comment.
- [ ] **Step 7: Run** `npm test`. Expected: all green.
- [ ] **Step 8: Commit** `feat: flag the pasted fetch-decode-run chain`

### Task 4: `risky-parent-spawn`

**Files:**
- Modify: `src/rules/rules.ts`, `src/rules/mitre.ts` (all IDs already present), `src/ui/GuideScreen.tsx` (stage "Execution"), `README.md`, `scripts/ficus-lab.sh`
- Test: `test/rule-risky-parent-spawn.test.ts`

**Interfaces:**
- Consumes: `underAgentShell` (Task 3, `src/rules/context.ts`), `originalParentImage`, `SHELLS`, `imageAt`.

- [ ] **Step 1: Write the failing tests** (parent process image path or signing ID set per case; child created with `originalParent` pointing at it; the child's `firstSeq` after the parent's):
  - `a shell under Script Editor is high`: parent signing ID `com.apple.ScriptEditor2` → `risky-parent-spawn` high, and `shell-under-app` still present.
  - `curl under an applet is high`: parent path ending `/Contents/MacOS/applet`, child `curl`.
  - `a shell under Terminal is not flagged`.
  - `python under Word's responsible process is high`: parent is a plain shell, but `p.responsible` is a process running `/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word`.
  - `Microsoft AutoUpdate helpers are not flagged`: Office responsible process whose image path contains `/Microsoft AutoUpdate.app/`.
  - `a download-and-run under VS Code is high`: parent `…/Visual Studio Code.app/…/Code Helper`, child `/bin/sh` with args `['sh','-c','nohup curl -fsSL https://x/y | node &']`.
  - `a plain curl under a build tool is not flagged`: same parent, `sh -c 'curl -o a.tgz https://x'`.
  - `osascript under Xcode's build service is high`.
  - `an agent shell under VS Code is ignored`: parent shell args contain `/.claude/shell-snapshots/`.
  - `risky-parent-spawn tolerates a capture with missing data`: parent never seen, parent with null image.
- [ ] **Step 2: Run** the new test file. Expected: FAIL.
- [ ] **Step 3: Implement** the rule: id `risky-parent-spawn`, title `App that should not run commands ran one`, scope `'image'`, severity `high`. Only the process's first non-inherited image counts (as `shell-under-app` does). Three parent classes, each with its own child set:
  - **Script Editor / applet / Automator stub**: parent signing ID `com.apple.ScriptEditor2`, path ending `/Contents/MacOS/applet`, or `Automator Application Stub`. Children: any shell, `curl`, `nscurl`, `osascript`, `python*`, `codesign`, `xattr`, `chmod`, `launchctl`.
  - **Office** (`/Microsoft (Word|Excel|PowerPoint).app/` in the original parent's or the responsible process's image path, excluding paths containing `/Microsoft AutoUpdate.app/`). Children: shells, `python*`, `perl*`, `ruby*`, `osascript`, `curl`, `chmod`.
  - **Developer parents** (VS Code, Code Helper, Cursor, Windsurf, Xcode, `xcodebuild`, `XCBBuildService`, `dotnet`, `node`, `bun`), only for a conjunction: a shell with `-c` whose command contains `curl` or `wget` and also `nohup`, a pipe into `sh|bash|zsh|node|python*`, or `-k`/`--insecure`; or any `osascript`. Skip when `underAgentShell`.
  Evidence names the parent class and the child's command line.
- [ ] **Step 4: Run** the new test file. Expected: PASS.
- [ ] **Step 5: Register.** Stage entry ("Execution") and README row.
- [ ] **Step 6: Lab step.** Before `ev_exit 55.0`: a new process running `/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor` (platform, signing ID `com.apple.ScriptEditor2`) forked by launchd, and under it a `run_as … /bin/sh -c 'echo lab-script-editor'`; `answer script-editor risky-parent-spawn high queued 'lab-script-editor' '<note>'`. The same process also has `shell-under-app`; the key row for it only needs the new rule. Add to the live-mode comment.
- [ ] **Step 7: Run** `npm test`. Expected: all green.
- [ ] **Step 8: Commit** `feat: flag Script Editor, Office and developer-tool parents that run commands`

### Task 5: `dropped-then-executed` and the file ledger

**Files:**
- Create: `src/rules/ledger.ts`
- Modify: `src/rules/locations.ts` (add `hiddenName`), `src/rules/rules.ts`, `src/rules/mitre.ts`, `src/ui/GuideScreen.tsx` (stage "Delivery"), `README.md`, `scripts/ficus-lab.sh`
- Test: `test/ledger.test.ts`, `test/rule-dropped-then-executed.test.ts`

**Interfaces:**
- Produces, in `src/rules/ledger.ts`:
  - `export interface DropRecord { path: string; writer: ProcId; seq: number; ms: number | null }`
  - `export interface UnlinkRecord { seq: number; ms: number | null }`
  - `export interface FileLedger { drops: Map<string, DropRecord[]>; unlinks: Map<string, UnlinkRecord[]> }`
  - `export function fileLedger(m: CaptureModel): FileLedger`: built once per model (memoized in a `WeakMap`). Keys are `normPath(path).toLowerCase()`. A drop is a `create` at its `path` or a `rename` at its `toPath`; an unlink is an `unlink` at its `path`. Times through `timeMs`; null stays null.
  - In `locations.ts`: `export function hiddenName(path: string): boolean`: the basename starts with `.` (and is not `.` or `..`).
- Consumes: `oddLocation`, `inBuildDir`, `HOME` (`locations.ts`), `isUnsigned`, `isAdhoc`, `cmdline`, `timeMs`.

- [ ] **Step 1: Write the failing ledger tests** (`test/ledger.test.ts`): `create and rename destinations are drops`; `keys ignore case and /private`; `unlinks are indexed separately`; `a null time gives ms null`; `the ledger is built once per model` (same object on a second call).
- [ ] **Step 2: Write the failing rule tests** (`test/rule-dropped-then-executed.test.ts`; FileOps carry explicit `time` and `seq`, images explicit `time`):
  - `curl output run 3 s later from /tmp is med`: team-signed image.
  - `an unsigned drop is high`.
  - `a drop deleted 20 s after the run is high`: `unlink` of the path 20 s after the exec.
  - `a hidden file in the home folder is high`: `/Users/u/.helper` written by `curl`, run 2 s later (the case `odd-location-exec` misses today).
  - `a drop older than 15 s is not flagged`.
  - `go-build output is not a drop`: `/var/folders/ab/cd/T/go-build123/b001/exe/x` written by `go`.
  - `toolchain writers are skipped`: writer `clang` or `ld` into `/tmp/a.out`, run immediately.
  - `an installer writing to /Applications is not flagged`.
  - `dropped-then-executed tolerates a capture with missing data`: null exec time, null drop time, null path.
- [ ] **Step 3: Run** both test files. Expected: FAIL.
- [ ] **Step 4: Implement** `hiddenName`, `ledger.ts`, then the rule: id `dropped-then-executed`, title `Ran a file written just before`, scope `'image'`, severity `med`, constants `DROP_WINDOW_MS = 15_000`, `DELETE_WINDOW_MS = 60_000`. Candidate images: non-inherited, with a path, where `oddLocation(path)` is strong, or `hiddenName(path)` under a home folder outside `inBuildDir`. Find the latest ledger drop of the path with `seq` below the image's `seq` and a non-null time difference within `DROP_WINDOW_MS`; skip when the writer's last image basename is a toolchain tool (`go cargo rustc swift swiftc clang clang++ gcc cc ld xcodebuild make cmake ninja brew`). Severity `high` when the path was unlinked within `DELETE_WINDOW_MS` after the exec, the name is hidden, or the image is unsigned or ad-hoc (non-platform); else `med`. Evidence: path, writer, seconds before the run, and the delete delay when present.
- [ ] **Step 5: Run** both test files. Expected: PASS.
- [ ] **Step 6: Register.** `MITRE_NAMES`: add `T1070.004` File Deletion, `T1564.001` Hidden Files and Directories. Stage entry ("Delivery"), README row.
- [ ] **Step 7: Lab step.** Before `ev_exit 55.0`: a `curl` (`run`, `-o /private/tmp/lab/stage2`) whose `create` is emitted 1 s before an ad-hoc program (`run_as … adhoc …`) executes `/private/tmp/lab/stage2`; `answer dropped dropped-then-executed high queued 'lab/stage2' '<note>'`. Add to the live-mode comment.
- [ ] **Step 8: Run** `npm test`. Expected: all green.
- [ ] **Step 9: Commit** `feat: flag files that ran right after something wrote them`

---

### Self-review notes

- **Spec coverage:** rules 1–5 of the report's shortlist map to Tasks 2, 4, 5, 3, 1. Report ranks them 1 to 5 by corroboration; the tasks run cheapest-first, and Task 4 depends on Task 3's `context.ts`. Not in this plan, by decision: the shared allow-list module and `oddLocation` dot-file patch (the report's implement-first items) and `shell-under-app` changes. Task 5 uses its own `hiddenName` instead, so the patch can land later without changing these rules' tests.
- **Narrowed first versions:** `dropped-then-executed` fires only for strong odd places and hidden home names (report: escalation logic starts wider; /Applications and Sparkle-style updaters would flood). `clickfix-paste-chain` pairs through the shared original parent within 3 s, because the model keeps no process group id; it needs a decoder or a marked fetcher, so plain `curl | bash` installers stay at `shell-from-pipe`. `apple-masquerade` skips the `/Library/Caches/com.apple.*` directory and name-only parts.
- **Open contradictions from the report that these rules touch:** MITRE IDs for the paste chain and masquerade (newer ATT&CK IDs exist); the drop window (report notes 1 s, 15 s and 5 min across sources; 15 s used); whether `img.script` is `/dev/fd/N` for `bash <(curl …)` (not covered by Task 3; check in a lab capture).
