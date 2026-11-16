# Learning Lab Script Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One bash script, `scripts/gameleira-lab.sh`, that writes a teaching capture setting off every Gameleira rule: `synthetic` builds it by hand, `live` runs harmless steps on a real Mac under `sudo eslogger`; both write an answer key.

**Architecture:** A single bash 3.2-compatible script with small `printf` JSON helpers (process object, fork, exec, exit, create, rename, btm add) mirroring `scripts/make-synthetic-lab.mjs`, a synthetic story built from those helpers, and a live mode that runs each step as a child process in a lab folder. A Vitest test runs the synthetic mode through `buildModel` and `analyze` and checks it against the answer key.

**Tech Stack:** bash 3.2 (macOS) / bash 5 (CI Linux), Vitest, the repo's TypeScript model and rule engine.

**Spec:** `docs/superpowers/specs/2026-11-16-learning-lab-script-design.md`

## Global Constraints

- Synthetic mode uses bash builtins only: no `jq`, `date`, `md5`, `shasum`, `$RANDOM`, `$USER`, `$HOME`. Output is byte-identical on every run.
- Bash 3.2 compatible: no associative arrays, no `${x,,}`, no `mapfile`, no `|&`.
- Synthetic capture: invented user `learner`, uid 502, home `/Users/learner`; `version` 11; never a `telemetry_version` key.
- Live mode: macOS only, refuses to run as root; only `eslogger` runs under sudo; every step runs as the user, as a child process, with cwd in `mktemp -d /tmp/gameleira-lab.XXXXXX`.
- Live mode never: names a real keychain item, runs `dscl -authonly` against a real account, runs spctl/networksetup/add-trusted-cert/authorizationdb, leaves the plist or job behind.
- Default outputs under `scratch/` (gitignored): `scratch/gameleira-lab-<mode>.jsonl` and `scratch/gameleira-lab-<mode>.answers.tsv`.
- Answer key columns, tab-separated, header line first, `#` comment lines allowed: `step rule severity queue marker note`. Queue values: `item`, `queued`, `burst`, `in-chain`, `context` (precedence as in the spec).

## Review Focus

- A home or lab path containing a space or a quote (`Lab Editor.app`, osascript `display dialog "..."`) must come out as valid JSON: the test asserts `badLines` 0, and Task 1 adds a `json_str` test case with `"`, `\` and a tab.
- Running `live` on Linux, or under `sudo`, must refuse with a message and exit non-zero before touching anything: Task 3 tests both refusals.
- Ctrl-C during live mode must still bootout the job, remove the plist, stop eslogger and delete the lab folder: Task 3 puts all of that in one `trap cleanup EXIT INT TERM` function and checks it by hand in the manual run.
- A rule added to `RULES` later without a synthetic step must fail CI, not slip through: Task 2's test iterates `RULES`, not a hard-coded list.
- `-o` pointing at a path whose folder does not exist: the script creates the folder (`mkdir -p`); Task 1 tests `-o` into a fresh temp subfolder.

---

### Task 1: Script skeleton, JSON helpers, and the test harness

**Files:**
- Create: `scripts/gameleira-lab.sh` (executable)
- Create: `test/lab-script.test.ts`
- Add (already written): `docs/superpowers/specs/2026-11-16-learning-lab-script-design.md`, this plan

**Interfaces:**
- Produces (bash, in the script):
  - `json_str STRING` → prints a JSON string literal (quotes included), escaping `\`, `"`, `\n`, `\r`, `\t` and other control characters as `\u00XX`.
  - `json_arr STRING...` → prints a JSON array of strings.
  - Process registry in parallel indexed arrays keyed by a small integer handle: pid, pidversion, path, signing id, team id, flags kind (`platform|team|adhoc|unsigned`), ppid, original ppid, parent handle, responsible handle, ruid, euid, rgid, egid, start time, session, group.
  - `new_proc VAR pid pv path kind signing_id team_id parent_handle [opts]` sets VAR to a new handle.
  - `ev_fork SEC parent_handle child_pid child_pv` (echoes the child handle via a global `LAST`), `ev_exec SEC handle path kind signing_id team_id cwd fds_kind ARGS...` (`fds_kind` is `tty` or `pipe`; optional script path through a global `EXEC_SCRIPT` reset after each call), `ev_exit SEC handle`, `ev_create SEC handle fullpath`, `ev_rename SEC handle from to`, `ev_btm_add SEC item_url app_url item_type executable_path app_handle_or_empty`.
  - Events are emitted in call order; the story calls them in time order. `SEC` is seconds (decimal string, e.g. `5.2`) after `2026-03-14T10:00:00Z`; time strings are formed with integer arithmetic only. `global_seq_num` and `mach_time` count up per emitted line.
  - `answer step rule severity queue marker note` appends a row to the key.
- Produces (CLI): `synthetic --stdout`, `synthetic --answers` (key to stdout), `synthetic [-o FILE]`, `--help`; unknown arguments exit 2 with usage.
- Produces (test helpers in `test/lab-script.test.ts`): `runLab(...args: string[]): string` runs `/bin/bash scripts/gameleira-lab.sh` with `execFileSync`.

- [ ] **Step 1: Write the failing tests**

```ts
test('synthetic --stdout is a clean schema 11 capture', () => {
  const m = buildModel(runLab('synthetic', '--stdout').split('\n'));
  expect(m.stats.badLines).toBe(0);
  expect(m.stats.versions).toEqual([11]);
  expect(m.stats.events).toBeGreaterThan(0);
});
test('synthetic output is the same on every run', () => {
  expect(runLab('synthetic', '--stdout')).toBe(runLab('synthetic', '--stdout'));
});
test('json_str escapes quotes, backslashes and control characters', () => {
  // the script, sourced with GAMELEIRA_LAB_SOURCE_ONLY=1, exposes its helpers
  const out = execFileSync('/bin/bash', ['-c', `GAMELEIRA_LAB_SOURCE_ONLY=1 . ${SCRIPT}; json_str "$1"`, '_', 'a"b\\c\td'])
    .toString();
  expect(JSON.parse(out)).toBe('a"b\\c\td');
});
test('-o writes the capture and the answer key, creating the folder', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-'));
  runLab('synthetic', '-o', path.join(dir, 'sub', 'x.jsonl'));
  expect(fs.readFileSync(path.join(dir, 'sub', 'x.jsonl'), 'utf8')).toBe(runLab('synthetic', '--stdout'));
  expect(fs.readFileSync(path.join(dir, 'sub', 'x.answers.tsv'), 'utf8')).toBe(runLab('synthetic', '--answers'));
});
test('an unknown argument exits 2', () => {
  expect(() => runLab('synthetic', '--nope')).toThrow(/status 2|code 2/);
});
```

- [ ] **Step 2: Run, confirm failure**

Run: `npx vitest run test/lab-script.test.ts`
Expected: FAIL (script missing).

- [ ] **Step 3: Implement the skeleton and helpers**

The script ends with `[ -n "$GAMELEIRA_LAB_SOURCE_ONLY" ] && return 0` before `main "$@"`. For this task the synthetic story is one shell (`zsh`, started before the capture) forking one `ls`: just enough to prove the helpers. JSON field layout per event follows `make-synthetic-lab.mjs` (`procObj`, `emit`, `exec`); flags constants: platform 637631233, team 570491649, adhoc 131075 (0x20003), unsigned 0 with null `signing_id`. Audit tokens take the handle's ruid/euid/rgid/egid. Time format `2026-03-14T10:00:05.200000000Z` (nine fractional digits).

- [ ] **Step 4: Run, confirm pass**

Run: `npx vitest run test/lab-script.test.ts` — Expected: PASS. Also `bash -n scripts/gameleira-lab.sh` exits 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/gameleira-lab.sh test/lab-script.test.ts docs/superpowers/specs/2026-11-16-learning-lab-script-design.md docs/superpowers/plans/2026-11-16-learning-lab-script.md
git commit -m "feat: lab script skeleton with printf JSON helpers"
```

### Task 2: The synthetic story and its answer key

**Files:**
- Modify: `scripts/gameleira-lab.sh` (replace the placeholder story; header comment tells the story with times)
- Modify: `test/lab-script.test.ts`

**Interfaces:**
- Consumes: Task 1 helpers and `answer`.
- Produces: `parseKey(tsv: string): KeyRow[]` in the test, `KeyRow = { step, rule, severity: Severity, queue: 'item'|'queued'|'burst'|'in-chain'|'context', marker, note }`.

- [ ] **Step 1: Write the failing tests**

```ts
const m = buildModel(runLab('synthetic', '--stdout').split('\n'));
const a = analyze(m);
const key = parseKey(runLab('synthetic', '--answers'));

test('every rule fires at least once', () => {
  const fired = new Set([...a.findings.values(), ...a.contextOnly.values()].flat().map(f => f.ruleId));
  for (const q of a.queue) for (const f of q.findings) fired.add(f.ruleId);
  expect([...RULES.map(r => r.id)].filter(id => !fired.has(id))).toEqual([]);
});
test.each(key)('$step: $rule ($severity, $queue)', (row) => {
  // item rows: a queue item of kind 'persistence' whose launch item plistPath contains the marker.
  // process rows: the process whose joined args (all images) contain the marker; exactly one such process.
  // assert: a finding with ruleId === row.rule and severity === row.severity (in a.findings or a.contextOnly);
  // and its queue status, by the spec's precedence, equals row.queue.
});
test('the key covers the queue concepts', () => {
  expect(new Set(key.map(r => r.queue))).toEqual(new Set(['item', 'queued', 'burst', 'in-chain', 'context']));
});
```

Queue status of a process row, computed in the test: not in `a.queue` → `context`; queue item with any own finding that is not gated (gated = rule `gated: 'always'`, or `'when-low'` with severity low) → `queued`; else `reconBurst` → `burst`; else `inFlaggedChain` → `in-chain`.

- [ ] **Step 2: Run, confirm failure**

Run: `npx vitest run test/lab-script.test.ts` — Expected: FAIL (rules missing from the placeholder story).

- [ ] **Step 3: Write the story**

Every step of the spec's synthetic table, with one `answer` row per taught finding. Story layout: a Terminal-started `zsh` (pid 6130-like, parent never seen) runs the infostealer steps as direct children; the piped `bash` runs `whoami` (the `in-chain` row); a separate `zsh` runs `sw_vers`, `uname -a`, `system_profiler SPHardwareDataType` within 4 s (`burst` rows); a team-signed `Monitor.app` runs `ps -axo pid,comm` once (`context` row for `recon`; it is also an Apple setuid tool, so give it euid 0 → `uid-mismatch` low `context`); a standalone updater `btm_launch_item_add` with no process (`item` row, med); `/Applications/Lab Notes.app` runs `/bin/sh -c ...` (`shell-under-app`). The uid-mismatch high step is `/Applications/Helper Tool.app/Contents/MacOS/helper`, team-signed, with euid 0 and ruid 502 (a path outside any odd location, so the only finding is the uid one). The drop step is a root daemon (`/Library/PrivilegedHelperTools/com.example.agent`, team-signed) with ruid 0, euid 502. Markers must each match exactly one process.

- [ ] **Step 4: Run, confirm pass**

Run: `npx vitest run test/lab-script.test.ts` — Expected: PASS. Run on bash 3.2 explicitly: the test already uses `/bin/bash`.

- [ ] **Step 5: Commit**

```bash
git add scripts/gameleira-lab.sh test/lab-script.test.ts
git commit -m "feat: synthetic lab capture that sets off every rule, with its answer key"
```

### Task 3: Live mode

**Files:**
- Modify: `scripts/gameleira-lab.sh`
- Modify: `test/lab-script.test.ts`

**Interfaces:**
- Consumes: `answer`, argument parsing from Task 1.
- Produces (CLI): `live [-o FILE]`, `live --answers` (key to stdout, no sudo, any OS).

- [ ] **Step 1: Write the failing tests**

```ts
test('live --answers names only real rules and lists what live mode cannot set off', () => {
  const tsv = runLab('live', '--answers');
  const ids = new Set(RULES.map(r => r.id));
  for (const r of parseKey(tsv)) expect(ids.has(r.rule), r.rule).toBe(true);
  expect(tsv).toMatch(/^#.*unsigned/m);
});
test.runIf(process.platform !== 'darwin')('live refuses to run off macOS', () => {
  expect(() => runLab('live', '-o', path.join(os.tmpdir(), 'x.jsonl'))).toThrow(/macOS/);
});
test('live refuses to run as root', () => {
  // GAMELEIRA_LAB_FAKE_UID=0 stands in for `id -u` so the test needs no sudo
  expect(() => execFileSync('/bin/bash', [SCRIPT, 'live'], { env: { ...process.env, GAMELEIRA_LAB_FAKE_UID: '0' } }))
    .toThrow(/not as root|without sudo/);
});
```

The macOS check runs before the root check, so on Linux the root test fails on the macOS message instead: make the root test `runIf(process.platform === 'darwin')`.

- [ ] **Step 2: Run, confirm failure**

Run: `npx vitest run test/lab-script.test.ts` — Expected: FAIL.

- [ ] **Step 3: Implement live mode**

Order: refuse non-macOS (`uname -s` ≠ Darwin), refuse uid 0, print what will happen (the dialog, the Background Items notification, the privacy warning), `sudo -v`, `LAB=$(mktemp -d /tmp/gameleira-lab.XXXXXX)`, start `sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > "$OUT" &`, wait (poll up to 10 s) until `$OUT` is non-empty, `sleep 5`, run the spec's live steps in order (each `( cd "$LAB" && ... ) || true`, each step printed as it runs), `sleep 5`, cleanup. `cleanup` (trap `EXIT INT TERM`, idempotent): `launchctl bootout gui/$UID/com.gameleira.lab 2>/dev/null`, remove `~/Library/LaunchAgents/com.gameleira.lab.plist`, `sudo kill -INT` the eslogger sudo pid and `wait` it, `rm -rf "$LAB"`, then write the key and print both paths. The key's first comment lines say: find `gameleira-lab.sh` in the Tree; markers match among its descendants; the not-covered list from the spec.

- [ ] **Step 4: Run, confirm pass**

Run: `npx vitest run test/lab-script.test.ts` — Expected: PASS.

- [ ] **Step 5: Manual run (needs the user's sudo)**

Run in a terminal: `scripts/gameleira-lab.sh live`. Then load `scratch/gameleira-lab-live.jsonl` through the engine (a throwaway `npx vitest run` snippet or the app) and check each key row. Also press Ctrl-C mid-run once and confirm no `~/Library/LaunchAgents/com.gameleira.lab.plist`, no `/tmp/gameleira-lab.*`, no `eslogger` process remain.

- [ ] **Step 6: Commit**

```bash
git add scripts/gameleira-lab.sh test/lab-script.test.ts
git commit -m "feat: live lab mode that records harmless attack steps with eslogger"
```

### Task 4: README

**Files:**
- Modify: `README.md` (new "Learning lab" section after "Capturing")

- [ ] **Step 1: Write the section**: both commands, what each is for, where the files go, the answer key columns, the live warnings (dialog, Background Items notification, sudo only for eslogger, privacy of the capture).
- [ ] **Step 2: Run the whole suite**: `npm test` — Expected: all pass (the README rules-table test is unaffected).
- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: describe the learning lab script"
```
