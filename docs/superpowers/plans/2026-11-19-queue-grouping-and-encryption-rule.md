# Grouped queue rows and a mass-encryption rule: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse runs of identical queued processes into one counted queue row, and add a `mass-rename` rule for ransomware-style rename bursts.

**Architecture:** Grouping happens at the end of `analyze()` (`src/rules/group.ts`): each `QueueItem` gains `members`, while `Analysis.findings`/`contextOnly` stay per process. Every place that maps a process to its queue row goes through `queueItemFor`. Verdicts stay stored per process; the session context writes a group row's verdict to every member. The rule is a process-scoped rule over `Process.fileOps`.

**Tech Stack:** TypeScript, React, Vitest (`npx vitest run <file>`), `npx tsc --noEmit`.

**Spec:** `docs/superpowers/specs/2026-11-19-queue-grouping-and-encryption-rule-design.md`

**Two pull requests.** Part A (Tasks 1-5) on branch `queue-grouping`; Part B (Tasks 6-7) on branch `mass-rename-rule`, cut from `main`, independent of Part A. The spec and this plan are committed with Part A (`git add -f` for the spec: a global gitignore hides that folder).

## Global Constraints

- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; PR bodies end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- A capture with no repeated processes must analyze and display exactly as before: every `members` has length 1 and no `×N` appears. The existing suite passes unchanged except where a task says a test changes.
- Group identity ignores pids, times and any evidence text. Thresholds for the rule are named constants: `MASS_RENAME_MIN_FILES = 10`, `MASS_RENAME_WINDOW_MS = 10_000`.
- Copy rule: the app's wording is plain and learner-facing (no jargon without a gloss); `×527` is the only new symbol.
- Fixtures: use `test/synth.ts` (`img`, `apple`, `proc`, `op`, `capture`); real captures are not in the repo, so tests never need `FIXTURES_DIR`.

## Review Focus

1. Two otherwise identical processes where only one owns a persistence finding: they must stay two rows.
2. The same program run with different arguments (`--dialog` vs `--other`): two rows, not one.
3. One member already has a verdict, the others none: toggling the group row sets all to the new status computed from the representative; undo restores each member's own previous status.
4. Selecting a non-representative member (from the tree or the member list) highlights the group row, and `j`/`k` move on from it.
5. A routine-marked program's group hides or stays as a whole; "N routine hidden" counts rows.
6. A group of 5,000 members: grouping is linear in processes (no pairwise comparison), and a verdict write does not freeze the UI (writes are queued like any other).
7. Part B: 10 renames to one new extension, over 10 s or less, by one process fires; 9 does not; 10 over a longer span does not; mixed extensions do not; `tmp`-style extensions do not; an app renaming `a.txt` to `a.txt` + same extension it already had does not.

---

# Part A: grouped queue rows

### Task 1: Group the queue in the engine

**Files:**
- Create: `src/rules/group.ts`
- Modify: `src/rules/engine.ts` (`QueueItem`, the end of `analyze`)
- Test: `test/queue-grouping.test.ts`

**Interfaces:**
- Produces:
  - `QueueItem.members: ProcId[]`: every member in sequence order, the first is the representative and equals `procId`; `[]` for a persistence item.
  - `groupQueue(m: CaptureModel, queue: QueueItem[]): QueueItem[]` in `group.ts`: returns the queue with each run of identical process items replaced by its first item carrying all `members`; other items untouched; preserves order.
  - `groupKey(m: CaptureModel, q: QueueItem): string | null`: `null` for a persistence item; otherwise the join of: latest image `path`, `signingId`, `teamId`, the latest captured args (null → a sentinel), the originalParent's latest image path (or `-`), the sorted `ruleId|severity|title` of `q.findings`, `inFlaggedChain`, `reconBurst`.
  - `queueItemFor(a: Analysis, id: ProcId): QueueItem | undefined`: the row holding `id` as a member; memoized per `Analysis` in a `WeakMap`.

- [ ] **Step 1: Write the failing tests** in `test/queue-grouping.test.ts`: build captures with `capture([...])`, a parent process and N child processes that each run the same image with a rule that fires (use `odd-location-exec`: path under `/Users/u/Downloads/`, ad-hoc signed; copy the image setup from `test/rule-risky-parent-spawn.test.ts`). Tests:
  - 3 identical children under one parent → `analyze(m).queue` has one row for them with `members` of length 3, `members[0] === procId`, sorted by first seq; `analysis.findings` still has 3 entries.
  - different args → 2 rows.
  - one child also owning a persistence item finding → 2 rows (Review Focus 1).
  - a lone process → `members` equals `[procId]`.
  - a persistence-only item → `members` equals `[]`.
  - `queueItemFor(a, member2)` returns the group row; unknown id returns `undefined`.
  - 5,000 identical children analyze within 2 seconds (Review Focus 6).
- [ ] **Step 2: Run** `npx vitest run test/queue-grouping.test.ts`. Expected: FAIL (`members` undefined / module missing).
- [ ] **Step 3: Implement** `group.ts` and the `QueueItem.members` field; every `queue.push` in `engine.ts` sets `members` (`[id]` for processes, `[]` for persistence items); `analyze` returns `queue: groupQueue(m, queue)` after the existing sort, with `sortSeq` of the representative. Group by a `Map<string, QueueItem>` keyed by `groupKey` (linear).
- [ ] **Step 4: Run** the new test file and `npx vitest run test/rules.test.ts test/triage-model.test.ts test/routine.test.ts`. Expected: PASS (fix helper builders that construct `QueueItem` literals by adding `members`).
- [ ] **Step 5: Commit** `feat(rules): group identical queued processes into one row`.

### Task 2: Look rows up through `queueItemFor`

**Files:**
- Modify: `src/ui/DetailPane.tsx` (lines using `queue.find(x => x.procId === ...)` and the severity map in `DidWhat`), `src/ui/TreeView.tsx` (the `q.procId` maps and `queue.find`), `src/ui/TimelineView.tsx` (severity map), `src/ui/lanes.ts` (`flaggedIds`), `src/report/report.ts` (`queued` set)
- Test: `test/queue-grouping.test.ts` (extend), existing `test/lanes*.test.ts`, `test/report-*.test.ts`

**Interfaces:**
- Consumes: `queueItemFor`, `QueueItem.members` from Task 1.
- Produces: `flaggedIds` returns every member of a group (so the timeline lanes keep every process); the tree and the detail pane treat any member as queued with the group's severity; the report's `queued` set contains every member.

- [ ] **Step 1: Write failing tests**: `flaggedIds(cap, queue)` for a 3-member group returns 3 ids; `buildReport` for a capture with a 3-member group treats a verdict on member 2 as queued (not under `userMarked`).
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement** by replacing each direct `procId` lookup with `queueItemFor(cap.analysis, id)` or by iterating `q.members`.
- [ ] **Step 4: Run** `npx vitest run test/queue-grouping.test.ts test/lanes.test.ts test/report-markdown.test.ts test/report-build.test.ts` (use the names that exist: `ls test | grep -E "lane|report"`). Expected: PASS.
- [ ] **Step 5: Commit** `refactor(ui): find a process's queue row by any member`.

### Task 3: Verdicts apply to every member

**Files:**
- Modify: `src/ui/session-context.tsx` (`setVerdict`, `toggleVerdict`, `undoLastVerdict`, the `LastVerdict` type), `src/ui/triage-model.ts` (`verdictKey` stays the representative id)
- Test: `test/session-group-verdict.test.tsx` (new; follow the harness used by the existing session-context tests, `ls test | grep -i session`)

**Interfaces:**
- Consumes: `queueItemFor`.
- Produces: `toggleVerdict(procId, pressed)` and `setVerdict(procId, status, note?)` write the verdict for every member of the row holding `procId` in the active capture (the note only for `procId` itself); `LastVerdict` gains `members: { procKey: ProcId; from: Status }[]`; `undoLastVerdict` restores each member's own previous status; `from`/`to` shown in the undo line come from the representative.

- [ ] **Step 1: Write failing tests**: group of 3, member 2 has `benign`; `toggleVerdict(rep, 'confirmed')` leaves all three `confirmed`; `undoLastVerdict()` restores member 2 to `benign` and the others to `unreviewed`; `toggleVerdict(member3, 'confirmed')` acts on the whole group; a lone process behaves exactly as before; `setNote` on one member leaves the others' notes empty.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** with a local helper `groupOf(procId): ProcId[]` (`queueItemFor(latest.current.capture.analysis, procId)?.members ?? [procId]`) and `await Promise.all`-free sequential `save` calls (the existing write queue serializes them); `from` for the toggle is computed once, from the clicked process's current status.
- [ ] **Step 4: Run** the new file and `npx vitest run test/ui.test.tsx`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(session): a verdict on a grouped row applies to every member`.

### Task 4: Show the count and the members

**Files:**
- Modify: `src/ui/QueueList.tsx` (row: `×N` after the name), `src/ui/TriageView.tsx` (selection and `j`/`k` match a row by any member), `src/ui/DetailPane.tsx` (new `Repeats` section in `ProcessDetail` for a group; member list with time and pid, each selectable), `src/ui/styles.css`, `src/report/report.ts` + its Markdown renderer (`ReportRow.repeats: number`, name printed with ` ×N`), `src/ui/triage-model.ts` (`overview` counts rows: unchanged)
- Test: `test/ui.test.tsx` or a new `test/ui-grouped-queue.test.tsx`; report test

**Interfaces:**
- Consumes: `QueueItem.members`, `queueItemFor`.
- Produces: `.qrow` shows `<span class="reps">×N</span>` only when `members.length > 1`; the detail pane for any member of a group shows "Repeated N times" with the members listed as buttons (`pid · clock time`); `ReportRow.repeats` (1 when alone), the Markdown row line ends its name with ` ×N` when `repeats > 1`.

- [ ] **Step 1: Write failing tests**: render a capture with a 3-member group; the queue has one option row containing `×3`; selecting member 2 (via the member list) marks that row `aria-selected`; pressing `j` moves to the next row; the report Markdown contains `×3`; a capture with no repeats renders no `×`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the four places. In `TriageView`, replace `verdictKey(r.item) === selKey` row matching with `r.item.members.includes(selKey)` (for persistence items, still the queue key).
- [ ] **Step 4: Run** `npx vitest run test/ui.test.tsx test/report-markdown.test.ts` and the new tests. Expected: PASS. Then start the dev server (`preview_start`), load a synthetic capture with a loop (`test/fixtures/synthetic-lab.jsonl` or a generated one) and check the row, the member list and a verdict in the browser; no console errors.
- [ ] **Step 5: Commit** `feat(ui): show a repeat count on grouped queue rows, and list the members`.

### Task 5: Say what changed, and finish Part A

**Files:**
- Modify: `src/ui/GuideScreen.tsx` (the Koi row in the lab section says "nothing groups the repeats": reword to say identical repeats are now one row, with the count), `lab/README.md` and `lab/reports/2026-11-19-koistealer.md` (add a dated "After grouping" note that the queue for this run is now about 2 rows; leave the original numbers as the finding), `lab/summarize-core.ts` (if the "triage queue of N items" line reads `queue.length`, say rows, and add the member count), `README.md`/`docs/` if they describe one row per process (`grep -rn "one row per" README.md docs src`)
- Test: `test/lab-summarize.test.ts` (adjust expectations if the summary line changes)

- [ ] **Step 1: Make the edits.**
- [ ] **Step 2: Run** `npx tsc --noEmit` (no output expected) and `npx vitest run` (all pass, same skips as `main`).
- [ ] **Step 3: Commit** `docs(lab): note that identical repeats are now one queue row`, then push `queue-grouping` and open the PR (include the force-added spec and plan; mention the lab's Koi capture as the motivating case; state that the real Koi capture was not re-run in CI).

---

# Part B: the `mass-rename` rule (branch `mass-rename-rule`, from `main`)

### Task 6: The rule

**Files:**
- Modify: `src/rules/rules.ts` (new rule object after `credential-store-copy`)
- Test: `test/rule-mass-rename.test.ts`

**Interfaces:**
- Produces: rule `{ id: 'mass-rename', title: 'Many files renamed to one new extension', severity: 'high', mitre: ['T1486'], scope: 'process' }` with `matchProcess(p)`; exported constants `MASS_RENAME_MIN_FILES = 10`, `MASS_RENAME_WINDOW_MS = 10_000`, and `TEMP_EXTENSIONS: ReadonlySet<string>` (`tmp part download crdownload swp bak partial`).

Behavior: over `p.fileOps` of kind `rename` with both `path` and `toPath`, take the lower-cased extension of `toPath` (text after the last `.` of the base name, none if no dot); keep renames whose new extension differs from the old name's extension and is not in `TEMP_EXTENSIONS`; group by new extension; fire when some group has `MASS_RENAME_MIN_FILES` or more renames inside any window of `MASS_RENAME_WINDOW_MS` (sliding over `time`, via `timeMs` from `src/model/util`). Evidence: `N files renamed to .ext in S s: a, b, c` (three example base names).

- [ ] **Step 1: Write failing tests** with `synth`/`op('rename', from, seq, to)` and file ops carrying `time` (extend `op` usage or build `FileOp` literals with `time` set 100 ms apart): the HeartBreaker shape (15 renames `x` → `x.heartbreaker` in 1.3 s) fires with severity high, MITRE `T1486`, evidence containing `.heartbreaker` and `15`; 9 renames does not; 10 over 30 s does not; 10 renames to 10 different extensions does not; 10 renames to `.tmp` does not; 10 renames where the old name already ended in the new extension does not; two groups (one under the threshold) report only the large one.
- [ ] **Step 2: Run** `npx vitest run test/rule-mass-rename.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement** `matchProcess` as described (sort each extension's times; two-pointer window).
- [ ] **Step 4: Run** the test file. Expected: PASS.
- [ ] **Step 5: Commit** `feat(rules): mass-rename, a burst of renames to one new extension`.

### Task 7: Register it, check it, finish Part B

**Files:**
- Modify: `docs/rules.md` (a table row; a test keeps it in step with `RULES`), `src/ui/GuideScreen.tsx` (`STAGES`: put `mass-rename` where impact/encryption fits; add a stage `Impact` if none does and the guide-rules test allows), `src/ui/triage-model.ts` (`EXPECTED` rename entry already lists its checks: add `'mass-rename'`; `ARG_CHECKS` is unaffected), `lab/expected/HeartBreaker.tsv` (the encryption row now names `mass-rename` as the expected rule), `lab/README.md` (pilot note: gap closed by this rule)
- Test: `test/guide-rules.test.tsx`, `test/rule-levels.test.ts`, `test/triage-model.test.ts` as they stand

- [ ] **Step 1: Make the edits;** run `npx vitest run test/guide-rules.test.tsx test/rule-levels.test.ts test/triage-model.test.ts test/rules.test.ts` and fix whatever consistency checks report (rule table, stage list, MITRE table in `src/rules/mitre.ts` if it needs `T1486`).
- [ ] **Step 2: Baseline check.** Rebuild the lab tool (`npm run build:lab`) and run the summarizer over the HeartBreaker run folder and the idle and benign baselines (`$FICUS_LAB_DATA/runs/...`; list them with `ls`): HeartBreaker must show `mass-rename` as a hit; the baselines must show no `mass-rename` finding. Record the outcome in `lab/README.md`. If a baseline fires, stop and report it instead of loosening the rule silently.
- [ ] **Step 3: Run** `npx tsc --noEmit` and `npx vitest run`. Expected: clean, all pass.
- [ ] **Step 4: Commit** `docs(rules): list mass-rename; HeartBreaker's encryption gap is closed`, push, open the PR.
