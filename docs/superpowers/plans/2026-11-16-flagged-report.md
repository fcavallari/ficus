# Flagged-process report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One click writes a Markdown report and a JSON report of every flagged row in the session's loaded captures, for secops to read and ingest.

**Architecture:** A pure module (`src/report/`) builds one `gameleira-report` v1 object from loaded captures, their analyses, the session's verdicts and routine marks; the JSON file is that object, the Markdown is rendered from it. A small React component puts the button in the session header and on the Triage overview and downloads both files.

**Tech Stack:** TypeScript, React 19, Vitest + Testing Library, fake-indexeddb. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-16-flagged-report-design.md`

## Global Constraints

- The `Report` types in Task 1's Interfaces are the v1 JSON contract; the spec's JSON sketch was updated to match them.
- No new dependencies; the page keeps `connect-src 'none'` (nothing is sent anywhere).
- JSON: `format: "gameleira-report"`, `version: 1`.
- File names: `<slug(session.name)>.<idHash(session.id)>.gameleira-report.md` and `.json` (reuse `slug`, `idHash` from `src/session/export.ts`).
- Environment variables never appear in either file.
- Redaction option is `exportOpts.redactArgs` from the session context (shared with Save session), default off; redacted arguments become `[redacted]` (reuse `REDACTED` from `src/session/export.ts`).
- File events shown per process: 20 (`FILE_OPS_SHOWN = 20`), with the total.
- `signature` values: `"apple-platform" | "team-signed" | "signed-no-team" | "adhoc" | "unsigned" | "unknown"`.
- Button labels: header **Report for security**; overview **Report flagged processes for security** with the line "Writes a Markdown file to read and a JSON file for security tools, with every flagged row, reviewed or not."
- Not-loaded warning copy: "<file> isn't loaded, so its flagged rows can't be included. Re-add it first, or export without it."
- Save session and the `gameleira-session` export are unchanged in behaviour.
- Pure modules under `src/report/` import nothing from React or the DOM.

## Review Focus

1. **A secret cut off at the evidence limit.** Rule evidence truncates command lines at 300 characters (`MAX_EVIDENCE`). With redaction on, a password straddling the cut must not leak as a prefix. Pinned in Task 3 (`redacts a secret that the evidence limit cuts in half`).
2. **Hostile names in Markdown.** A path or note holding backticks, `|`, `[x](y)`, `<script>` or newlines must not add Markdown structure or links. Pinned in Task 4 (`escapes hostile capture text`).
3. **A session with no flagged rows.** The report still writes, says "No flagged rows", and lists captures and coverage. Pinned in Task 1 (`a capture with an empty queue`) and Task 4 (`renders an empty report`).
4. **A verdict whose process is not in the model any more** (stored against a procKey the loaded capture lacks). It is reported under `userMarked` from its snapshot name, not dropped and not a crash. Pinned in Task 2 (`a verdict whose process is missing`).
5. **Captures loaded, but the active one not.** The header button still works from the loaded ones; the overview is not shown. Pinned in Task 5 (`header button works when the active capture is not loaded`).

---

## File structure

- Create `src/report/report.ts`: types, `buildReport`, `signatureOf`, `reportFileName`, redaction helpers.
- Create `src/report/markdown.ts`: `reportMarkdown`, escaping helpers.
- Modify `src/model/relations.ts`: add `registrant(m, item)` (moved out of `LaunchItem.tsx`).
- Modify `src/model/util.ts`: add `itemTypeName` (moved out of `LaunchItem.tsx`, re-exported there so existing imports keep working).
- Modify `src/rules/rules.ts`: export `cmdline`, `isUnsigned`, `isAdhoc` (no behaviour change).
- Create `src/ui/download.ts`: `downloadText`; `useSaveSession`'s download branch in `src/ui/ConfirmedTab.tsx` uses it.
- Create `src/ui/ReportButton.tsx`; use it in `src/ui/SessionScreen.tsx` (title row, beside Save session) and `src/ui/DetailPane.tsx` (`NothingSelected`).
- Tests: create `test/report.test.ts`, `test/report-markdown.test.ts`; add to `test/ui.test.tsx`.
- `README.md`: a **Report for security** bullet under "Using it".

---

### Task 1: Report model for loaded captures

**Files:**
- Create: `src/report/report.ts`
- Modify: `src/model/relations.ts`, `src/model/util.ts`, `src/ui/LaunchItem.tsx`, `src/rules/rules.ts`
- Test: `test/report.test.ts`

**Interfaces:**
- Consumes: `analyze`, `QueueItem`, `Finding` (`src/rules/engine.ts`); `applyRoutine`, `programKey` (`src/session/routine.ts`); `coverage`, `itemName`, `verdictKey` (`src/ui/triage-model.ts`, pure TS); `ancestry`, `childrenIndex`, `displayName` (`src/model/relations.ts`); `slug`, `idHash` (`src/session/export.ts`).
- Produces:

```ts
export const REPORT_FORMAT = 'gameleira-report';
export const FILE_OPS_SHOWN = 20;
export type Signature = 'apple-platform' | 'team-signed' | 'signed-no-team' | 'adhoc' | 'unsigned' | 'unknown';
export interface ReportInput {
  session: Pick<Session, 'id' | 'name'>;
  capRecs: CaptureRec[];
  loaded: Map<string, LoadedCapture>;
  verdicts: Verdict[];            // every verdict of the session
  routineKeys: Set<string>;
}
export interface ReportOpts { redactArgs: boolean; generated: string }
export interface ProcRef { name: string; pid: number }
export interface ReportImage { path: string | null; args: string[] | null; cwd: string | null; signingId: string | null;
  teamId: string | null; isPlatform: boolean; signature: Signature; script: string | null; stdinIsPipe: boolean | null;
  time: string | null; inherited: boolean }
export interface ReportLaunchItem { id: string; type: number | null; typeName: string; plistPath: string | null;
  executablePath: string | null; appPath: string | null; time: string;
  registeredBy: (ProcRef & { via: 'app' | 'instigator' | 'creator' }) | null }
export interface ReportRow {
  n: number;                       // 1-based, across the whole report, in Markdown order (see buildReport)
  key: string; kind: 'process' | 'persistence' | 'user-marked';
  name: string;
  severity: Severity | null;       // null only for 'user-marked'
  verdict: { status: Status; note: string; updated: string } | null;
  inFlaggedChain: boolean; reconBurst: boolean;
  hiddenAsRoutine: boolean; keptReason: string | null;
  findings: Pick<Finding, 'ruleId' | 'severity' | 'title' | 'explanation' | 'mitre' | 'evidence' | 'trait'>[];
  process?: { procId: string; pid: number; startTime: string | null; exitTime: string | null; images: ReportImage[];
    ancestry: ProcRef[]; responsible: ProcRef | null; children: number;
    fileOps: { total: number; shown: FileOp[] } };
  launchItems: ReportLaunchItem[];
}
export interface ReportCapture {
  fingerprint: string; fileName: string; size: number; events: number; processes: number;
  firstTime: string | null; lastTime: string | null; schemaVersions: number[];
  loaded: boolean;
  coverage?: { id: string; level: 'warn' | 'info'; title: string; detail: string; checks: string[] }[];
  contextOnly?: Record<string, number>;
  rows?: ReportRow[];
  userMarked?: ReportRow[];
  notLoaded?: { procKey: string; status: Status; note: string; snapshot: VerdictSnapshot }[];
}
export interface Report {
  format: typeof REPORT_FORMAT; version: 1; generated: string;
  session: { id: string; name: string }; redacted: boolean;
  summary: { rows: number; bySeverity: Record<Severity, number>; byVerdict: Record<Status, number>;
    hiddenAsRoutine: number; userMarked: number; capturesNotLoaded: number };
  captures: ReportCapture[];
}
export function buildReport(input: ReportInput, opts: ReportOpts): Report;
export function signatureOf(img: Image): Signature;
export function reportFileName(s: Pick<Session, 'id' | 'name'>, ext: 'md' | 'json'): string;
// src/model/relations.ts
export function registrant(m: CaptureModel, item: PersistenceItem): { id: ProcId; via: 'app' | 'instigator' | 'creator' } | null;
// src/model/util.ts
export function itemTypeName(t: number | null): string;
// src/rules/rules.ts: export the existing cmdline, isUnsigned, isAdhoc
```

Test fixture for this file: build `loaded` like `test/export.test.ts` does (`queued('synthetic-lab.jsonl')` → `{ fingerprint: 'fp', fileName: 'synthetic-lab.jsonl', size: 1, model: m, analysis: a }`), a `CaptureRec` for `fp`, `generated: '2026-11-16T12:00:00.000Z'`.

- [ ] **Step 1: Write the failing tests** in `test/report.test.ts`:
  - `every queue row is in the report, in queue order`: `report.captures[0].rows.map(r => r.key)` equals `a.queue.map(q => q.key)`; `report.format === 'gameleira-report'`, `version === 1`.
  - `verdicts and notes are carried, and an untouched row has none`: with a `confirmed` verdict (note `'n'`) on pid 7006 and `benign` on pid 7001, those rows have `verdict.status` `'confirmed'` / `'benign'`; some other row has `verdict === null`; an `unreviewed` verdict with note `''` also gives `null`.
  - `a routine-hidden row stays, marked`: pick the first queue row with `keepReason(q) === null` and a process; put `programKey(latestImage(p))` in `routineKeys`; that row has `hiddenAsRoutine: true`, `keptReason: null`; `summary.hiddenAsRoutine >= 1`; row count unchanged. A row with a high finding whose program is marked routine has `hiddenAsRoutine: false` and `keptReason` equal to `keepReason(q)`.
  - `process detail`: the pid 7006 row has `process.pid === 7006`, `process.ancestry[0].name` equal to `displayName(m, p.originalParent)`, `process.images` non-empty, and `JSON.stringify(report)` does not contain `"env"`.
  - `signature`: `signatureOf` returns `'apple-platform'` for `{ isPlatform: true }`, `'unsigned'` for not platform and no signingId, `'adhoc'` for signingId + csFlags `0x2`, `'team-signed'` with a teamId, `'signed-no-team'` with signingId and no teamId, `'unknown'` for `path: null` (build `Image` objects inline).
  - `launch items`: every row whose findings include `persistence-item` has `launchItems.length >= 1`; a `kind: 'persistence'` row's `launchItems[0].id` equals its `persistenceId`.
  - `file events are capped`: for a process with more than 20 file ops (make one by pushing 25 synthetic `FileOp`s onto a fresh model's process built with `buildModel(readLines('synthetic-lab.jsonl'))`), `fileOps.total === 25`, `shown.length === 20`.
  - `context-only counts`: `captures[0].contextOnly` equals counts per `ruleId` over `[...a.contextOnly.values()].flat()`.
  - `coverage and capture facts`: `captures[0].coverage` equals `coverage(m).notes` (same ids, in order); `schemaVersions` equals `m.stats.versions.filter(v => v > 0)`; `loaded === true`.
  - `summary`: `rows` equals the queue length; `bySeverity` and `byVerdict` sum to `rows`.
  - `numbering follows the Markdown order`: across all rows, sorting by `n` gives: severity high, med, low; within a severity, captures in report order then queue order; `n` runs 1..rows with no gaps.
  - `a capture with an empty queue`: a loaded capture whose `analysis.queue` is `[]` gives `rows: []`, `summary.rows === 0`, coverage still present.
  - `reportFileName`: matches `/^lab\.[0-9a-f]{8}\.gameleira-report\.md$/` for a session named `lab`.
  - `deterministic`: two builds with the same input stringify identically.

- [ ] **Step 2: Run them to see them fail**

Run: `npx vitest run test/report.test.ts`
Expected: FAIL, cannot resolve `../src/report/report`.

- [ ] **Step 3: Move `registrant` and `itemTypeName`; export `cmdline`, `isUnsigned`, `isAdhoc`.** `registrant` is `LaunchItem.tsx`'s app → instigator → creator choice (first id present in `m.processes`); `LaunchItem.tsx` calls it and keeps its labels. `itemTypeName` moves to `src/model/util.ts`; `LaunchItem.tsx` re-exports it.

- [ ] **Step 4: Implement `buildReport`, `signatureOf`, `reportFileName` in `src/report/report.ts`.**
  - Captures in report order: `capRecs` sorted by `fileName`, then `fingerprint`. A record with no entry in `loaded` gets `loaded: false` (filled in Task 2).
  - Hidden rows: `applyRoutine(analysis, model, routineKeys)`; a queue row not in its result `queue` is `hiddenAsRoutine: true`; `kept.get(key)` is `keptReason`. Rows come from `analysis.queue` (all of them).
  - Verdict: the session verdict with this fingerprint and `procKey === verdictKey(q)`; null when absent or `unreviewed` with an empty note.
  - `name`: `itemName(cap, q)`. `children`: length of `childrenIndex(m, 'original').get(id)` (build the index once per capture). `responsible`: `p.responsible` when not null and not `p.id`. `ancestry`: `ancestry(m, id, 'original')` mapped to `{ name: displayName, pid }`.
  - `launchItems`: for a persistence row, its item; for a process row, the items named by its findings' `persistenceId`, deduplicated, in finding order.
  - `n`: assign after all captures are built, in the order the Markdown prints (severity high → med → low, then capture order, then queue order; `user-marked` rows last, by capture then procKey).
  - `signatureOf` order: path null → `unknown`; `isPlatform` → `apple-platform`; `isUnsigned` → `unsigned`; `isAdhoc` → `adhoc`; teamId → `team-signed`; else `signed-no-team`.

- [ ] **Step 5: Run the tests**

Run: `npx vitest run test/report.test.ts test/ui.test.tsx`
Expected: PASS (ui tests guard the `LaunchItem` refactor).

- [ ] **Step 6: Commit**

```bash
git add src/report/report.ts src/model/relations.ts src/model/util.ts src/ui/LaunchItem.tsx src/rules/rules.ts test/report.test.ts docs/superpowers
git commit -m "feat: a report model of every flagged row in the loaded captures"
```

---

### Task 2: Captures not loaded, and processes the user marked

**Files:**
- Modify: `src/report/report.ts`
- Test: `test/report.test.ts`

**Interfaces:**
- Consumes: Task 1's types and `buildReport`.
- Produces: `ReportCapture.notLoaded`, `ReportCapture.userMarked`, `summary.userMarked`, `summary.capturesNotLoaded` filled.

- [ ] **Step 1: Write the failing tests:**
  - `a capture that is not loaded is listed with its verdicts`: add a `CaptureRec` `gone.jsonl` (fingerprint `gone`) and two verdicts on it (one `confirmed`, one `unreviewed` with note `''`); its report capture has `loaded: false`, no `rows`, `notLoaded` holding only the confirmed one; `summary.capturesNotLoaded === 1`.
  - `a verdict on a process the rules did not flag`: a `confirmed` verdict (note `'odd'`) on a process of the lab capture that is not in `a.queue` lands in `userMarked` with `kind: 'user-marked'`, `severity: null`, `findings` equal to its `a.contextOnly` findings (or `[]`), a `process` block, and is counted in `summary.userMarked`, not in `summary.rows` or `bySeverity`.
  - `a verdict whose process is missing`: a `confirmed` verdict with `procKey: 'nope'` and snapshot name `ghosty` lands in `userMarked` with `name: 'ghosty'` and no `process`.
  - `numbering`: `user-marked` rows are numbered after every queue row.

- [ ] **Step 2: Run to see them fail.** Run: `npx vitest run test/report.test.ts` — Expected: the four new tests FAIL.

- [ ] **Step 3: Implement.** User-marked: verdicts of a loaded capture whose `procKey` matches no queue row's `verdictKey`, excluding `unreviewed` with an empty note. Not loaded: same filter over that capture's verdicts.

- [ ] **Step 4: Run.** Run: `npx vitest run test/report.test.ts` — Expected: PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat: the report lists captures not loaded and processes the user marked"`

---

### Task 3: Redaction

**Files:**
- Modify: `src/report/report.ts`
- Test: `test/report.test.ts`

**Interfaces:**
- Consumes: `cmdline` (exported in Task 1), `REDACTED` from `src/session/export.ts`.
- Produces: `buildReport(input, { redactArgs: true, … })` honours the spec's field-level redaction; `report.redacted` mirrors the option.

- [ ] **Step 1: Write the failing tests:**
  Leak checks never search `JSON.stringify(report)`: JSON escaping (`"`, `\`) would hide a leaked copy. They walk every string value of the report object (`strings(report)`, a small recursive helper in the test), and search the Markdown separately.
  - `redaction hides the dscl password everywhere`: in a redacted report, no string value and not the Markdown contains `labpass-not-real`; in an unredacted one, both do. The pid 7016 row's last image args equal `['dscl', '[redacted]', '[redacted]', '[redacted]', '[redacted]']`.
  - `redaction reaches captures that are not loaded`: a not-loaded capture `gone` with a `confirmed` verdict whose snapshot args are `['dscl','.','-authonly','labuser','labpass-not-real']`: the secret is in no string value and not in the Markdown when redacted, and is present when not.
  - `no argument survives redaction outside kept fields`: per the spec's test: collect every argument after argv[0] (length ≥ 3) of every image in the model; drop those that occur in any kept field (an image path, `displayName` of any process, a file-op `path`/`toPath`, a launch item's plist/executable/app path, any `cwd` or `script`); assert at least one remains (the fixture's `display dialog "LAB DEMO…"` argument, with its quotes, must be among them). Walk the report's string values, skipping the keys `title`, `explanation` and `note`, and assert none contains any remaining argument. (Rule titles and explanations interpolate only subcommands and flags — checked in `src/rules/rules.ts`: `security <sub>`, `spctl <flag>`, `networksetup <flag>`, `-r <trust>` — so they are not redacted; notes are not redacted by design.)
  - `redacts a secret that the evidence limit cuts in half`: on a fresh `buildModel(readLines('synthetic-lab.jsonl'))`, set pid 7016's exec image args to `['dscl', '.', '-authonly', 'labuser', 'x'.repeat(280) + 'SECRETSECRETSECRET']`, `analyze` it, build a redacted report; no string value and not the Markdown contains `xxxxxxxxxx` or `SECRET`. (Task 4 lands after this one: add the Markdown half of each leak test in Task 4's Step 1.)
  - `notes are not redacted`: a note `'pw is hunter22'` appears verbatim in a redacted report.
  - `redacted flag`: `report.redacted` equals the option.

- [ ] **Step 2: Run to see them fail.** Expected: the new tests FAIL.

- [ ] **Step 3: Implement.** Redact `images[].args` and not-loaded snapshot `args` (element 0 kept). For each finding's `evidence`: first, where `imgIndex !== null`, replace `cmdline(img)` with `cmdline(redactedImg)` (same function, so the 300-character cut matches); then replace every remaining occurrence of that process's own arguments (length ≥ 3, argv[0] excluded, longest first) that are not kept-field values with `[redacted]`. Persistence-only rows' evidence holds paths only and is left as is.

- [ ] **Step 4: Run.** Run: `npx vitest run test/report.test.ts` — Expected: PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat: the report redacts command lines and the evidence built from them"`

---

### Task 4: Markdown

**Files:**
- Create: `src/report/markdown.ts`
- Test: `test/report-markdown.test.ts`

**Interfaces:**
- Consumes: `Report`, `ReportRow` (Task 1).
- Produces: `export function reportMarkdown(r: Report): string`; `export function code(s: string): string` (inline code span whose fence is one backtick longer than the longest backtick run in `s`, padded with a space when `s` starts or ends with a backtick, newlines shown as `⏎`); `export function text(s: string): string` (escapes `` \ ` * _ [ ] < > # | ! ~ `` with a backslash, newlines to a space).

Layout is the spec's "Markdown layout" section. Fixed wording, so the snapshot is stable:
- Title `# Gameleira report: <text(name)>`.
- Verdict line ends with "(Verdicts were set by the person who ran the capture, not by security staff.)"
- Redaction line: "Command-line arguments are redacted." or "Command lines are complete and may contain secrets."
- Severity headings `## High`, `## Medium`, `## Low`; then `## Marked by the user, not flagged by the rules`; then `## Captures not loaded`. Empty sections are left out. With no rows at all: the line "No flagged rows." after the summary.
- Row heading `### <n>. <text(name)> (pid <pid>): <text(first finding title)>` (no pid part when there is no process; no title part when no findings).
- "Command line" and "Program" come from the latest image with captured args (as `rowArgs` in `src/ui/triage-model.ts` picks it), falling back to the latest image when none has args; when the process exec'd other programs, a line "Also ran: <code(path)>, …" lists their paths in order.
- Signature words: `apple-platform` "Apple platform binary", `team-signed` "signed by team <teamId>", `signed-no-team` "signed, no team ID", `adhoc` "ad-hoc signed", `unsigned` "unsigned", `unknown` "unknown".
- "Started by" lists ancestry root first, ending in "this".
- Every value from the capture or the user goes through `code()` (paths, command lines, evidence) or `text()` (names, notes, titles).

- [ ] **Step 1: Write the failing tests** in `test/report-markdown.test.ts` (reuse Task 1's fixture setup; a small shared builder in `test/report-fixture.ts` is fine):
  - `snapshot of the lab report`: `expect(reportMarkdown(build())).toMatchSnapshot()`.
  - `agrees with the JSON`: for every row, the Markdown contains `### ${n}. ` followed by `text(name)`, and that heading sits under the heading for the row's severity (or the user-marked section).
  - `escapes hostile capture text`: a row whose name is ``a`b|c[x](http://e)<script>\n# h`` renders with no line starting with `#` other than real headings, no `](http` outside a code span, and the raw `<script>` only inside a code span or escaped as `\<script\>`.
  - `renders an empty report`: an empty-queue report contains "No flagged rows." and the `## Captures` section.
  - `redaction line`: "Command-line arguments are redacted." present iff `redacted`.
  - `not-loaded warning`: with a not-loaded capture, the Markdown names it before `## Captures`.
  - The Markdown halves of Task 3's leak tests (`labpass-not-real` on a loaded and on a not-loaded capture, and the cut-in-half secret): absent from `reportMarkdown` of the redacted report, present (the first two) in the unredacted one.

- [ ] **Step 2: Run to see them fail.** Run: `npx vitest run test/report-markdown.test.ts` — Expected: FAIL, module not found.

- [ ] **Step 3: Implement `reportMarkdown`, `code`, `text`.**

- [ ] **Step 4: Run, and read the snapshot once by eye** (it is what secops will read). Run: `npx vitest run test/report-markdown.test.ts` — Expected: PASS, one snapshot written.

- [ ] **Step 5: Commit** — `git add src/report/markdown.ts test/report-markdown.test.ts test/__snapshots__ && git commit -m "feat: render the report as Markdown"`

---

### Task 5: The button

**Files:**
- Create: `src/ui/download.ts`, `src/ui/ReportButton.tsx`
- Modify: `src/ui/ConfirmedTab.tsx` (use `downloadText`), `src/ui/SessionScreen.tsx`, `src/ui/DetailPane.tsx`, `src/ui/styles.css` (only if the layout needs it)
- Test: `test/ui.test.tsx`

**Interfaces:**
- Consumes: `buildReport`, `reportFileName` (Task 1), `reportMarkdown` (Task 4); session context `session`, `capRecs`, `captures`, `allVerdicts`, `routineKeys`, `exportOpts`, `setExportOpts`.
- Produces: `export function downloadText(name: string, text: string, type: string): void`; `export function ReportButton({ place }: { place: 'header' | 'overview' })`.

Behaviour:
- Disabled when `captures.size === 0`.
- Click: `buildReport` with `generated: new Date().toISOString()`, then `downloadText` the `.md` (`text/markdown`) and the `.json` (`application/json`, 2-space indent). Status line after: "Downloaded <md name> and <json name>." plus, when captures were left out, "Left out, not loaded: <file names>."
- `place="header"`: the button only, beside Save session in the title row, shown when `c.view !== 'confirmed'`; its `title` attribute summarises what it writes.
- `place="overview"`: in `NothingSelected` after the lead paragraph, the longer label and description line; the "Redact command-line arguments" checkbox bound to `exportOpts.redactArgs`; when unticked, "Command lines can hold secrets such as passwords."; always "Your notes are included as written."; one not-loaded warning line per capture record without a loaded capture.

- [ ] **Step 1: Write the failing tests** in `test/ui.test.tsx`, following the `Save session … downloads` test's pattern (spy on `HTMLAnchorElement.prototype.click`, read blobs from `URL.createObjectURL` calls):
  - `Report for security downloads a Markdown and a JSON report`: after loading `synthetic-lab-2.jsonl` in a session `lab`, clicking **Report for security** downloads names matching `/^lab\.[0-9a-f]{8}\.gameleira-report\.md$/` then `…\.json$/`; the JSON parses with `format === 'gameleira-report'`; the Markdown starts with `# Gameleira report: lab`.
  - `the overview offers the report with the redaction choice`: before a row is picked, **Report flagged processes for security** is shown with the description line; ticking "Redact command-line arguments" there also changes the Save session warning to "Save session redacts command-line arguments.".
  - `the overview warns about a capture that is not loaded`: with an extra `CaptureRec` `gone.jsonl` (as the existing not-loaded test does), the overview shows "gone.jsonl isn't loaded, so its flagged rows can't be included. Re-add it first, or export without it."
  - `header button works when the active capture is not loaded`: same setup, active capture switched to `other-fp`; **Report for security** is enabled and downloads two files.
  - The existing `Save session … downloads` test still passes (it covers the `downloadText` refactor).

- [ ] **Step 2: Run to see them fail.** Run: `npx vitest run test/ui.test.tsx` — Expected: the new tests FAIL.

- [ ] **Step 3: Implement `downloadText`, `ReportButton`, and place it.** `downloadText` is the anchor/Blob/revoke sequence now inline in `useSaveSession`, which then calls it.

- [ ] **Step 4: Run.** Run: `npx vitest run test/ui.test.tsx` — Expected: PASS.

- [ ] **Step 5: Commit** — `git add src/ui test/ui.test.tsx && git commit -m "feat: Report for security, in the session header and on the triage overview"`

---

### Task 6: README, full suite, and the real app

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the README bullet** under "Using it", after **Save session**: what **Report for security** writes (both files, every flagged row reviewed or not, user-marked processes, captures not loaded named, context-only as counts, coverage notes), where the button is, that redaction is shared with Save session and is field-level (paths and names stay; notes are not redacted), and that environment variables are never included.

- [ ] **Step 2: Run the whole suite and the build.** Run: `npm test` — Expected: all tests pass (real-capture suites may skip with their usual note); `dist/index.html` builds.

- [ ] **Step 3: Check it in the browser.** Serve the build, load `test/fixtures/synthetic-lab.jsonl` into a session, click **Report for security**, and confirm both files actually arrive (Chromium can drop a second download started in the same tick; if it does, start the JSON one after a short `setTimeout` and re-check). Confirm the overview shows the button, the checkbox and the notes line. Screenshot the overview.

- [ ] **Step 4: Commit** — `git commit -am "docs: Report for security in the README"`
