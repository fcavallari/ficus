# uid/gid Mismatch Rule and Nearby Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flag processes running with euid≠ruid or egid≠rgid (with an Apple allow list), and add a "What happened nearby" panel that lists other processes' events close in time to a chosen timeline event.

**Architecture:** The parser reads the four ids from every `audit_token`; the builder records each process's first mismatch; a new process-scope rule turns it into a finding whose severity depends on the image running at that moment. A new `src/ui/nearby.ts` builds a capture-wide, time-sorted event index from the existing timeline construction, and `DetailPane` renders a panel anchored on one Timeline row.

**Tech Stack:** TypeScript, React 19, Vitest (+ jsdom, Testing Library).

**Spec:** `docs/superpowers/specs/2026-11-16-uid-mismatch-and-nearby-design.md`

## Global Constraints

- No new dependency; no IndexedDB, session export or verdict schema change.
- Rule id `uid-mismatch`, MITRE `T1548.001`, scope `process`, `gated: 'when-low'`; default severity `high`.
- Severities: allow-listed (platform **and** signing ID listed) → `low`; other platform → `med`; non-platform → `high`.
- The Timeline stays recorded-only; the nearby panel carries the line "Inferred from timing: these events are close in time, not recorded as related."
- Nearby windows ±1 s / ±5 s / ±30 s, default ±5 s; first 200 events shown, then "show more" in steps.
- Every rule must be in the README rules table, in exactly one Guide stage, and every MITRE ID in `MITRE_NAMES` (existing tests enforce all three).

## Review Focus

- **Capture without uid fields** (older schema, trimmed tokens): no finding, no crash. → Task 1 test `ids are null when audit_token lacks them`.
- **Lookalike binary** (`/tmp/sudo` unsigned, or `com.apple.sudo` not platform): must be `high`, never allow-listed. → Task 2 test `lookalike sudo is high`.
- **setuid() without exec** (fork-only process whose later event shows euid 0): flagged. → Task 1 test `mismatch seen on a later non-exec event is recorded`.
- **Events with no or unparseable time**: left out of the nearby index and counted, never placed at epoch 0. → Task 3 test `events without a time are left out and counted`.
- **Busy capture** (thousands of events in the window): panel mounts at most 200 rows. → Task 4 test `nearby shows at most 200 events, then more on request`.

---

### Task 1: Parse uids and record the first mismatch

**Files:**
- Modify: `src/model/types.ts` (ProcInfo, Process)
- Modify: `src/model/parse.ts:19-36` (`procInfo`)
- Modify: `src/model/builder.ts` (`ensure`, `apply` for exec target / fork child)
- Test: `test/builder.test.ts`

**Interfaces:**
- Produces: `export interface Ids { ruid: number; euid: number; rgid: number; egid: number }` in `types.ts`; `ProcInfo.ids: Ids | null`; `Process.credMismatch?: Ids & { seq: number; time: string }`.

- [ ] **Step 1: Write the failing tests** in `test/builder.test.ts`, with a local helper `line(o)` that builds one eslogger JSON line (fields: `process` with `audit_token {pid, pidversion, ruid, euid, rgid, egid}`, `executable.path`, `signing_id`, `is_platform_binary`, `start_time`; `event`; `global_seq_num`; `time`).
  - `exec into a setuid binary records the mismatch`: zsh (501/501, 20/20) execs target `/bin/ps` with euid 0 → `credMismatch` equals `{ ruid: 501, euid: 0, rgid: 20, egid: 20, seq: <exec seq>, time: <exec time> }`.
  - `mismatch seen on a later non-exec event is recorded`: forked child, then a `write` event whose `process.audit_token.euid` is 0 → `credMismatch.seq` is the write's seq.
  - `only the first mismatch is kept`: two mismatching events → seq of the first.
  - `ids are null when audit_token lacks them`: token with only pid/pidversion → `parseLine(...).proc.ids` is `null` and no `credMismatch`.
  - `matching ids record nothing`.
- [ ] **Step 2: Run** `npx vitest run test/builder.test.ts` — expect the new tests to FAIL.
- [ ] **Step 3: Implement.** `procInfo` sets `ids` when all four are numbers, else `null`. Builder: a private `noteIds(p: Process, info: ProcInfo, seq: number, time: string)` that sets `credMismatch` once when `ids.euid !== ids.ruid || ids.egid !== ids.rgid`; call it for `ev.proc` (after `ensure`), the exec `target` (on `p`), the fork `child` (on the child process) and btm instigator/app (on the process `ensure` returns).
- [ ] **Step 4: Run** `npx vitest run test/builder.test.ts test/parse.test.ts` — PASS.
- [ ] **Step 5: Commit** `feat: record uid/gid mismatches from audit tokens`.

### Task 2: `uid-mismatch` rule with Apple allow list

**Files:**
- Modify: `src/rules/rules.ts` (new rule after `orphaned`; exported `SETUID_ALLOW`)
- Modify: `src/rules/mitre.ts` (`T1548.001`: "Abuse Elevation Control Mechanism: Setuid and Setgid")
- Modify: `README.md` rules table (row `uid-mismatch` | high | …T1548.001…)
- Modify: `src/ui/GuideScreen.tsx` `STAGES` — add `uid-mismatch` to "Getting past the defences" and add "or running with someone else's privileges (a setuid binary)" to its text
- Test: `test/rule-cases.test.ts`

**Interfaces:**
- Consumes: `Process.credMismatch` (Task 1), `imageAt(p, seq)` from `src/model/util.ts`.
- Produces: `export const SETUID_ALLOW: Set<string>`.

`SETUID_ALLOW` (verified on macOS with `find -perm -4000/-2000` + `codesign -dv`, plus two seen in real captures; `sudo` and `security_authtrampoline` refuse `codesign` without root, so their IDs are Apple's documented ones):
`com.apple.ps, com.apple.top, com.apple.write, com.apple.atrm, com.apple.batch, com.apple.crontab, com.apple.newgrp, com.apple.su, com.apple.sudo, com.apple.quota, com.apple.login, com.apple.traceroute, com.apple.traceroute6, com.apple.postqueue, com.apple.postdrop, com.apple.authopen, com.apple.security_authtrampoline, com.apple.RemoteDesktopAgent, com.apple.loginwindow`.

- [ ] **Step 1: Write the failing tests** (`describe('uid-mismatch')`, using `proc`/`img`/`apple`/`capture` from `test/synth.ts` and `analyze`):
  - `allow-listed ps is low and context-only`: `apple('/bin/ps', ['ps'])` with `credMismatch {501,0,20,20}` → finding severity `low`, process not in `queue`, present in `contextOnly`.
  - `unlisted platform binary is med`: `apple('/usr/bin/foo', …)` → `med`, queued.
  - `lookalike sudo is high`: `img({ path: '/tmp/sudo', signingId: 'com.apple.sudo', isPlatform: false })` → `high`.
  - `evidence names the differing pair`: euid differs → evidence contains `euid 0 ≠ ruid 501`; egid only → `egid 80 ≠ rgid 20`; both → both.
  - `uses the image running at the mismatch`: process with images zsh(seq 1) then `/tmp/x`(seq 5), mismatch seq 5 → `high`.
  - `no credMismatch, no finding`.
- [ ] **Step 2: Run** `npx vitest run test/rule-cases.test.ts` — FAIL.
- [ ] **Step 3: Implement** the rule (`title: 'Running with borrowed privileges'`, explanation: effective and real user/group ids differ, so the process holds privileges of another account; a setuid/setgid binary or a `setuid()` call; Apple's own setuid tools are expected). Evidence: `euid X ≠ ruid Y` and/or `egid X ≠ rgid Y`, then ` (basename)`. Add MITRE name, README row, Guide stage entry.
- [ ] **Step 4: Run** `npm test` — all PASS (includes README, Guide stage, MITRE-name checks, and the real-capture tests if present: `es-lab` must not queue `ps` or `loginwindow`).
- [ ] **Step 5: Commit** `feat: flag processes running with a different effective uid or gid`.

### Task 3: Capture-wide nearby index

**Files:**
- Modify: `src/ui/timeline.ts` — export `allTimelineEvents(cap: LoadedCapture): TimelineEvent[]` (every non-ghost process via `eventsOf`, `fork` entries whose `other` is a captured process dropped, as the subtree dedupe does)
- Create: `src/ui/nearby.ts`
- Test: `test/nearby.test.ts`

**Interfaces:**
- Produces:
  ```ts
  export const NEARBY_WINDOWS = [1_000, 5_000, 30_000] as const;   // ms, default index 1
  export interface NearbyEvent { e: TimelineEvent; offsetMs: number; samePath: boolean }
  export interface NearbyGroup { proc: ProcId; linked: boolean; events: NearbyEvent[] }
  export interface NearbyResult { groups: NearbyGroup[]; total: number; untimed: number }
  export function nearby(cap: LoadedCapture, anchor: TimelineEvent, windowMs: number): NearbyResult;
  export function defaultAnchor(events: TimelineEvent[]): TimelineEvent | null;
  ```
- `linked`: the event's process is in the anchor process's ancestry or the anchor process is in its ancestry, under any of `'original' | 'current' | 'responsible'`.
- `samePath`: any of the event's `path`/`toPath` equals any of the anchor's `path`/`toPath`.
- Groups ordered by their first event's time; events within a group by time. `total` counts all events in the window (excluding the anchor's own process). `untimed` counts index events without a parseable time.
- Index cached per capture in a `WeakMap`; time parse reuses the engine's nanosecond-tolerant approach (move `timeMs` from `engine.ts` to `src/model/util.ts` and export it). Window lookup by binary search on the sorted ms array.

- [ ] **Step 1: Write the failing tests** on a synthetic capture (`capture`/`proc`/`op` from `test/synth.ts`, wrapped as a `LoadedCapture` with `analyze`, as `test/ui.test.tsx` does):
  - `lists other processes' events inside the window, with offsets`: anchor at t=10 s; events at 7, 12, 20 s → ±5 s returns 7 s (−3000) and 12 s (+2000) only.
  - `leaves out the anchor's own process`.
  - `marks an unrelated process unlinked and a parent linked`.
  - `marks same-path events`: anchor `write /tmp/a`; other process `exec /tmp/a` → `samePath: true`.
  - `events without a time are left out and counted`.
  - `defaultAnchor prefers the first flagged event, then the first exec, then the first event`.
- [ ] **Step 2: Run** `npx vitest run test/nearby.test.ts` — FAIL.
- [ ] **Step 3: Implement** `allTimelineEvents`, `timeMs` move, and `nearby.ts`.
- [ ] **Step 4: Run** `npx vitest run test/nearby.test.ts test/rules.test.ts` — PASS.
- [ ] **Step 5: Commit** `feat: index capture events by time for nearby lookups`.

### Task 4: "What happened nearby" panel

**Files:**
- Modify: `src/ui/DetailPane.tsx` (`Timeline`, `TimelineRow`, new `Nearby` component rendered after `<Timeline>` in `DidWhat`; anchor state lifted into `DidWhat`)
- Modify: `src/ui/styles.css` (anchor-row mark, same-path highlight, group headings; reuse existing tokens)
- Test: `test/ui.test.tsx`

**Interfaces:**
- Consumes: `nearby`, `defaultAnchor`, `NEARBY_WINDOWS` (Task 3); `TimelineRow` gains `onAnchor(e: TimelineEvent): void` and `anchored: boolean`.

UI decisions: each Timeline row gets a small button labelled "nearby" (`aria-label="Show what happened near this event"`, `aria-pressed` when it is the anchor). The panel is an `<h4>What happened nearby</h4>`, the inferred-from-timing line, an anchor summary (time, kind, path), a radio group "±1 s / ±5 s / ±30 s", then one block per group: process link, `Sev` badge if queued, and "no recorded link" (muted-warn) or "linked by parent chain" (muted); rows reuse `TimelineRow` styling with an offset column (`+2.000 s`, `−0.420 s`) instead of the clock; same-path rows get class `same-path` and the text "same path". Summary line: "N events in other processes within ±5 s" plus "M events have no time" when `untimed > 0`. Empty: "Nothing else recorded within ±5 s."

- [ ] **Step 1: Write the failing tests:**
  - `the nearby panel lists another process's event, unlinked, and labels it inferred`: render a capture with two unrelated processes 2 s apart, select one → panel shows the other's event, "no recorded link", and the inferred line.
  - `clicking nearby on a timeline row re-anchors the panel` (aria-pressed moves; contents change).
  - `the window choice changes what is listed` (±1 s hides the 2 s event).
  - `nearby shows at most 200 events, then more on request` (250 events in window → 200 rows + "Show 50 more").
- [ ] **Step 2: Run** `npx vitest run test/ui.test.tsx -t nearby` — FAIL.
- [ ] **Step 3: Implement** the component and CSS.
- [ ] **Step 4: Run** `npm test` and `npm run build` — PASS, no type errors.
- [ ] **Step 5: Verify in the app**: start the dev server, load `test/fixtures/synthetic-lab.jsonl`, open a flagged process, check the panel, re-anchoring, windows, and dark/light; screenshot.
- [ ] **Step 6: Commit** `feat: show what happened nearby in time, labelled as inferred`.
