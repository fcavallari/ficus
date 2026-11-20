# Grouped queue rows and a mass-encryption rule: design

Two changes that come from the lab's pilot runs (`lab/reports/`). They ship as two pull requests, the grouping first.

## 1. Group repeated findings in the queue

### Why

KoiStealer looped 528 times; each pass started a new helper process and a new `dscl . authonly admin` process. The queue has one row per process, so one program produced 1,056 rows, and the real findings sat behind them. A learner should see one row that says "this happened 527 times".

### Goals
- A run of identical processes is one queue row, with a count.
- Nothing is lost: every member process is still in the tree, the timeline and the detail pane, with its own findings.
- A verdict on the row applies to every member.

### Non-goals
- Grouping different programs, or processes whose findings differ.
- Grouping persistence-only items (they have no process).
- A user control to ungroup. If the rule is too loose we tighten it, not add a switch.

### Anti-goals
- Hiding a differing process inside a group. Two processes group only when everything a learner would judge is the same.

### Design

**Which processes group.** Two queued process items are the same group when all of these match: the latest exec'd image's path, its signing id and team id, its arguments, the parent's program (path of the parent's latest image, or none), the set of `(ruleId, severity, title)` of the findings, `inFlaggedChain`, and `reconBurst`. Pids, times and evidence text that contains a pid or time do not count. A group needs 2 or more members.

**Model.** `QueueItem` gains `members: ProcId[]` (every member, in sequence order; the first is the representative and is the one `procId` names). A row that is alone has `members: [procId]`. `Analysis.findings` and `contextOnly` stay per process, so the tree and timeline are unchanged. `sortSeq` is the first member's. The queue key stays `p:<representative id>`.

**Verdicts.** Stored per process, as now. Setting a verdict on a group row writes it for every member; the row's status is the representative's. Undo restores every member. Notes stay on the representative only.

**Everything that maps a process to its queue row** (tree flags, timeline flags, detail pane "in the queue" chip, report, routine marks) goes through one helper, `queueItemFor(analysis, procId)`, which finds the row by any member. A member shows as flagged like the representative.

**Display.** The row shows `×527` after the name. The detail pane for a group lists the members (time, pid) and lets you select one. The overview counts rows, as before, so "1,056 flagged" becomes "2 flagged". The report prints one row per group with the count.

**Routine marks.** Apply to the group as a whole (the program is the same for every member).

### Approaches considered
- **A. Group in the analysis** (chosen): one queue row per group, members kept on it. The report and MCP see the small queue.
- B. Group only in the Triage list: safer, but the report and MCP still list every process.
- C. A "hide repeats" toggle: the default view stays flooded.

### Left to the builder
Where the member list sits in the detail pane; the exact wording of the count; how the MCP workspace reports members (at least the count).

## 2. A mass-encryption rule

### Why
HeartBreaker truncated, rewrote and renamed 15 files to `<name>.heartbreaker` in 1.3 seconds and Ficus raised nothing.

### Design
A process-scoped rule, `mass-rename`. It fires for one process that renames 10 or more files to the same new extension within 10 seconds (the file operations the process already records: `rename` with `path` and `toPath`). The extension must be new (the source name does not already end in it) and not one of the usual temporary ones (`tmp`, `part`, `download`, `crdownload`, `swp`, `bak`, `partial`). Severity high; MITRE T1486 (Data Encrypted for Impact). The evidence names the extension, the count, the span and three example files.

### Checks
The lab's HeartBreaker capture must raise it. The idle and benign baselines must not. A synthetic capture covers the edges: 9 renames (no), 10 over a longer span (no), temporary extensions (no), mixed extensions (no).

### Left to the builder
The thresholds are a first guess from one sample; keep them as named constants.
