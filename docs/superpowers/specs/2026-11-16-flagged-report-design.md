# Flagged-process report: Markdown and JSON for secops

## Intent

Gameleira is becoming a self-service tool. Ordinary users (not the senior staff the capture cleaner is for; they get a different process) run a capture on their own Mac, drop it into Gameleira, and see processes the rules flagged. Most of them are not security people: some will triage, many will not, and the verdicts they set are guesses.

When a user sees flags, they need a way to hand the whole picture to secops and security researchers, who decide whether a deeper investigation is needed. Those readers probably do not have the capture, cannot easily ask the user follow-up questions, and want to feed the result into their own tooling.

So: one button that writes a report of **every flagged row**, triaged or not, as two files: Markdown for a person to read (pasted into a ticket or Slack) and JSON for a secops tool to ingest. Both come from the same data, so what a person reads and what a tool ingests always agree.

## Goals

- One click on the Triage overview downloads `<session>.<hash>.gameleira-report.md` and `<session>.<hash>.gameleira-report.json` (same `slug` and `idHash` as Save session).
- The report covers every row of the triage queue in every loaded capture of the session: process rows and launch items with no process, whatever their verdict, including rows a routine mark hides.
- Each row stands on its own for a reader without the capture: what was flagged and why, the evidence, the program and its signature, its command line, where it came from, and what the user said about it.
- The report says what the capture could not see (the coverage notes), so a missing event type is never read as "nothing happened".
- The JSON has a stable, versioned shape (`format: "gameleira-report"`, `version: 1`) a tool can rely on.
- Nothing is dropped silently: captures that are not loaded, rows hidden as routine, context-only findings and redaction are all stated in the report.

## Non-goals

- Sending the report anywhere. The page keeps `connect-src 'none'`; the user attaches or pastes the files themselves.
- A free-text "what happened" field for the user. (Possible later; the per-row notes already exist.)
- Importing a report back into Gameleira. The session export (`gameleira-session`) stays the format for that and is unchanged.
- HTML or PDF output.
- Including environment variables. They are noise for this reader and a common place for secrets; the report never has them.
- Reloading captures to complete a report. The report covers the captures loaded now; a session whose captures exceed the in-memory limit (300 MB, least recently used dropped) cannot get a complete report, and the report's header names every capture it leaves out (decided by the requester: self-service users will usually have one capture).
- Full per-process timelines. The report carries a bounded summary of what each process did; the capture itself is the source for more.

## Anti-goals (a failure even if it works)

- The Markdown and the JSON disagreeing about anything.
- A flagged row missing from the report because the user marked it benign, marked its program routine, or never looked at it.
- A redacted report that still contains an argument after argv[0] anywhere: in a command line, in a finding's evidence, in ancestry, in a launch item's fields, in a file path that came from an argument.
- A non-expert user believing the report is complete when a capture was not loaded and its rows are missing.
- Changing what Save session / the session export writes or reads.

## Approaches considered

1. **One report model, two renderings** (picked). A pure module builds a `gameleira-report` v1 object from the loaded captures, their analyses and the session's verdicts; the JSON file is that object serialized, the Markdown is rendered from it. The two cannot disagree, and the module is testable without the UI. Cost: a second JSON format beside the session export.
2. **Extend the session export** with queue rows and render Markdown from it. One format, but that file exists for backup and re-import (validated on import, carries routine marks and store records); secops would ingest a file shaped for something else, and every report change would risk breaking re-import.
3. **Markdown with the JSON embedded** in a fenced block. One attachment, but ingestion has to dig JSON out of prose, and the paste into Slack doubles in size.

## Design

### Module

`src/report/report.ts` (pure, no DOM, no store access):

- `buildReport(input, opts): Report`, where `input` holds the session (`id`, `name`), the capture records (`CaptureRec[]`), the loaded captures (`Map<fingerprint, LoadedCapture>`), all of the session's verdicts and its routine program keys; `opts` is `{ redactArgs: boolean; generated: string }` (`generated` is an ISO time passed in, so output is deterministic in tests).
- `reportMarkdown(report: Report): string`.
- `reportFileName(session, ext)`.

`src/ui/` gains the button and the download; it gathers the input from the session context and calls the module.

### What the report holds (the JSON shape)

```
{
  format: "gameleira-report", version: 1,
  generated: ISO time,
  session: { id, name },
  redacted: boolean,                     // command-line arguments after argv[0] replaced with "[redacted]"
  summary: {
    rows: n,                             // queue rows of loaded captures
    bySeverity: { high, med, low },      // rows
    byVerdict: { unreviewed, confirmed, benign },
    hiddenAsRoutine: n,
    userMarked: n,
    capturesNotLoaded: n
  },
  captures: [ {
    fingerprint, fileName, size, events, processes,
    firstTime, lastTime, schemaVersions: number[],
    loaded: boolean,
    coverage: [ { id, level, title, detail, checks: [ruleId] } ],   // loaded only; from coverage()
    contextOnly: { [ruleId]: count },                               // loaded only; findings kept out of the queue
    rows: [Row],                                                    // loaded only; queue order (severity, then time)
    userMarked: [Row],                                              // loaded only; see below
    notLoaded?: [ { procKey, status, note, snapshot } ]             // not loaded: the verdicts stored for it, from their snapshots
  } ]
}
```

A `Row`:

```
{
  n,                                     // row number across the report, as the Markdown prints it
  key,                                   // queue key: p:<procId> or i:<itemId>; the procKey for a user-marked row
  kind: "process" | "persistence" | "user-marked",
  name,                                  // as the queue shows it; from the verdict snapshot when the process is gone
  severity: "high" | "med" | "low" | null,   // null only for user-marked
  verdict: { status, note, updated } | null,   // the user's view; null when never touched
  inFlaggedChain, reconBurst,
  hiddenAsRoutine: boolean, keptReason: string | null,   // routine-marked program; why a routine row stays visible
  findings: [ { ruleId, severity, title, explanation, mitre: [], evidence, trait } ],
  process?: {                            // process rows
    pid, procId,
    startTime, exitTime,
    images: [ { path, args, cwd, signingId, teamId, isPlatform, signature, script, stdinIsPipe, time, inherited } ],
    ancestry: [ { name, pid } ],         // original-parent chain, nearest first, launchd last
    responsible: { name, pid } | null,
    children: n,                          // processes it started (original parent)
    fileOps: { total: n, shown: [FileOp] }   // capped, see below
  },
  launchItems: {                         // persistence rows, and launch items attached to a process row ([] otherwise)
    id, type, typeName, plistPath, executablePath, appPath, time, registeredBy: { name, pid, via } | null
  }[]
}
```

`signature` is one of `"apple-platform" | "team-signed" | "signed-no-team" | "adhoc" | "unsigned" | "unknown"` (`unknown` when the image's path is null), so the reader does not have to decode `csFlags`. Checked in that order: platform first, then unsigned and ad-hoc using the rules' own `isUnsigned` / `isAdhoc` (exported from `src/rules/rules.ts` if needed, not reimplemented), then team ID present or not. The Markdown spells it out ("Apple platform binary", "signed by team ABCDE12345", "signed, no team ID", "ad-hoc signed", "unsigned"). The detail pane is not changed.

### Markdown layout

```
# Gameleira report: <session name>

Generated <time>. <n> flagged rows in <k> captures: <h> high, <m> medium, <l> low.
User's verdicts: <s> suspicious, <b> benign, <u> not reviewed. (Verdicts were set by the person who ran
the capture, not by security staff.)
Command-line arguments are redacted. | Command lines are complete and may contain secrets.
<warning block if any capture is not loaded>

## Captures
<per capture: file, size, time span, schema, coverage notes (warn level first), context-only counts>

## High
### 1. <name> (pid <pid>): <first finding title>
- User's verdict: Suspicious, "<note>"  |  Not reviewed
- Capture: <file>  ·  in a flagged chain  ·  recon burst  ·  marked routine (kept: <reason>)
- Command line: `...`
- Program: <path>, <signature>
- Started by: launchd → Terminal (pid 400) → bash (pid 812) → this
- Responsible: Terminal (pid 400)
**Findings**
- <title> [high] T1056.002: <explanation> Evidence: `...`
**What it did**: <children> processes started; <total> file events, first <shown>: ...

## Medium
## Low

## Captures not loaded
<verdict snapshots only>
```

Rows are numbered across the report so a reader can say "row 7". Severity sections with no rows are omitted. Every value from the capture that goes into Markdown (names, paths, args, notes) is escaped or put in code spans, so a hostile file name cannot break the layout or inject links.

### Processes the user marked that the rules did not flag

A user can give a verdict to a process that is not in the queue (from the tree, or the detail pane's "Not in the queue"); it is stored with `severity: null` and no rule IDs. Every such verdict that is not `unreviewed`-with-no-note appears in its loaded capture's report under `userMarked: [Row]`, with `severity: null` and `findings: []` (context-only findings of that process, if any, are listed). In Markdown it is a section **Marked by the user, not flagged by the rules**, after Low. Its rows are not counted in `summary.bySeverity`; `summary.userMarked` counts them.

### The button

The button sits in the session header beside Save session, visible on Triage and Tree whatever is selected: **Report for security**. A user who has opened a row (and so has triaged something, which is the point of the report) can still reach it; the overview has no way back once a row is picked.

The Triage overview (the right pane before a row is picked) also carries it prominently, under the counts, as **Report flagged processes for security**, with one line beneath it: "Writes a Markdown file to read and a JSON file for security tools, with every flagged row, reviewed or not." Both buttons do the same thing. It is enabled when at least one capture is loaded; it reports all loaded captures of the session, not only the active one.

Beside the button, the same redaction state Save session uses (`exportOpts.redactArgs`, shared): a checkbox "Redact command-line arguments" and, when unticked, the warning that command lines can hold passwords. Default stays unticked: secops needs the command lines, and this report goes to the user's own security team.

If a capture of the session is not loaded, the button area says so before export: "<file> isn't loaded, so its flagged rows can't be included. Re-add it first, or export without it." Export still works.

Both files are downloaded in one click (Chrome may ask once to allow multiple downloads). Folder saving is not used: a self-service user will not have picked a save folder.

### Redaction

Redaction exists to keep secrets typed into command lines (a password passed to `dscl -authonly`, `openssl -pass pass:…`) out of the files. It is **field-level**: when `redactArgs` is set, every field built from a command line is redacted, and data the capture recorded on its own stays.

- Redacted: `images[].args` (every element after argv[0] becomes `[redacted]`), every finding's `evidence` (many rules build it from the command line), and the not-loaded verdict snapshots' `args`.
- Kept: program paths, process names, ancestry, `cwd`, script paths, file-event paths, launch item paths. They come from their own fields of the capture, and they are the evidence secops needs most (the dropped app's path, the plist that was written). The same text may also be an argument somewhere (`xattr -cr /Users/alice/Downloads/Installer.app`); that is not a leak of a secret.
- The user's notes are not redacted (Save session does not redact them either); the export area says so next to the checkbox.

Test: build a report of the synthetic lab capture with redaction on, collect every argument after argv[0] of every image (length 3 or more, to skip `-c`-style flags), drop those that also occur in any kept field of the capture (a program path, a process name, a file-event path, a launch item path, a cwd or script), and assert none of the rest occurs in either serialized file. Also assert at least one argument is checked, so the test cannot pass empty.

## Calls made by Claude (correct any)

- Benign and routine-hidden rows are included in full, marked, not left out or shortened: the user's verdict is a guess secops may overrule.
- Context-only findings appear as counts per rule per capture, not as rows.
- Environment variables are never included.
- File events per process are capped at 20 shown, with the total.
- Rows of the not-loaded captures come only from stored verdicts (what the user touched); their untouched rows cannot be known and the report says so.
- Redaction default is off, shared with Save session's option.
- Redaction is field-level (command lines and evidence), not a scrub of every occurrence of an argument's text; notes are not redacted.
- Verdicts on processes the rules did not flag are included, in their own section.
- `signature` values are the six listed above, from the rules' own checks; the detail pane is not changed.
- The button is in the session header (always reachable) and on the Triage overview.

## Left to the builder

- How redaction is applied to evidence strings (re-deriving evidence from redacted images, or replacing argument text), as long as the redaction test holds.
- Markdown escaping details.
- Where the button's component lives, and whether the download helper is shared with Save session's.

## Testing

- `buildReport` on `test/fixtures/synthetic-lab.jsonl`: every queue row present, in queue order; verdicts and notes carried; a benign row and a routine-hidden row present and marked; context-only counts match `analysis.contextOnly`; coverage notes match `coverage()`.
- A not-loaded capture: listed with `loaded: false`, its stored verdicts under `notLoaded`, warning present in Markdown.
- Markdown snapshot of the synthetic lab report (generated time fixed).
- The Markdown agrees with the JSON: every row key's number, name and severity in the JSON appears in the Markdown section for that severity.
- Redaction test as above.
- Escaping: a process whose path holds backticks, `|`, `[x](y)` and newlines renders inside code and does not add Markdown structure.
- UI: the button on the overview triggers two downloads with the right names; the not-loaded warning shows.
- README: a section under "Using it"; `test/readme.test.ts` will need whatever it checks.
