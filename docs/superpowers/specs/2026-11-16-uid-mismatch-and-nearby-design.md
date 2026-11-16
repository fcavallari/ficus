# uid/gid mismatch rule and "What happened nearby" panel

## Intent

eslogger records less than an investigation needs. Links broken by launchd or XPC, and events that the capture never ties together, can only be found by matching timestamps. Researchers do this by hand today. Separately, a process whose effective uid/gid differs from its real uid/gid is running with someone else's privileges (setuid binary, or a `setuid()` call after exploitation) and deserves attention, except for the usual Apple setuid tools.

## Goals

- Flag processes seen with `euid != ruid` or `egid != rgid`, with a built-in allow list for routine Apple setuid/setgid tools.
- In the process detail, show what other processes did close in time to a chosen event, clearly labelled as inferred from timing.

## Non-goals and anti-goals

- No user-editable allow list (the existing "Treat as routine" covers per-program noise). No storage or export schema change.
- No automatic correlation findings in the queue (possible later, once the panel shows which patterns recur).
- Never present a timing correlation as a recorded link: the Timeline stays "nothing inferred"; the new panel is separate and says it is inferred.
- The panel must not stall the pane on busy captures.

## Approaches considered

Allow list: (1) built-in list keyed by Apple signing ID + platform binary, allow-listed hits shown as context only; (2) built-in plus a per-session editable list in IndexedDB; (3) reuse "Treat as routine" only. **Picked 1**: no storage change, a copied or lookalike binary is not trusted, and (3) would hide every finding of the program, not just this one.

Nearby: (1) anchored to one event, cross-process, chosen window; (2) the whole process lifetime; (3) automatic correlation rules. **Picked 1**: (2) is too noisy for long-running processes; (3) is a larger change that the panel should inform first.

## Design

### uid/gid mismatch

- **Parse**: `ProcInfo` gains `ids: { ruid, euid, rgid, egid } | null` from `audit_token` (null when any of the four is missing, e.g. older or trimmed captures).
- **Model**: `Process` gains `credMismatches?: { ruid, euid, rgid, egid, seq, time, imgIndex }[]`, the first mismatch per image: for each image the process ran, the first event at which its own audit token (as emitter, exec target, fork child or btm instigator/app) showed a mismatch. `imgIndex` is the image the process was running when that token was observed: for the emitter of an exec, the image before the exec target is pushed; for the exec target, the new image; for a fork child, its image 0; for btm instigator/app and other events, the process's current last image. Recording it per event rather than per exec also catches a `setuid()` call with no exec; keeping one per image means an allow-listed setuid tool that execs a shell still at euid 0 does not hide the shell.
- **Rule** `uid-mismatch`, scope `process`, MITRE T1548.001, `gated: 'when-low'`. Each entry is graded against its own image (`p.images[imgIndex]`) and the finding takes the worst severity; the evidence lists each distinct pair and basename, joined by "; ":
  - allow-listed (platform binary **and** signing ID in the list): **low**, so context-only unless in a flagged chain;
  - other platform binary: **med**;
  - non-platform binary: **high**.
  - **Drop rule**: an entry is a privilege *drop*, not an escalation, when `ruid === 0 && euid !== 0` (and, when only the gid pair differs, `rgid === 0 && egid !== 0`): a root process running with a user's effective id (loginwindow, a vendor daemon acting for the console user). A drop is always **low** (context-only through the when-low gate). When every entry is a drop the finding's explanation is overridden with: "Running as root with a user's effective id: it dropped its privileges and can take them back. Common for system and vendor daemons acting for the logged-in user; context, not escalation." Escalations keep the tiers above and the rule's own explanation.
  Evidence, e.g. `euid 0 ≠ ruid 501 (sudo)`, or the gid pair, or both.
- **Allow list** (builder's call): the Apple setuid/setgid binaries on a current macOS, found with `find / -xdev -perm -4000 -o -perm -2000` and their signing IDs read with `codesign -dv`, so the list holds real IDs, not guesses (expected: sudo, su, login, passwd, chpass, crontab, at/atq/atrm/batch, newgrp, quota, ps, top, traceroute/traceroute6, security_authtrampoline, authopen).
- The Guide's rule list gains the rule; the README rule list too if it enumerates rules (a test checks this).

### "What happened nearby" panel

- **Index**: a capture-wide list of every timeline event (same construction as `processTimeline`, spawn kept and duplicate fork entries dropped), with time parsed to ms, sorted by time; built lazily once per capture (WeakMap cache). Events without a parseable time are left out and counted.
- **Anchor**: a "nearby" button on each Timeline row sets the anchor; default anchor is the first event with a finding, else the first exec, else the first event.
- **Window**: ±1 s / ±5 s / ±30 s chips, default ±5 s.
- **Contents**: events of other processes inside the window, grouped by process (process link, severity badge if queued), in time order with the offset from the anchor (`+0.42 s`). Each group carries `link: { kind: 'chain' } | { kind: 'shared'; via: ProcId } | null`: `chain` when one process is the other's ancestor in any mode (original/current/responsible), shown as "linked by parent chain"; `shared` when both descend from the same recorded process, the nearest common ancestor under any mode (modes tried in that order) that is not pid 0/1 (kernel/launchd) and not a ghost, shown as "shares <name> pid N" with a link to it; null otherwise, shown as **no recorded link** in the warning colour, the interesting case. Events touching the same path as the anchor are highlighted: only a file op's path/toPath, an exec or image path, and a launch item's path count, not the inherited program path a fork, spawn or exit entry carries.
- **Labelling**: heading "What happened nearby", with the line "Inferred from timing: these events are close in time, not recorded as related."
- **Limits**: the panel shows the 200 events nearest the anchor across all processes, never the first groups in full: same-path events first, then by |offset|. "Show more" adds the next 200 nearest. The shown events stay grouped, with groups ordered same-path first, then by their nearest event (ties: earlier first event, then process id), and events in time order within a group; a group with hidden events says "+K more in this process". The summary gives the total count in the window. `nearby()` still returns every event; the selection is a pure helper (`pickShown`), so one busy process cannot crowd out the rest.
- Placed in the "What it did" section, below the Timeline.

## Constraints

Use existing model and timeline data; no new dependency; no IndexedDB or export change. Keep the existing visual language (see the Gameleira visual direction). Tests: parser fields, rule severities incl. allow list and lookalike binary, fork-only `setuid()` case, nearby index windowing and grouping, UI smoke test.

## Left to the builder

Exact allow-list entries after verification, CSS details, the exact offset formatting, and whether the anchor row gets a visual mark in the Timeline.
