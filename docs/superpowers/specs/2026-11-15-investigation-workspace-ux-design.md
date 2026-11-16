# Investigation Workspace UX Refinement

## Intent

Help researchers move from a flagged process to its available evidence with less searching, while preserving Gameleira's compact dark botanical workspace. The implementation will surface evidence already parsed by the app and clarify what queue badges mean.

## Goals

- Make key identity and activity evidence visible near the selected process heading.
- Make severity and verdict understandable at a glance in the compact queue, including without hover.
- Strengthen selected-row and keyboard-navigation feedback without changing shortcuts.
- Preserve capture parsing, verdict storage, import/export formats, and existing detection behavior.

## Non-goals and anti-goals

- No workspace redesign, new dependency, or data-model/schema change.
- No new inference, event reconstruction, or compatibility claim.
- No changes to verdict semantics, detection severities, keyboard bindings, or timeline ordering.
- Avoid duplicating large evidence blocks or making the queue too wide to scan.

## Approaches considered

1. Keep the current implementation. Most requested features already exist, but key evidence and queue label meanings are not immediately visible.
2. Add a compact process evidence summary to the existing detail header and use explicit compact queue labels and focus states. This preserves the layout and reuses existing model values; selected.
3. Reorganize the detail pane and queue into a new information architecture. This adds risk and scope without addressing a missing capability.

## Design

- In the selected-process header, show available command-line arguments and a compact observed-activity summary (first and last recorded timestamps and the count of associated events). Omit values that are unavailable; keep full details and timeline in their current sections. Continue showing the existing name, PID, parent PID, executable path, signing ID, severity, and verdict.
- In queue rows, show severity as its full label (High, Medium, Low) and expose the verdict label (Unreviewed, Suspicious, Benign) as readable text alongside its existing status treatment. Keep rows single-line and compact; adjust flex sizing and truncation as needed. Preserve accessible listbox semantics.
- Make keyboard focus and the selected row easy to distinguish through the existing accent treatment and visible focus outline, including forced-colors mode. Preserve the existing `j`/`k`, arrow, verdict, undo, note, search, and tree shortcuts.
- Leave the no-selection overview, capture compatibility panel, Triage-to-Tree handoff, return context, and evidence timeline behavior intact; they already meet the requested functional scope.

## Constraints and data handling

Use existing `Process`, `Image`, and timeline data. Do not add fields to session exports or change stored `confirmed` verdict values. Display missing values as absent, following current UI conventions. For observed timestamps, use the event order and helpers already used by the timeline rather than assuming missing event times.

## Acceptance

The refinement is successful when the selected process's available command line and observed activity summary are visible without scrolling to Details; each queue row communicates severity and verdict without relying on hover; focus and selection remain distinguishable; and existing overview, compatibility, Tree navigation, verdict, and timeline flows remain unchanged.
