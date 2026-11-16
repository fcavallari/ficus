# Investigation Workspace UX Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface selected-process evidence sooner and clarify severity and verdict in the compact Triage queue.

**Architecture:** Reuse `Process`, `Image`, and timeline helpers in `DetailPane`; keep selection, queue filters, and verdict storage unchanged. Update `QueueList` and its CSS for always-readable labels and clear focus feedback without changing row virtualization or listbox semantics.

**Tech Stack:** React 19, TypeScript, existing CSS, existing timeline helpers.

**Spec:** `docs/superpowers/specs/2026-11-15-investigation-workspace-ux-design.md`

## Global Constraints

- Preserve existing capture import/export and stored verdict values.
- Do not infer missing process data, events, or timestamps.
- Preserve existing keyboard shortcuts, layout, palette, and compact queue design.
- Add no dependencies.

## Review Focus

- Process without an exec image or recorded timestamps: omit unavailable summary fields and keep current graceful fallbacks.
- Queue row in narrow layout: retain readable severity and verdict while allowing process name and arguments to truncate.
- Keyboard-selected queue row in normal and forced-colors modes: distinguish it from hover and keyboard focus without changing navigation behavior.

---

### Task 1: Surface selected-process evidence in the detail header

**Files:**
- Modify: `src/ui/DetailPane.tsx`
- Modify: `src/ui/styles.css`

**Interfaces:**
- Consume existing `processTimeline`, `recordedSpan`, `recordedCounts`, `latestImage`, and `fmtArgs` helpers.
- Keep the detail header's existing process identity and assessment controls; add compact evidence only when present.

- [ ] Derive command-line arguments from the latest captured exec image; omit the line when no exec arguments were captured.
- [ ] Derive the observed first/last timestamps and event count from the existing per-process timeline; show a single timestamp when first and last are equal, and omit timestamp text when no events are timed.
- [ ] Place the evidence summary below the existing path and above assessment chips; allow long command lines and paths to wrap without horizontal overflow.
- [ ] Review behavior for ghost processes, processes without timestamps, and processes without exec events by tracing existing helper behavior and inspecting the resulting diff. Do not add or run tests.

### Task 2: Clarify queue labels and keyboard feedback

**Files:**
- Modify: `src/ui/QueueList.tsx`
- Modify: `src/ui/styles.css`

**Interfaces:**
- Consume existing `SEVERITY_LABEL`, `VERDICT_LABEL`, `STATUS_ICON`, and `optionId` values.
- Preserve the `role="listbox"` / `role="option"` relationship, `aria-selected`, virtualization, and row click behavior.

- [ ] Render full severity labels and visible verdict text in each row while retaining the existing status icon and color treatment.
- [ ] Adjust row flex sizing so severity and verdict remain legible at narrow widths while process name and arguments truncate first.
- [ ] Add a `:focus-visible` treatment for the focused listbox and keep the selected row's accent treatment distinct from hover; retain forced-colors selection outline.
- [ ] Review listbox semantics, keyboard interaction wiring, and narrow-width styles in the resulting diff. Do not add or run tests.
