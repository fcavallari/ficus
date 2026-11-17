import type { CaptureModel, Image, Process } from '../model/types';
import { imageAt } from '../model/util';

/** How far apart, in ms, the commands of one pasted line start: they run within the same moment of one paste. */
export const PASTE_WINDOW_MS = 3000;

/** The original parent's image when this process was born (the parent may exec something else later). */
export function originalParentImage(m: CaptureModel, p: Process): Image | undefined {
  const parent = p.originalParent !== null ? m.processes.get(p.originalParent) : undefined;
  return parent ? imageAt(parent, p.firstSeq) : undefined;
}

/** The other processes that share this one's original parent. None when the parent is unknown; ghosts are left out. */
export function siblings(m: CaptureModel, p: Process): Process[] {
  if (p.originalParent === null) return [];
  return [...m.processes.values()].filter(o => o !== p && !o.ghost && o.originalParent === p.originalParent);
}

/** The shell-snapshot folders of the AI coding agents (Claude Code, Codex, Cursor). */
const AGENT_SNAPSHOTS = /\.(?:claude\/shell-snapshots|codex\/shell_snapshots|cursor\/shell-snapshots)\//;

/** True when the shell that started this process sourced an AI coding agent's snapshot: agents run `base64 -d` and `curl` through such shells. */
export function underAgentShell(m: CaptureModel, p: Process): boolean {
  return originalParentImage(m, p)?.args?.some(a => AGENT_SNAPSHOTS.test(a)) ?? false;
}
