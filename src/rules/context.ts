import type { CaptureModel, Image, ProcId, Process } from '../model/types';
import { basename, imageAt } from '../model/util';

/** How far apart, in ms, the commands of one pasted line start: they run within the same moment of one paste. */
export const PASTE_WINDOW_MS = 3000;

/** The original parent's image when this process was born (the parent may exec something else later). */
export function originalParentImage(m: CaptureModel, p: Process): Image | undefined {
  const parent = p.originalParent !== null ? m.processes.get(p.originalParent) : undefined;
  return parent ? imageAt(parent, p.firstSeq) : undefined;
}

/** Each live (non-ghost) process under its original parent, in capture order, built once per model. */
const childIndexes = new WeakMap<CaptureModel, Map<ProcId, Process[]>>();

function childIndex(m: CaptureModel): Map<ProcId, Process[]> {
  const cached = childIndexes.get(m);
  if (cached) return cached;
  const index = new Map<ProcId, Process[]>();
  for (const o of m.processes.values()) {
    if (o.ghost || o.originalParent === null) continue;
    const list = index.get(o.originalParent);
    if (list) list.push(o); else index.set(o.originalParent, [o]);
  }
  childIndexes.set(m, index);
  return index;
}

/** The other processes that share this one's original parent. None when the parent is unknown; ghosts are left out. */
export function siblings(m: CaptureModel, p: Process): Process[] {
  if (p.originalParent === null) return [];
  return (childIndex(m).get(p.originalParent) ?? []).filter(o => o !== p);
}

/** The AI coding agents Ficus knows by name. */
export type Agent = 'claude' | 'codex' | 'cursor' | 'gemini';

/** The shell-snapshot folder each agent's shells source (Gemini CLI has none). */
const AGENT_SNAPSHOTS: [Agent, RegExp][] = [
  ['claude', /\.claude\/shell-snapshots\//],
  ['codex', /\.codex\/shell_snapshots\//],
  ['cursor', /\.cursor\/shell-snapshots\//],
];

/**
 * The agent an npm- or bun-installed CLI is: node or bun running a script whose path names the agent
 * (`@anthropic-ai/claude-code/cli.js`, `@google/gemini-cli/…`, `@openai/codex/…`). Only the program and its arguments
 * count, never what a shell was told to run.
 */
export function agentRuntime(img: Image | undefined): Agent | null {
  if (img === undefined || !['node', 'bun'].includes(basename(img.path))) return null;
  const args = img.args?.slice(1) ?? [];
  if (args.some(a => a.includes('claude-code'))) return 'claude';
  if (args.some(a => a.includes('gemini-cli'))) return 'gemini';
  if (args.some(a => a.split('/').includes('codex'))) return 'codex';
  return null;
}

/**
 * Which agent this image is, from what it is rather than what it says: Claude Code's `claude` executable (also under
 * `/claude-code/` or `/share/claude/versions/`), Codex's `codex`, anything inside Cursor.app, or an npm-installed agent
 * running under node or bun.
 */
export function agentOf(img: Image | undefined): Agent | null {
  if (img === undefined) return null;
  const path = img.path ?? '';
  if (basename(path) === 'claude' || path.includes('/claude-code/') || path.includes('/share/claude/versions/')) return 'claude';
  if (basename(path) === 'codex') return 'codex';
  if (path.includes('/Cursor.app/')) return 'cursor';
  return agentRuntime(img);
}

/**
 * True when this image sources the shell-snapshot folder of the agent that started it. The folder name alone proves
 * nothing, since any command line can carry it (a trailing comment, a copied `source … || true` prefix), so the
 * image's parent must itself be the matching agent.
 */
export function sourcesAgentSnapshot(img: Image, parent: Image | undefined): boolean {
  const agent = agentOf(parent);
  if (agent === null) return false;
  const folder = AGENT_SNAPSHOTS.find(([who]) => who === agent)?.[1];
  return folder !== undefined && (img.args?.some(a => folder.test(a)) ?? false);
}

/** True when the shell that started this process is an agent's snapshot shell: reader -> snapshot shell -> the agent itself. */
export function underAgentShell(m: CaptureModel, p: Process): boolean {
  const shell = p.originalParent !== null ? m.processes.get(p.originalParent) : undefined;
  const shellImage = originalParentImage(m, p);
  return shell !== undefined && shellImage !== undefined && sourcesAgentSnapshot(shellImage, originalParentImage(m, shell));
}
