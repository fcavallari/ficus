import type { Severity } from '../rules/rules';
import type { Status } from '../session/store';
import type { ProcRef, Report, ReportCapture, ReportImage, ReportRow, Signature } from './report';

/**
 * The report as Markdown, for a person on the security team to read in a ticket or a chat. Everything here comes from
 * the report object, so it says what the JSON says. Every value that came from the capture or the user goes through
 * `code()` or `text()`: a file name can hold backticks, pipes, links or HTML, and must not change the layout.
 */

/** Plain text that cannot add Markdown structure: specials are backslash-escaped, newlines become spaces. */
export function text(s: string): string {
  return s.replace(/\r?\n|\r/g, ' ').replace(/[\\`*_[\]<>#|!~]/g, c => `\\${c}`);
}

/** An inline code span that holds `s` whatever backticks it contains; newlines are shown as ⏎. */
export function code(s: string): string {
  const v = s.replace(/\r?\n|\r/g, '⏎');
  const longest = Math.max(0, ...(v.match(/`+/g) ?? []).map(r => r.length));
  const fence = '`'.repeat(longest + 1);
  const pad = v.startsWith('`') || v.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${v}${pad}${fence}`;
}

const SEV_WORD: Record<Severity, string> = { high: 'High', med: 'Medium', low: 'Low' };
const VERDICT_WORD: Record<Status, string> = { unreviewed: 'Not reviewed', confirmed: 'Suspicious', benign: 'Benign' };
const SIG_WORDS: Record<Signature, string> = {
  'apple-platform': 'Apple platform binary', 'team-signed': 'signed by team', 'signed-no-team': 'signed, no team ID',
  adhoc: 'ad-hoc signed', unsigned: 'unsigned', unknown: 'unknown',
};
const USER_SECTION = 'Marked by the user, not flagged by the rules';

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;
/** A command line with each argument that has spaces (or is empty) quoted, as the app shows it. */
const argsLine = (args: string[]): string => args.map(a => (a === '' || /\s/.test(a) ? `"${a}"` : a)).join(' ');
/** "zsh (pid 6130)"; a process known only by its pid is already named by it. */
const who = (r: ProcRef): string => (r.pid >= 0 && !r.name.startsWith(`pid ${r.pid}`) ? `${text(r.name)} (pid ${r.pid})` : text(r.name));
const signature = (i: ReportImage): string =>
  i.signature === 'team-signed' && i.teamId ? `signed by team ${text(i.teamId)}` : SIG_WORDS[i.signature];

/** The latest image whose exec was captured, so it has arguments and a working directory; undefined when none was. */
function lastExec(images: ReportImage[]): ReportImage | undefined {
  for (let i = images.length - 1; i >= 0; i--) if (images[i]!.args !== null) return images[i];
  return undefined;
}

function row(r: ReportRow, fileName: string): string[] {
  const p = r.process;
  const head = [`### ${r.n}. ${text(r.name)}`, p ? ` (pid ${p.pid})` : '', r.findings[0] ? `: ${text(r.findings[0].title)}` : ''].join('');
  const out = [head, ''];
  const v = r.verdict;
  out.push(`- **User's verdict:** ${v ? VERDICT_WORD[v.status] : 'Not reviewed'}${v?.note ? `, note: “${text(v.note)}”` : ''}`);
  const marks = [code(fileName)];
  if (r.inFlaggedChain) marks.push('in a flagged chain');
  if (r.reconBurst) marks.push('recon burst');
  if (r.hiddenAsRoutine) marks.push('hidden by the user as routine');
  else if (r.keptReason) marks.push(`marked routine by the user, kept: ${text(r.keptReason)}`);
  out.push(`- **Capture:** ${marks.join(' · ')}`);
  if (p) {
    // The row is named after the latest program, so Program describes that one. The command line comes from the last
    // exec the capture saw; when that was an earlier program (a later change had no exec event), it says which.
    const img = p.images[p.images.length - 1];
    const exec = lastExec(p.images);
    if (exec?.args) {
      const label = exec === img ? '**Command line:**'
        : `**Command line** (of ${exec.path ? code(exec.path) : 'an earlier program'}, the last exec captured):`;
      out.push(`- ${label} ${code(argsLine(exec.args))}`);
    }
    if (img) out.push(`- **Program:** ${img.path ? code(img.path) : 'unknown'}, ${signature(img)}`);
    const others = p.images.filter(i => i !== img && !i.inherited && i.path !== null && i.path !== img?.path);
    if (others.length > 0) out.push(`- **Also ran:** ${others.map(i => code(i.path!)).join(', ')}`);
    if (exec?.cwd) out.push(`- **Working directory:** ${code(exec.cwd)}`);
    if (exec?.script) out.push(`- **Script:** ${code(exec.script)}`);
    out.push(`- **Started by:** ${[...p.ancestry].reverse().map(who).concat('this').join(' → ')}`);
    if (p.responsible) out.push(`- **Responsible:** ${who(p.responsible)}`);
    out.push(`- **Ran:** ${p.startTime ?? 'start not captured'} to ${p.exitTime ?? 'no exit captured'}`);
  }
  for (const i of r.launchItems) {
    const parts = [text(i.typeName)];
    if (i.plistPath) parts.push(code(i.plistPath));
    if (i.executablePath) parts.push(`runs ${code(i.executablePath)}`);
    if (i.appPath && i.appPath !== i.plistPath) parts.push(`app ${code(i.appPath)}`);
    parts.push(i.registeredBy ? `registered by ${who(i.registeredBy)} (${i.registeredBy.via})` : 'registered by no captured process');
    out.push(`- **Launch item:** ${parts.join(', ')}, at ${i.time}`);
  }
  if (r.findings.length > 0) {
    out.push('', r.kind === 'user-marked' ? '**Context-only findings**' : '**Findings**', '');
    for (const f of r.findings) {
      const tag = f.trait ? 'a trait of the binary, no technique' : f.mitre.join(', ') || 'no MITRE ID';
      out.push(`- **${text(f.title)}** (${SEV_WORD[f.severity].toLowerCase()}, ${tag}): ${text(f.explanation)}`);
      if (f.evidence) out.push(`  Evidence: ${code(f.evidence)}`);
    }
  }
  if (p) {
    const ops = p.fileOps;
    out.push('', `**What it did:** started ${plural(p.children, 'process', 'processes')}; ${plural(ops.total, 'file event')}${ops.total > ops.shown.length ? `, first ${ops.shown.length}` : ''}${ops.total > 0 ? ':' : '.'}`);
    if (ops.total > 0) out.push('');
    for (const o of ops.shown) out.push(`- ${o.kind} ${code(o.path)}${o.toPath ? ` → ${code(o.toPath)}` : ''}${o.xattr ? ` (${code(o.xattr)})` : ''}`);
  }
  out.push('');
  return out;
}

function captureLines(c: ReportCapture): string[] {
  if (!c.loaded) return [`- ${code(c.fileName)}: not loaded when the report was made.`];
  const span = c.firstTime ? `, ${c.firstTime} to ${c.lastTime ?? '?'}` : '';
  const schema = c.schemaVersions.length > 0 ? `, eslogger schema ${c.schemaVersions.map(v => `v${v}`).join(', ')}` : '';
  const out = [`- ${code(c.fileName)}: ${plural(c.events, 'event')}, ${plural(c.processes, 'process', 'processes')}${span}${schema}.`];
  const notes = [...(c.coverage ?? [])].sort((x, y) => (x.level === y.level ? 0 : x.level === 'warn' ? -1 : 1));
  for (const n of notes) out.push(`  - ${n.level === 'warn' ? '**Cannot see:** ' : ''}${text(n.title)}. ${text(n.detail)}`);
  const ctx = Object.entries(c.contextOnly ?? {}).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1));
  if (ctx.length > 0) out.push(`  - Low-signal findings kept out of the queue: ${ctx.map(([id, k]) => `${text(id)} ×${k}`).join(', ')}.`);
  return out;
}

export function reportMarkdown(r: Report): string {
  const s = r.summary;
  const loaded = r.captures.filter(c => c.loaded);
  const out = [`# Gameleira report: ${text(r.session.name)}`, ''];
  out.push(`Generated ${r.generated}. ${plural(s.rows, 'flagged row')} in ${plural(loaded.length, 'loaded capture')}: ${s.bySeverity.high} high, ${s.bySeverity.med} medium, ${s.bySeverity.low} low.`);
  out.push(`User's verdicts: ${s.byVerdict.confirmed} suspicious, ${s.byVerdict.benign} benign, ${s.byVerdict.unreviewed} not reviewed. (Verdicts were set by the person who ran the capture, not by security staff.)`);
  if (s.hiddenAsRoutine > 0) out.push(`${plural(s.hiddenAsRoutine, 'row')} the user hid as routine ${s.hiddenAsRoutine === 1 ? 'is' : 'are'} included and marked.`);
  if (s.userMarked > 0) out.push(`${plural(s.userMarked, 'process', 'processes')} the user marked without a rule flagging ${s.userMarked === 1 ? 'it is' : 'them are'} listed after the flagged rows.`);
  out.push(r.redacted ? 'Command-line arguments are redacted.' : 'Command lines are complete and may contain secrets.');
  out.push('');
  const missing = r.captures.filter(c => !c.loaded);
  if (missing.length > 0) {
    out.push(`> **Not loaded:** ${missing.map(c => code(c.fileName)).join(', ')}. Their flagged rows are not in this report; only the verdicts the user set on them are listed at the end.`, '');
  }
  if (s.rows === 0) out.push('No flagged rows.', '');

  out.push('## Captures', '');
  for (const c of r.captures) out.push(...captureLines(c));
  out.push('');

  const rows = r.captures.flatMap(c => (c.rows ?? []).map(x => ({ x, file: c.fileName })));
  for (const sev of ['high', 'med', 'low'] as const) {
    const these = rows.filter(e => e.x.severity === sev).sort((p, q) => p.x.n - q.x.n);
    if (these.length === 0) continue;
    out.push(`## ${SEV_WORD[sev]}`, '');
    for (const e of these) out.push(...row(e.x, e.file));
  }
  const marked = r.captures.flatMap(c => (c.userMarked ?? []).map(x => ({ x, file: c.fileName })));
  if (marked.length > 0) {
    out.push(`## ${USER_SECTION}`, '');
    for (const e of marked) out.push(...row(e.x, e.file));
  }
  const stale = missing.filter(c => (c.notLoaded ?? []).length > 0);
  if (missing.length > 0) {
    out.push('## Captures not loaded', '');
    if (stale.length === 0) out.push('The user set no verdicts on them.', '');
    for (const c of stale) {
      for (const v of c.notLoaded!) {
        const cmd = v.snapshot.args ? code(argsLine(v.snapshot.args)) : v.snapshot.path ? code(v.snapshot.path) : '';
        const rules = v.snapshot.ruleIds.length > 0 ? `, rules: ${v.snapshot.ruleIds.map(text).join(', ')}` : '';
        const sev = v.snapshot.severity ? `, ${SEV_WORD[v.snapshot.severity].toLowerCase()}` : '';
        out.push(`- ${code(c.fileName)}: **${text(v.snapshot.name)}**${cmd ? ` ${cmd}` : ''}${sev}${rules}. User's verdict: ${VERDICT_WORD[v.status]}${v.note ? `, note: “${text(v.note)}”` : ''}`);
      }
    }
    out.push('');
  }
  return `${out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}\n`;
}
