// The one place the server reads a capture and builds a report. Everything an agent sees comes from here, and
// by default from a report built with redactArgs: true, which holds no argument after argv[0] anywhere.
// Only row(name, key, true) returns an unredacted row, and each such reveal is remembered per capture.
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { loadCapture, type LoadedCapture } from '../ingest/load';
import { buildReport, type Report, type ReportRow, type Signature } from '../report/report';
import type { Severity } from '../rules/rules';
import type { CaptureRec, Session } from '../session/store';
import { cleanedCapturePath, type FicusPaths } from './home';

export const PAGE_SIZE = 40;

export class UnknownRow extends Error {
  constructor(key: string) {
    super(`No row with key "${key}" in this capture. Take keys from ficus_analyze.`);
    this.name = 'UnknownRow';
  }
}

export interface AnalyzeRow {
  n: number;
  key: string;
  kind: ReportRow['kind'];
  name: string;
  severity: Severity | null;
  inFlaggedChain: boolean;
  reconBurst: boolean;
  path: string | null;
  signature: Signature | null;
  findings: { ruleId: string; severity: Severity; title: string; mitre: string[]; evidence: string; trait: boolean }[];
  launchItems: { typeName: string; plistPath: string | null; executablePath: string | null }[];
}

export interface AnalyzeView {
  capture: {
    name: string;
    firstTime: string | null;
    lastTime: string | null;
    events: number;
    processes: number;
    schemaVersions: number[];
    coverage: { id: string; level: 'warn' | 'info'; title: string; checks: string[] }[];
    coverageDetail: Record<string, string>;
  };
  summary: { rows: number; bySeverity: Record<Severity, number>; contextOnly: Record<string, number> };
  rows: AnalyzeRow[];
  offset: number;
  truncated: { remaining: number; bySeverity: Record<Severity, number> } | null;
  rules: Record<string, string>;
}

interface Loaded {
  name: string;
  /** Size and mtime when read: a file that changed since is read again. */
  stamp: string;
  cap: Promise<LoadedCapture>;
  /** The redacted report, built on first use; it does not change while the capture stays loaded. */
  redacted?: Report;
}

const pad = (n: number): string => String(n).padStart(2, '0');

function sessionName(d: Date): string {
  return `self-check ${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export class Workspace {
  private current: Loaded | null = null;
  private readonly sessions = new Map<string, Pick<Session, 'id' | 'name'>>();
  private readonly reveals = new Map<string, string[]>();

  constructor(private readonly paths: FicusPaths, private readonly now: () => Date = () => new Date()) {}

  /** Resolve through the cleaned-capture guard, then load. Keeps only the last capture; the same one is not parsed twice. */
  private async entry(name: string): Promise<Loaded> {
    const file = cleanedCapturePath(this.paths, name); // throws CaptureRefused, on every call
    const st = fs.statSync(file);
    const stamp = `${st.size}:${st.mtimeMs}`;
    if (this.current && this.current.name === name && this.current.stamp === stamp) return this.current;
    const entry: Loaded = {
      name,
      stamp,
      // Registered before anything is awaited, so a second call for the same capture shares this load.
      cap: (async () => ({ ...(await loadCapture(await fs.openAsBlob(file))), fileName: name }))(),
    };
    this.current = entry;
    try {
      await entry.cap;
    } catch (e) {
      if (this.current === entry) this.current = null; // a failed load is not cached
      throw e;
    }
    return entry;
  }

  async load(name: string): Promise<LoadedCapture> {
    return (await this.entry(name)).cap;
  }

  /** A made-up session per capture, stable for the life of the server. */
  session(name: string): Pick<Session, 'id' | 'name'> {
    let s = this.sessions.get(name);
    if (!s) {
      s = { id: randomUUID(), name: sessionName(this.now()) };
      this.sessions.set(name, s);
    }
    return s;
  }

  async captureRec(name: string): Promise<CaptureRec> {
    return this.recFor(name, await this.load(name));
  }

  private recFor(name: string, cap: LoadedCapture): CaptureRec {
    return {
      sessionId: this.session(name).id, fingerprint: cap.fingerprint, fileName: cap.fileName, size: cap.size,
      events: cap.model.stats.events, processes: cap.model.processes.size, flagged: cap.analysis.queue.length,
      added: this.now().toISOString(),
    };
  }

  private build(name: string, cap: LoadedCapture, redact: boolean): Report {
    return buildReport(
      {
        session: this.session(name),
        capRecs: [this.recFor(name, cap)],
        loaded: new Map([[cap.fingerprint, cap]]),
        verdicts: [],
        routineKeys: new Set(),
      },
      { redactArgs: redact, generated: this.now().toISOString() },
    );
  }

  async report(name: string, redact: boolean): Promise<Report> {
    const entry = await this.entry(name);
    const cap = await entry.cap;
    if (!redact) return this.build(name, cap, false);
    return (entry.redacted ??= this.build(name, cap, true));
  }

  async analyze(name: string, offset = 0, pageSize = PAGE_SIZE): Promise<AnalyzeView> {
    const report = await this.report(name, true);
    const c = report.captures[0]!;
    const sorted = [...(c.rows ?? [])].sort((a, b) => a.n - b.n);
    const start = Math.max(0, Math.floor(offset) || 0);
    const size = Math.max(1, Math.floor(pageSize) || PAGE_SIZE);
    const page = sorted.slice(start, start + size);
    const rest = sorted.slice(start + page.length);

    // One entry per rule id. A rule can explain itself differently per finding (the recon rule names what each tool
    // reads), so the distinct texts are kept, not just the first.
    const texts = new Map<string, string[]>();
    for (const row of page) {
      for (const f of row.findings) {
        const list = texts.get(f.ruleId) ?? [];
        if (!list.includes(f.explanation)) list.push(f.explanation);
        texts.set(f.ruleId, list);
      }
    }
    const rules: Record<string, string> = Object.fromEntries([...texts].map(([id, list]) => [id, list.join('\n')]));

    const remaining: Record<Severity, number> = { high: 0, med: 0, low: 0 };
    for (const r of rest) if (r.severity) remaining[r.severity]++;

    const coverage = c.coverage ?? [];
    return {
      capture: {
        name: c.fileName,
        firstTime: c.firstTime,
        lastTime: c.lastTime,
        events: c.events,
        processes: c.processes,
        schemaVersions: c.schemaVersions,
        coverage: coverage.map(({ id, level, title, checks }) => ({ id, level, title, checks })),
        coverageDetail: Object.fromEntries(coverage.map(n => [n.id, n.detail])),
      },
      summary: { rows: report.summary.rows, bySeverity: report.summary.bySeverity, contextOnly: c.contextOnly ?? {} },
      rows: page.map(projectRow),
      offset: start,
      truncated: rest.length > 0 ? { remaining: rest.length, bySeverity: remaining } : null,
      rules,
    };
  }

  /** One row in full. `reveal` builds an unredacted report and remembers that this row was shown that way. */
  async row(name: string, key: string, reveal = false): Promise<ReportRow> {
    const report = await this.report(name, !reveal); // redact unless this is a reveal
    const found = report.captures[0]!.rows?.find(r => r.key === key);
    if (!found) throw new UnknownRow(key);
    if (reveal) {
      const list = this.reveals.get(name) ?? [];
      if (!list.includes(key)) list.push(key);
      this.reveals.set(name, list);
    }
    return found;
  }

  /** Keys of the rows shown unredacted for this capture, in the order they were revealed. */
  revealed(name: string): string[] {
    return [...(this.reveals.get(name) ?? [])];
  }
}

function projectRow(row: ReportRow): AnalyzeRow {
  const images = row.process?.images ?? [];
  const last = images[images.length - 1];
  return {
    n: row.n,
    key: row.key,
    kind: row.kind,
    name: row.name,
    severity: row.severity,
    inFlaggedChain: row.inFlaggedChain,
    reconBurst: row.reconBurst,
    path: last?.path ?? null,
    signature: last?.signature ?? null,
    findings: row.findings.map(({ ruleId, severity, title, mitre, evidence, trait }) => ({ ruleId, severity, title, mitre, evidence, trait })),
    launchItems: row.launchItems.map(({ typeName, plistPath, executablePath }) => ({ typeName, plistPath, executablePath })),
  };
}
