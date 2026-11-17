import { useState } from 'react';
import { reportMarkdown } from '../report/markdown';
import { buildReport, reportFileName } from '../report/report';
import { downloadText } from './download';
import { useSession } from './session-context';

export interface ReportExport {
  write(): void;
  disabled: boolean;
  /** What the last click downloaded, for a status line. */
  done: string | null;
  error: string | null;
}

/**
 * Writes the report for the security team: a Markdown file to read and a JSON file for their tools, with every flagged
 * row of the loaded captures, reviewed or not, redacted as Save session is.
 */
export function useReportExport(): ReportExport {
  const c = useSession();
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const write = () => {
    setDone(null); setError(null);
    const session = c.session!;
    const missing = c.capRecs.filter(r => !c.captures.has(r.fingerprint));
    try {
      const report = buildReport(
        { session, capRecs: c.capRecs, loaded: c.captures, verdicts: c.allVerdicts, routineKeys: c.routineKeys },
        { redactArgs: c.exportOpts.redactArgs, generated: new Date().toISOString() },
      );
      const md = reportFileName(session, 'md');
      const json = reportFileName(session, 'json');
      downloadText(md, reportMarkdown(report), 'text/markdown');
      downloadText(json, JSON.stringify(report, null, 2), 'application/json');
      setDone(`Downloaded ${md} and ${json}.${missing.length > 0 ? ` Left out, not loaded: ${missing.map(r => r.fileName).join(', ')}.` : ''}`);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return { write, disabled: c.captures.size === 0, done, error };
}

/** The header's button; its status lines go under the title row, beside Save session's. */
export function ReportButton({ r }: { r: ReportExport }) {
  return (
    <button onClick={r.write} disabled={r.disabled}
      title="Download a Markdown and a JSON report of every flagged row in the loaded captures, reviewed or not, for your security team.">
      Report for security
    </button>
  );
}

export function ReportStatus({ r, className }: { r: ReportExport; className?: string }) {
  return (
    <>
      {r.done && <p role="status" className={`small ${className ?? ''}`.trim()}>{r.done}</p>}
      {r.error && <p role="alert" className="error">{r.error}</p>}
    </>
  );
}

/** On the triage overview: the button with what the files hold, the redaction choice and the captures it would leave out. */
export function ReportOffer() {
  const c = useSession();
  const r = useReportExport();
  const { redactArgs } = c.exportOpts;
  const missing = c.capRecs.filter(x => !c.captures.has(x.fingerprint));
  return (
    <section className="report-offer" aria-labelledby="ov-report">
      <h3 id="ov-report">For your security team</h3>
      <button className="primary" onClick={r.write} disabled={r.disabled}>Report flagged processes for security</button>
      <p className="muted small">Writes a Markdown file to read and a JSON file for security tools, with every flagged row, reviewed or not.</p>
      <label className="inline small">
        <input type="checkbox" checked={redactArgs} onChange={e => { c.setExportOpts({ redactArgs: e.target.checked }); }} /> Redact command-line arguments
      </label>
      <p className="small">
        {!redactArgs && <span className="warn">Command lines can hold secrets such as passwords. </span>}
        <span className="muted">Your notes are included as written.</span>
      </p>
      {missing.map(x => (
        <p key={x.fingerprint} className="warn small">{x.fileName} isn't loaded, so its flagged rows can't be included. Re-add it first, or export without it.</p>
      ))}
      <ReportStatus r={r} />
    </section>
  );
}
