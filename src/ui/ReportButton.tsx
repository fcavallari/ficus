import { useState } from 'react';
import { reportMarkdown } from '../report/markdown';
import { buildReport, reportFileName } from '../report/report';
import { downloadText } from './download';
import { useSession } from './session-context';

/**
 * Writes the report for the security team: a Markdown file to read and a JSON file for their tools, with every flagged
 * row of the loaded captures, reviewed or not. In the header it is just the button; on the triage overview it comes with
 * what the files hold, the redaction choice (shared with Save session) and the captures it would leave out.
 */
export function ReportButton({ place }: { place: 'header' | 'overview' }) {
  const c = useSession();
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const session = c.session!;
  const { redactArgs } = c.exportOpts;
  const missing = c.capRecs.filter(r => !c.captures.has(r.fingerprint));

  const write = () => {
    setDone(null); setError(null);
    try {
      const report = buildReport(
        { session, capRecs: c.capRecs, loaded: c.captures, verdicts: c.allVerdicts, routineKeys: c.routineKeys },
        { redactArgs, generated: new Date().toISOString() },
      );
      const md = reportFileName(session, 'md');
      const json = reportFileName(session, 'json');
      downloadText(md, reportMarkdown(report), 'text/markdown');
      downloadText(json, JSON.stringify(report, null, 2), 'application/json');
      setDone(`Downloaded ${md} and ${json}.${missing.length > 0 ? ` Left out, not loaded: ${missing.map(r => r.fileName).join(', ')}.` : ''}`);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  const disabled = c.captures.size === 0;
  const status = (
    <>
      {done && <p role="status" className="small">{done}</p>}
      {error && <p role="alert" className="error">{error}</p>}
    </>
  );
  if (place === 'header') {
    return (
      <span className="report-group">
        <button onClick={write} disabled={disabled}
          title="Download a Markdown and a JSON report of every flagged row in the loaded captures, reviewed or not, for your security team.">
          Report for security
        </button>
        {status}
      </span>
    );
  }
  return (
    <section className="report-offer" aria-labelledby="ov-report">
      <h3 id="ov-report">For your security team</h3>
      <button className="primary" onClick={write} disabled={disabled}>Report flagged processes for security</button>
      <p className="muted small">Writes a Markdown file to read and a JSON file for security tools, with every flagged row, reviewed or not.</p>
      <label className="inline small">
        <input type="checkbox" checked={redactArgs} onChange={e => { c.setExportOpts({ redactArgs: e.target.checked }); }} /> Redact command-line arguments
      </label>
      <p className="small">
        {!redactArgs && <span className="warn">Command lines can hold secrets such as passwords. </span>}
        <span className="muted">Your notes are included as written.</span>
      </p>
      {missing.map(r => (
        <p key={r.fingerprint} className="warn small">{r.fileName} isn't loaded, so its flagged rows can't be included. Re-add it first, or export without it.</p>
      ))}
      {status}
    </section>
  );
}
