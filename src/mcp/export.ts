// What a person sends to Security Ops: a new folder on their Desktop with the agent's verdict, the Ficus report
// files, and in 'full' mode the cleaned capture plus a session file the Ficus web app imports. The folder goes to
// Security Ops, not to the agent, so the tool returns only its path and the file names. The key file (the real
// values behind the placeholders) is never copied here.
import fs from 'node:fs';
import path from 'node:path';
import { reportMarkdown } from '../report/markdown';
import { reportFileName } from '../report/report';
import { saveFileName, type SessionExport } from '../session/export';
import { cleanedCapturePath, CaptureRefused, type FicusPaths } from './home';
import type { Workspace } from './workspace';

export interface ExportResult {
  folder: string;
  /** File names in the folder, sorted. */
  files: string[];
}

const pad = (n: number): string => String(n).padStart(2, '0');

/** `Ficus report YYYY-MM-DD HHMMSS`, from the local-time fields of `d`. */
function folderName(d: Date): string {
  return `Ficus report ${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

/** The Desktop is protected by macOS: the first write there can be refused until the person allows it. */
function desktopRefused(root: string, e: unknown): Error | undefined {
  const code = (e as NodeJS.ErrnoException | undefined)?.code;
  if (code !== 'EPERM' && code !== 'EACCES') return undefined;
  return new Error(
    `The Ficus server could not write to the Desktop folder (${root}). macOS may need to allow it: ask the person to open ` +
      'System Settings > Privacy & Security, give the app that runs this server access to the Desktop folder (Files & Folders), ' +
      'and then call ficus_export again. Nothing was exported.',
  );
}

/** Make a new folder, never reusing one: `… 2`, `… 3` when the name is taken. */
function makeFolder(root: string, base: string): string {
  fs.mkdirSync(root, { recursive: true });
  for (let i = 1; ; i++) {
    const folder = path.join(root, i === 1 ? base : `${base} ${i}`);
    try {
      fs.mkdirSync(folder, { recursive: false });
      return folder;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
  }
}

function readme(full: boolean, redact: boolean, capture: string, sessionFile: string, reportMd: string, reportJson: string): string {
  const lines = [
    'Ficus report for Security Ops',
    '',
    'What is in this folder:',
    '  agent-verdict.md  The AI agent\'s verdict on the capture, and the list of rows it was shown with the person\'s consent.',
    `  ${reportMd}  The Ficus report, to read.`,
    `  ${reportJson}  The same report, for tools.`,
  ];
  if (full) {
    lines.push(
      `  ${capture}  The capture. It is pseudonymized.`,
      `  ${sessionFile}  A Ficus session, to open in Ficus (see below).`,
    );
  } else {
    lines.push('', 'The capture itself is not included.');
  }
  lines.push(
    '',
    'The capture is pseudonymized, not anonymous: the cleaner replaced user names, home folders and host names with placeholders before anything was analyzed, but everything else in it (program names, paths, other names and values) is as recorded.',
    '',
    redact
      ? 'The report files were exported with redaction: the arguments after each program name are removed.'
      : 'The report files contain the cleaned command lines (the arguments after each program name), as they appear in the capture.',
    '',
    'Read the report before you send this folder to anyone.',
    '',
    'The key that maps the placeholders back to the real values stays on the Mac that recorded the capture. It is not in this folder.',
  );
  if (full) {
    lines.push(
      '',
      'To open the full session in Ficus: on Ficus\'s home page use "Import a session" and choose the .ficus-session.json file, then drop the capture file in to see the same tree.',
    );
  }
  lines.push('');
  return lines.join('\n');
}

export async function writeExport(
  ws: Workspace,
  p: FicusPaths,
  name: string,
  opts: { mode: 'report' | 'full'; verdict: string; redact?: boolean },
  now: Date = new Date(),
): Promise<ExportResult> {
  // Everything that can refuse or fail is done before the folder exists, so a refusal leaves nothing behind.
  const source = cleanedCapturePath(p, name);
  if (name.endsWith('.key.tsv')) throw new CaptureRefused(`"${name}" is a key file and is never exported.`);
  const full = opts.mode === 'full';
  const session = ws.session(name);
  const report = await ws.report(name, opts.redact === true);
  const names = new Map((await ws.report(name, true)).captures[0]!.rows?.map(r => [r.key, r.name]) ?? []);

  const mdName = reportFileName(session, 'md');
  const jsonName = reportFileName(session, 'json');
  const sessionName = saveFileName(session);
  const iso = now.toISOString();

  const revealed = ws.revealed(name).map(key => `- ${names.get(key) ?? 'unknown row'} (${key})`);
  // The server's own record comes first, so the agent's text cannot push it out of sight or imitate it.
  const verdictFile = [
    '## Shown to the agent with consent',
    '',
    ...(revealed.length > 0 ? revealed : ['none recorded since the Ficus server started']),
    '',
    '---',
    '',
    opts.verdict,
    '',
  ].join('\n');

  const texts: [string, string][] = [
    ['agent-verdict.md', verdictFile],
    ['README.txt', readme(full, opts.redact === true, name, sessionName, mdName, jsonName)],
    [mdName, reportMarkdown(report)],
    [jsonName, JSON.stringify(report, null, 2)],
  ];
  if (full) {
    const data: SessionExport = {
      format: 'ficus-session',
      version: 1,
      session: { ...session, created: iso, updated: iso },
      captures: [await ws.captureRec(name)],
      verdicts: [],
      routine: [],
      details: {},
    };
    texts.push([sessionName, JSON.stringify(data, null, 2)]);
  }

  let folder: string;
  try {
    folder = makeFolder(p.exportRoot, folderName(now));
  } catch (e) {
    throw desktopRefused(p.exportRoot, e) ?? e;
  }
  try {
    // 'wx' and COPYFILE_EXCL: nothing in the new folder is overwritten, even if the capture is named like a report file.
    for (const [file, text] of texts) fs.writeFileSync(path.join(folder, file), text, { flag: 'wx' });
    if (full) fs.copyFileSync(source, path.join(folder, name), fs.constants.COPYFILE_EXCL);
  } catch (e) {
    fs.rmSync(folder, { recursive: true, force: true }); // a half-written folder must not look like a report
    throw desktopRefused(p.exportRoot, e) ?? e;
  }
  return { folder, files: fs.readdirSync(folder).sort() };
}
