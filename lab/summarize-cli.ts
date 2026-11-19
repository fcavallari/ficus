// summarize-cli.ts: the command line for summarize-core. Built to dist-lab/lab-summarize.mjs with `npm run build:lab`.
//
//   node dist-lab/lab-summarize.mjs [--under PROGRAM_PATH_PART] RUN_DIR [EXPECTED_TSV]
//
// --under keeps only the findings about the sample: its process or a descendant whose program path contains the text. Use it for any
// run where the capture holds more than the sample (a manual run has your own commands; macOS's crash reporter runs tools too).
//
// RUN_DIR is a run folder from lab-run.sh (it holds capture.jsonl), or a capture file itself. Prints the findings as a table
// (tab-separated) on stdout; the facts about the capture and any notes go to stderr. With EXPECTED_TSV (see lab/expected/README.md)
// it also writes gap.md beside the capture. Exit 0 whatever the findings, 1 on a missing file or an unreadable expected file, 2 on usage.
import fs from 'node:fs';
import path from 'node:path';
import { compare, countDrops, filterUnder, findingsTsv, gapMarkdown, linesOf, parseExpected, schemaNotes, summarize } from './summarize-core';

const USAGE = 'usage: lab-summarize.mjs [--under PROGRAM_PATH_PART] RUN_DIR [EXPECTED_TSV]\n'
  + '  --under  keep only findings about the sample: its process or a descendant whose program path contains this text\n'
  + '           (use it for a manual run, where the capture also holds your own commands and macOS\'s crash reporter)\n';

function main(argv: string[]): number {
  let under: string | undefined;
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--under') { under = argv[++i]; if (under === undefined) { process.stderr.write(USAGE); return 2; } }
    else if (a.startsWith('--under=')) under = a.slice('--under='.length);
    else if (a.startsWith('-')) { process.stderr.write(USAGE); return 2; }
    else positional.push(a);
  }
  if (positional.length < 1 || positional.length > 2) { process.stderr.write(USAGE); return 2; }
  const [target, expectedFile] = positional as [string, string | undefined];
  const isFile = fs.existsSync(target) && fs.statSync(target).isFile();
  const dir = isFile ? path.dirname(target) : target;
  const capture = isFile ? target : path.join(target, 'capture.jsonl');
  if (!fs.existsSync(capture)) { process.stderr.write(`error: ${capture} does not exist\n`); return 1; }

  let expected;
  if (expectedFile !== undefined) {
    try { expected = parseExpected(fs.readFileSync(expectedFile, 'utf8')); }
    catch (e) { process.stderr.write(`error: ${expectedFile}: ${(e as Error).message}\n`); return 1; }
  }

  const s = summarize(linesOf(capture));
  const drops = countDrops(linesOf(capture));
  let rows = s.rows;
  if (under !== undefined) {
    try { rows = filterUnder(s.rows, under); }
    catch (e) { process.stderr.write(`error: ${(e as Error).message}\n`); return 2; }
  }
  process.stdout.write(findingsTsv(rows));
  process.stderr.write(`events ${s.events}, processes ${s.processes}, schema ${s.versions.join('/') || 'unknown'}, bad lines ${s.badLines}, dropped events ${drops.total}, findings ${s.rows.length}\n`);
  if (under !== undefined) process.stderr.write(`kept ${rows.length} of ${s.rows.length} findings: the process tree under "${under}"\n`);
  for (const note of schemaNotes(s.versions)) process.stderr.write(`note: ${note}\n`);
  if (drops.total > 0) {
    process.stderr.write(`note: Endpoint Security dropped events while recording (${Object.entries(drops.byType).map(([t, n]) => `${t} ${n}`).join(', ')}); the capture is incomplete, so a miss may be a missing event\n`);
  }
  if (s.badLines > 0) process.stderr.write(`note: ${s.badLines} lines could not be read\n`);

  if (expected) {
    let family = path.basename(path.resolve(dir));
    try { family = (JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')) as { family?: string }).family ?? family; } catch { /* no meta.json: the folder name will do */ }
    const c = compare(rows, expected);
    const out = path.join(dir, 'gap.md');
    fs.writeFileSync(out, gapMarkdown(family, c, under));
    process.stderr.write(`${out}: hit ${c.hit.length}, miss ${c.miss.length}, gap ${c.gap.length}, review ${c.review.length}\n`);
  }
  return 0;
}

process.exit(main(process.argv.slice(2)));
