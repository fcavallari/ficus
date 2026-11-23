#!/usr/bin/env node
// gen-indicators.mjs: copies what the am-i-pwned skill takes from Ficus into the skill's home, the am-i-pwned plugin in
// the claude-code-plugins repo. Ficus owns src/rules/indicators.json (its known-indicator rule reads it too) and the list of
// developer tooling folders in src/rules/locations.ts; the plugin holds generated copies, so one list is kept, here.
//
//   node scripts/gen-indicators.mjs             write the copies into the plugin checkout, and say what changed
//   node scripts/gen-indicators.mjs --check     change nothing; exit 1 if a copy is out of date (2 if there is no
//                                                checkout, 3 if a target file or marker is missing)
//   node scripts/gen-indicators.mjs --to DIR    the skill folder to write to (default: $AM_I_PWNED_DIR, else
//                                                ~/WORK/claude-code-plugins/plugins/am-i-pwned/skills/am-i-pwned)
//
// The copies are the generated reference page (references/known-indicators.md), the generated block of lib/indicators.sh,
// and the list of tooling folders in lib/signatures.sh (the awk of the processes check). They are never edited by hand; each
// carries a hash of its source, so a copy that was changed or left behind is visible. After a change to either source, run this, then commit in BOTH repos (the
// pre-commit hook in .githooks and test/plugin-sync.test.ts both fail when the copy is behind).

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, 'src/rules/indicators.json');
const LOCATIONS = path.join(ROOT, 'src/rules/locations.ts');
export const DEFAULT_TARGET = path.join(os.homedir(), 'WORK/claude-code-plugins/plugins/am-i-pwned/skills/am-i-pwned');
export const BEGIN = '# BEGIN GENERATED INDICATORS';
export const END = '# END GENERATED INDICATORS';
const SOURCE = 'fcavallari/ficus, src/rules/indicators.json';

/** The skill folder to write to: --to DIR, else $AM_I_PWNED_DIR, else the default checkout. */
export function targetDir(argv = process.argv) {
  const i = argv.indexOf('--to');
  if (i >= 0 && argv[i + 1]) return path.resolve(argv[i + 1]);
  return process.env.AM_I_PWNED_DIR ? path.resolve(process.env.AM_I_PWNED_DIR) : DEFAULT_TARGET;
}
/** A short hash of a source's text: what a copy records, so a stale or hand-edited copy shows. */
export const stampOf = text => crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);

const KIND_WORDS = {
  'team-id': 'signing team', 'signing-id': 'signing ID', path: 'path', plist: 'launch plist', argv: 'command-line word',
};
const cell = s => s.replace(/\|/g, '\\|');

/** The skill's reference page. */
export function renderPage(data, stamp) {
  const out = [
    '# Known actor indicators',
    '',
    `<!-- Generated in the Ficus repo (${SOURCE}, sha256 ${stamp}) by scripts/gen-indicators.mjs. Do not edit this page: edit the source there and run the script. -->`,
    '',
    data.about,
    '',
    `Last updated ${data.updated}. ${data.pathSyntax}`,
    '',
    '## How to use it',
    '',
    '- The `indicators` check of `mac-triage.sh` (`checks/70-indicators.sh`) looks for the **paths, launch plists, signing teams and signing IDs** below on this Mac and prints each match with its family. It cannot read command lines (they are off limits), so the *command-line word* entries are for a Ficus capture.',
    '- A match with a **high** entry is a finding at level 3 of *Choosing the verdict* (`reading-the-result.md`); a match with a **medium** entry is level 2. Say which family and which entry, and quote the source.',
    '- **No match proves nothing.** A family renames its files between samples, a list ages, and a Mac can be compromised by a family that is not here. Never say a Mac is clean because this list found nothing.',
    '- Never use an indicator from memory. If this page is not in front of you, say the check was not done.',
    '- **Attribution is the vendor\'s, with its own confidence.** Where a family\'s actor is tentative or not named, the table says so; do not tell the person a state actor is behind it unless the row says so.',
    '',
  ];
  for (const f of data.families) {
    out.push(`## ${f.name}`, '', `**Actor:** ${f.actor}. **Attribution:** ${f.attribution}.`, '', f.summary, '',
      '| Kind | Value | Severity | Confidence | What it is | Source |', '| --- | --- | --- | --- | --- | --- |');
    for (const i of f.indicators) {
      out.push(`| ${KIND_WORDS[i.kind]} | \`${cell(i.value)}\` | ${i.severity} | ${i.confidence} | ${cell(i.note ?? '')} | ${i.source} |`);
    }
    out.push('');
  }
  return `${out.join('\n').trimEnd()}\n`;
}

// What the script looks for: signing IDs, the paths it checks where they are published (a shell glob), and the paths
// published without a folder (they start with `**/`), which it searches for in the places it names. Command-line words are
// left out (the script cannot read command lines). A `**` anywhere but at the start is refused rather than dropped: the
// script has no way to look for it, and an entry it silently skipped would read as a miss.
export function scriptEntries(data) {
  const ids = [];
  const paths = [];
  const anywhere = [];
  for (const f of data.families) {
    for (const i of f.indicators) {
      const v = i.value;
      if (/['|\n]/.test(v) || /['|\n]/.test(f.name)) throw new Error(`indicator value or family name holds a character the script cannot carry: ${f.name}: ${v}`);
      if (i.kind === 'team-id') ids.push(`team|${f.name}|${i.severity}|${v}`);
      else if (i.kind === 'signing-id') ids.push(`signing|${f.name}|${i.severity}|${v}`);
      else if (i.kind === 'plist') {
        for (const dir of ['/Library/LaunchAgents', '/Library/LaunchDaemons', '~/Library/LaunchAgents']) paths.push(`${f.name}|${i.severity}|${dir}/${v}`);
      } else if (i.kind === 'path') {
        if (v.startsWith('**/') && !v.slice(3).includes('**') && v.length > 3) anywhere.push(`${f.name}|${i.severity}|${v}`);
        else if (v.includes('**')) throw new Error(`a path with ** other than at its start cannot be looked for by the script: ${f.name}: ${v}`);
        else paths.push(`${f.name}|${i.severity}|${v}`);
      }
    }
  }
  return { ids, paths, anywhere };
}

/** The block between the markers of lib/indicators.sh, markers included. */
export function renderBlock(data, stamp) {
  const { ids, paths, anywhere } = scriptEntries(data);
  return [
    `${BEGIN} (do not edit this block: it is generated in the Ficus repo, ${SOURCE}, sha256 ${stamp}; edit the source there and run scripts/gen-indicators.mjs)`,
    '# kind|family|severity|value (kind: team = code-signing team ID, signing = signing identifier)',
    `KNOWN_IDS='${ids.join('\n')}'`,
    '# family|severity|path (a leading ~/ is the home folder, * is a glob, a trailing / is a folder)',
    `KNOWN_PATHS='${paths.join('\n')}'`,
    '# family|severity|path published without a folder (it starts with **/, any number of folders; a trailing / is a folder)',
    `KNOWN_ANYWHERE='${anywhere.join('\n')}'`,
    END,
  ].join('\n');
}

/** The text of lib/indicators.sh with its generated block replaced (from the BEGIN marker to the END marker, whatever the marker says). */
export function replaceBlock(script, block) {
  const a = script.indexOf(BEGIN);
  const b = script.indexOf(END);
  if (a < 0 || b < a) throw new Error('lib/indicators.sh has no generated-indicators block between its markers');
  return script.slice(0, a) + block + script.slice(b + END.length);
}

/** Ficus's list of developer tooling folders (src/rules/locations.ts), lower-case, in the order written there. */
export function toolingDirs(source) {
  const m = /const TOOLING_DIRS = new Set\(\[([^\]]*)\]\)/.exec(source);
  if (!m) throw new Error('src/rules/locations.ts no longer has a TOOLING_DIRS set the script can copy');
  return [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
}

/** The text of lib/signatures.sh with its list of tooling folders (the awk `BEGIN { split("...", a, " ")`) replaced. */
export function replaceTooling(script, dirs) {
  const re = /(BEGIN \{ split\(")([^"]+)(", a, " "\))/;
  if (!re.test(script)) throw new Error('lib/signatures.sh has no tooling-folder list the generator can replace');
  return script.replace(re, (_, a, _old, c) => `${a}${dirs.join(' ')}${c}`);
}

/** A target file or marker the generator needs is not there (main prints it and exits 3). */
export class TargetError extends Error {}

/** The three copies, as paths relative to the skill folder. */
export const INDICATORS_FILE = 'lib/indicators.sh';
export const SIGNATURES_FILE = 'lib/signatures.sh';
export const PAGE_FILE = 'references/known-indicators.md';

function readTarget(target, rel) {
  const p = path.join(target, rel);
  if (!fs.existsSync(p)) throw new TargetError(`${rel} is missing in ${target}: this is not an am-i-pwned skill folder of the current layout`);
  return fs.readFileSync(p, 'utf8');
}
function inTarget(rel, fn) {
  try { return fn(); } catch (e) { throw e instanceof TargetError ? e : new TargetError(e.message.startsWith(rel) ? e.message : `${rel}: ${e.message}`); }
}

/** What the copies should hold, from the two sources of truth in this repo, and the current text of each copy. Nothing is written. */
export function build(target) {
  const raw = fs.readFileSync(DATA, 'utf8');
  const data = JSON.parse(raw);
  const stamp = stampOf(raw);
  const dirs = toolingDirs(fs.readFileSync(LOCATIONS, 'utf8'));
  const pagePath = path.join(target, PAGE_FILE);
  const indicatorsNow = readTarget(target, INDICATORS_FILE);
  const signaturesNow = readTarget(target, SIGNATURES_FILE);
  return {
    [INDICATORS_FILE]: { path: path.join(target, INDICATORS_FILE), next: inTarget(INDICATORS_FILE, () => replaceBlock(indicatorsNow, renderBlock(data, stamp))), now: indicatorsNow },
    [SIGNATURES_FILE]: { path: path.join(target, SIGNATURES_FILE), next: inTarget(SIGNATURES_FILE, () => replaceTooling(signaturesNow, dirs)), now: signaturesNow },
    [PAGE_FILE]: { path: pagePath, next: renderPage(data, stamp), now: fs.existsSync(pagePath) ? fs.readFileSync(pagePath, 'utf8') : '' },
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const target = targetDir();
  if (!fs.existsSync(target)) {
    console.error(`no plugin checkout at ${target}. Clone Automattic/claude-code-plugins, or pass --to DIR / set AM_I_PWNED_DIR.`);
    process.exit(2);
  }
  let files;
  try { files = build(target); } catch (e) {
    if (!(e instanceof TargetError)) throw e;
    console.error(`gen-indicators: ${e.message}`);
    process.exit(3);
  }
  const stale = Object.keys(files).filter(k => files[k].next !== files[k].now);
  if (process.argv.includes('--check')) {
    if (stale.length > 0) { console.error(`out of date in ${target}: ${stale.join(', ')}. Run: node scripts/gen-indicators.mjs`); process.exit(1); }
  } else {
    for (const k of stale) fs.writeFileSync(files[k].path, files[k].next);
    console.log(stale.length > 0 ? `updated ${stale.join(', ')} in ${target}\nCommit that change in the claude-code-plugins repo (and bump the plugin version there).` : 'already up to date');
  }
}
