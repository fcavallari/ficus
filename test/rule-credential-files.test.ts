import { describe, expect, test } from 'vitest';
import { developerCredential } from '../src/rules/credentials';
import { analyze } from '../src/rules/engine';
import type { CaptureModel, FileOp, Image } from '../src/model/types';
import { apple, capture, img, op, proc } from './synth';

// SSH keys and cloud credentials: files a developer's tools keep in the home folder. A stealer that copies them is
// credential-store-copy; the tools that make them (ssh-keygen, aws configure) are not.
const RULE = 'credential-store-copy';
const found = (m: CaptureModel) => analyze(m).queue.flatMap(q => q.findings).filter(f => f.ruleId === RULE);

const unsigned = (path: string): Image => img({ path, signingId: null, args: [path], seq: 1 });
const signed = (path: string): Image => img({ path, signingId: 'com.example.tool', teamId: 'ABCDE12345', args: [path], seq: 1 });
const story = (image: Image, fileOps: FileOp[]): CaptureModel => capture([proc('100:1', [image], { fileOps })]);

describe('developerCredential', () => {
  test('names the file and says whether it sits where its own tool keeps it', () => {
    expect(developerCredential('/Users/u/.ssh/id_ed25519')).toMatchObject({ label: 'SSH private key', home: true });
    expect(developerCredential('/Users/u/.ssh/id_rsa')).toMatchObject({ label: 'SSH private key', home: true });
    expect(developerCredential('/Users/u/.aws/credentials')).toMatchObject({ label: 'AWS credentials', home: true });
    expect(developerCredential('/Users/u/.kube/config')).toMatchObject({ label: 'Kubernetes credentials', home: true });
    expect(developerCredential('/Users/u/.docker/config.json')).toMatchObject({ label: 'Docker credentials', home: true });
    expect(developerCredential('/Users/u/.config/gcloud/application_default_credentials.json')).toMatchObject({ label: 'Google Cloud credentials', home: true });
    expect(developerCredential('/Users/u/.config/gcloud/credentials.db')).toMatchObject({ label: 'Google Cloud credentials', home: true });
    expect(developerCredential('/Users/u/.netrc')).toMatchObject({ label: 'saved passwords (netrc or git)', home: true });
    expect(developerCredential('/Users/u/.git-credentials')).toMatchObject({ label: 'saved passwords (netrc or git)', home: true });
    expect(developerCredential('/var/root/.ssh/id_rsa')).toMatchObject({ label: 'SSH private key', home: true });
  });

  test('a copy somewhere else is the same file, not at home', () => {
    expect(developerCredential('/Users/u/.docks/.ssh/id_rsa')).toMatchObject({ label: 'SSH private key', home: false });
    expect(developerCredential('/tmp/x/.aws/credentials')).toMatchObject({ label: 'AWS credentials', home: false });
    expect(developerCredential('/Users/u/proj/.kube/config')).toMatchObject({ label: 'Kubernetes credentials', home: false });
  });

  test('public keys, known_hosts, config and ordinary names are not credentials', () => {
    for (const p of ['/Users/u/.ssh/id_rsa.pub', '/Users/u/.ssh/known_hosts', '/Users/u/.ssh/config', '/Users/u/.ssh/authorized_keys',
      '/Users/u/Documents/id_rsa', '/Users/u/.aws/config', '/Users/u/notes.txt', '']) expect(developerCredential(p), p).toBeNull();
  });

  test('letter case does not matter', () => {
    expect(developerCredential('/Users/u/.SSH/ID_RSA')?.label).toBe('SSH private key');
  });
});

describe('credential-store-copy on SSH keys and cloud credentials', () => {
  test('RustDoor: a home folder cloned into a hidden folder by an unsigned program is high', () => {
    const m = story(unsigned('/Users/u/Downloads/s/localfile'), [
      op('create', '/Users/u/.docks/.ssh/id_rsa'),
      op('create', '/Users/u/.docks/.aws/credentials'),
      op('create', '/Users/u/.docks/Documents/notes.txt'),
    ]);
    const f = found(m);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('/Users/u/.docks/.ssh/id_rsa');
    expect(f[0]!.evidence).toContain('SSH private key');
    expect(f[0]!.evidence).toContain('AWS credentials');
    expect(f[0]!.mitre).toEqual(expect.arrayContaining(['T1005', 'T1552.001', 'T1552.004']));
  });

  test('a copy in a staging place fires even for a signed program (med)', () => {
    const f = found(story(signed('/Applications/Backup.app/Contents/MacOS/Backup'), [op('create', '/tmp/stage/.ssh/id_ed25519')]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('med');
  });

  test('a signed program copying a key to its own project folder is left alone', () => {
    expect(found(story(signed('/usr/local/bin/tool'), [op('create', '/Users/u/proj/.aws/credentials')]))).toHaveLength(0);
  });

  test('the tools that make these files, at home, are left alone, even unsigned', () => {
    expect(found(story(unsigned('/usr/local/bin/aws'), [op('create', '/Users/u/.aws/credentials')]))).toHaveLength(0);
    expect(found(story(unsigned('/usr/local/bin/mytool'), [op('create', '/Users/u/.ssh/id_ed25519'), op('rename', '/Users/u/.ssh/tmp', 3, '/Users/u/.kube/config')]))).toHaveLength(0);
  });

  test('a rename into a hidden copy counts like a create', () => {
    const f = found(story(unsigned('/Users/u/Downloads/s/x'), [op('rename', '/Users/u/.ssh/id_rsa', 2, '/Users/u/.cache2/.ssh/id_rsa')]));
    expect(f).toHaveLength(1);
  });

  test('cp naming a key and a staging place is high; cat of a key alone is left alone', () => {
    const cp = apple('/bin/cp', ['cp', '/Users/u/.ssh/id_rsa', '/tmp/loot/'], { cwd: '/Users/u' });
    const f = found(capture([proc('100:1', [cp])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.evidence).toContain('SSH private key');
    const cat = apple('/bin/cat', ['cat', '/Users/u/.aws/credentials'], { cwd: '/Users/u' });
    expect(found(capture([proc('100:1', [cat])]))).toHaveLength(0);
    const cp2 = apple('/bin/cp', ['cp', '/Users/u/.ssh/id_rsa', '/Users/u/Backups/'], { cwd: '/Users/u' });
    expect(found(capture([proc('100:1', [cp2])]))).toHaveLength(0);
  });

  test('existing stores still fire as before', () => {
    const f = found(story(unsigned('/Users/u/Downloads/s/x'), [op('create', '/tmp/stage/Login Data')]));
    expect(f).toHaveLength(1);
  });
});

describe('a forked child that never ran a program of its own', () => {
  test('is judged as its parent\'s program: an unsigned parent\'s fork cloning a home folder is high', () => {
    // RustDoor did its copying in a fork that never exec'd, so its only image is the inherited copy.
    const child = proc('200:1', [{ ...unsigned('/Users/u/Downloads/s/localfile'), inherited: true }], {
      fileOps: [op('create', '/Users/u/.docks/.ssh/id_rsa')],
    });
    const f = found(capture([child]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });
});
