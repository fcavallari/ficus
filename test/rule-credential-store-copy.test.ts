import { describe, expect, test } from 'vitest';
import { COPY_TOOLS, credentialStore } from '../src/rules/credentials';
import { analyze } from '../src/rules/engine';
import type { CaptureModel } from '../src/model/types';
import { apple, capture, img, op, proc } from './synth';

const RULE = 'credential-store-copy';
const hits = (m: CaptureModel) => analyze(m).queue.flatMap(q => q.findings).filter(f => f.ruleId === RULE);

describe('credentialStore', () => {
  test('names the store by basename, with or without a journal suffix, in any letter case', () => {
    expect(credentialStore('/Users/u/Library/Keychains/login.keychain-db')).toBe('login keychain');
    expect(credentialStore('/tmp/LOGIN.KEYCHAIN-DB')).toBe('login keychain');
    expect(credentialStore('/tmp/Login Data')).toBe('browser logins or cookies');
    expect(credentialStore('/tmp/Login Data-journal')).toBe('browser logins or cookies');
    expect(credentialStore('/tmp/Cookies-wal')).toBe('browser logins or cookies');
    expect(credentialStore('/tmp/Cookies.binarycookies')).toBe('browser logins or cookies');
    expect(credentialStore('/tmp/Web Data')).toBe('browser logins or cookies');
    expect(credentialStore('/tmp/Local State')).toBe('browser logins or cookies');
    expect(credentialStore('/tmp/NoteStore.sqlite-shm')).toBe('Notes database');
    expect(credentialStore('/tmp/key4.db')).toBe('Firefox logins');
    expect(credentialStore('/tmp/logins.json')).toBe('Firefox logins');
    expect(credentialStore('/tmp/cookies.sqlite')).toBe('Firefox logins');
    expect(credentialStore('/tmp/keychain-2.db')).toBe('saved Wi-Fi/keychain data');
    expect(credentialStore('/tmp/seed.seco')).toBe('saved Wi-Fi/keychain data');
  });
  test('names a store by the folder it sits in', () => {
    expect(credentialStore('/Library/Keychains/System.keychain')).toBe('saved Wi-Fi/keychain data');
    expect(credentialStore('/Users/u/Library/Keychains/ABCD/anything')).toBe('saved Wi-Fi/keychain data');
    expect(credentialStore('/Users/u/Library/Application Support/Google/Chrome/Default/Local Extension Settings/x/000003.log')).toBe('browser logins or cookies');
  });
  test('leaves other paths alone', () => {
    expect(credentialStore('/Users/u/Documents/notes.txt')).toBeNull();
    expect(credentialStore('/tmp/Login Data.bak')).toBeNull();
    expect(credentialStore('')).toBeNull();
  });
  test('the copy tools are the copiers and readers', () => {
    expect([...COPY_TOOLS].sort()).toEqual(['cat', 'cp', 'ditto', 'rsync', 'scp', 'sqlite3', 'tar', 'zip']);
  });
});

describe('credential-store-copy', () => {
  test('cp of the login keychain into /tmp is high', () => {
    const cp = apple('/bin/cp', ['cp', '/Users/u/Library/Keychains/login.keychain-db', '/tmp/login.keychain-db']);
    const p = proc('200:1', [cp], { fileOps: [op('create', '/tmp/login.keychain-db')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1005', 'T1074.001', 'T1555.001']);
    expect(f[0]!.evidence).toContain('/tmp/login.keychain-db');
  });
  test('cat of a keychain file is med', () => {
    const cat = apple('/bin/cat', ['cat', '/Users/u/Library/Keychains/login.keychain-db']);
    const f = hits(capture([proc('200:1', [cat])]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('med');
    expect(f[0]!.mitre).toEqual(['T1005', 'T1555.001']);
  });
  test('an unsigned writer creating Login Data in a hidden folder is high', () => {
    const w = img({ path: '/Users/u/bin/tool', signingId: null, isPlatform: false });
    const p = proc('200:1', [w], { fileOps: [op('create', '/Users/u/Documents/.k/Login Data')] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
    expect(f[0]!.mitre).toEqual(['T1005', 'T1074.001', 'T1555.003']);
  });
  test('a signed writer creating a credential store in a temporary folder is med', () => {
    const w = img({ path: '/Applications/Some.app/Contents/MacOS/Some', teamId: 'ABCDE12345' });
    const p = proc('200:1', [w], { fileOps: [op('create', '/var/folders/ab/cd/T/Cookies')] });
    expect(hits(capture([p])).map(f => f.severity)).toEqual(['med']);
  });
  test('a rename into a staging place counts through its destination', () => {
    const w = img({ path: '/usr/local/bin/x', signingId: null });
    const p = proc('200:1', [w], { fileOps: [op('rename', '/tmp/.x1', 2, '/Users/Shared/key4.db')] });
    expect(hits(capture([p])).map(f => f.severity)).toEqual(['high']);
  });
  test('a copy tool pointed at a credential store and a staging folder is high; relative paths resolve against cwd', () => {
    const rs = apple('/usr/bin/rsync', ['rsync', 'Login Data', 'out/'], { cwd: '/tmp/work' });
    expect(hits(capture([proc('200:1', [rs])])).map(f => f.severity)).toEqual(['high']);
  });
  test('a copy tool naming a credential store beside a quiet destination stays med', () => {
    const cp = apple('/bin/cp', ['cp', '/Users/u/Library/Keychains/login.keychain-db', '/Users/u/Documents/kc']);
    expect(hits(capture([proc('200:1', [cp])])).map(f => f.severity)).toEqual(['med']);
  });
  test('a copy into a hidden folder buried below a visible one is high', () => {
    const hidden = apple('/bin/cp', ['cp', '/Users/u/Library/Keychains/login.keychain-db', '/Users/u/Documents/.k/kc']);
    expect(hits(capture([proc('200:1', [hidden])])).map(f => f.severity)).toEqual(['high']);
  });
  test('a browser\'s own profile is not flagged', () => {
    const chrome = img({ path: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', signingId: 'com.google.Chrome', teamId: 'EQHXZ8M8AV' });
    const p = proc('200:1', [chrome], {
      fileOps: [op('create', '/Users/u/Library/Application Support/Google/Chrome/Default/Cookies')],
    });
    expect(hits(capture([p]))).toEqual([]);
  });
  // A3: automation drives a browser with a throwaway profile in a temporary folder, and its helpers are often ad-hoc signed.
  const PROFILE = '/var/folders/ab/cd/T/playwright_chromiumdev_profile-x/Default';
  test.each([
    ['chrome-headless-shell', '/Users/u/Library/Caches/ms-playwright/chromium_headless_shell-1169/chrome-headless-shell-mac-arm64/chrome-headless-shell'],
    ['headless_shell', '/Users/u/Library/Caches/ms-playwright/chromium_headless_shell-1169/chrome-mac/headless_shell'],
    ['Google Chrome for Testing', '/Users/u/Library/Caches/ms-playwright/chromium-1169/chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'],
    ['a Chrome helper', '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper'],
    ['Chromium', '/Applications/Chromium.app/Contents/MacOS/Chromium'],
    ['Edge', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'],
    ['Brave', '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'],
    ['Firefox', '/Applications/Firefox.app/Contents/MacOS/firefox'],
    ['firefox on its own', '/opt/homebrew/bin/firefox'],
    ['Arc', '/Applications/Arc.app/Contents/MacOS/Arc'],
    ['Vivaldi', '/Applications/Vivaldi.app/Contents/MacOS/Vivaldi'],
    ['Opera', '/Applications/Opera.app/Contents/MacOS/Opera'],
  ])('an ad-hoc %s writing its own throwaway profile is not flagged', (_, path) => {
    const browser = img({ path, signingId: 'chromium-x', csFlags: 0x2, args: [path] });
    const files = ['Cookies', 'Login Data', 'Web Data', 'Local State'].map(f => op('create', `${PROFILE}/${f}`));
    expect(hits(capture([proc('200:1', [browser], { fileOps: [...files, op('rename', `${PROFILE}/Cookies-new`, 3, `${PROFILE}/Cookies`)] })]))).toEqual([]);
  });
  test('the same temporary profile created by cp, or by an unsigned program that is not a browser, is high', () => {
    const cp = apple('/bin/cp', ['cp', '/Users/u/x', `${PROFILE}/Cookies`]);
    expect(hits(capture([proc('200:1', [cp], { fileOps: [op('create', `${PROFILE}/Cookies`)] })])).map(f => f.severity)).toEqual(['med']);
    const tool = img({ path: '/Users/u/bin/tool', signingId: null, args: ['tool'] });
    expect(hits(capture([proc('200:1', [tool], { fileOps: [op('create', `${PROFILE}/Cookies`)] })])).map(f => f.severity)).toEqual(['high']);
    const lookalike = img({ path: '/Applications/Archive Utility.app/Contents/MacOS/x', signingId: null, args: ['x'] });
    expect(hits(capture([proc('200:1', [lookalike], { fileOps: [op('create', `${PROFILE}/Cookies`)] })])).map(f => f.severity)).toEqual(['high']);
  });
  test('the writer is the image running at the time: a browser that execs a stealer is judged as the stealer', () => {
    const browser = img({ path: '/Applications/Firefox.app/Contents/MacOS/firefox', signingId: 'org.mozilla.firefox', teamId: '43AQ936H96', seq: 1 });
    const stealer = img({ path: '/tmp/stealer', signingId: null, seq: 5, args: ['stealer'] });
    const p = proc('200:1', [browser, stealer], { fileOps: [op('create', '/tmp/early/Cookies', 2), op('create', '/tmp/late/Cookies', 6)] });
    const f = hits(capture([p]));
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain('/tmp/late/Cookies');
    expect(f[0]!.evidence).not.toContain('/tmp/early/Cookies');
  });
  // Known limit: part (a) trusts a writer by where it runs from, so a stealer placed inside a path that looks like a
  // browser bundle is not seen creating a store. Part (b) is about the tool, not the writer, so a copy is still caught.
  test('a stealer inside a Chromium-looking path passes part (a), but a cp of the real store is still flagged', () => {
    const fake = img({ path: '/tmp/x/Chromium.app/Contents/MacOS/x', signingId: null, args: ['x'] });
    expect(hits(capture([proc('200:1', [fake], { fileOps: [op('create', '/tmp/out/Login Data')] })]))).toEqual([]);
    const cp = apple('/bin/cp', ['cp', '/Users/u/Library/Application Support/Google/Chrome/Default/Login Data', '/tmp/out/Login Data']);
    const f = hits(capture([proc('201:1', [cp], { fileOps: [op('create', '/tmp/out/Login Data')] })]));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });
  test('a copy tool run by a browser-named image is still judged on its arguments', () => {
    const cp = apple('/bin/cp', ['cp', '/Users/u/Library/Keychains/login.keychain-db', '/tmp/kc']);
    expect(hits(capture([proc('200:1', [cp], { fileOps: [op('create', '/tmp/kc')] })])).map(f => f.severity)).toEqual(['high']);
  });
  // C: a folder named without a trailing slash is still a place, and a bare Keychains folder is still the keychains.
  test('a folder argument without a trailing slash counts as a staging place', () => {
    const cp = apple('/bin/cp', ['cp', '-r', '/Users/u/Library/Keychains/login.keychain-db', '/Users/u/Documents/.k']);
    expect(hits(capture([proc('200:1', [cp])])).map(f => f.severity)).toEqual(['high']);
    const tmp = apple('/bin/cp', ['cp', '-r', '/Users/u/Library/Keychains/login.keychain-db', '/tmp/stage']);
    expect(hits(capture([proc('201:1', [tmp])])).map(f => f.severity)).toEqual(['high']);
  });
  test('a bare Library/Keychains folder argument names the keychains', () => {
    expect(credentialStore('/Users/u/Library/Keychains')).toBe('saved Wi-Fi/keychain data');
    expect(credentialStore('/Library/Keychains')).toBe('saved Wi-Fi/keychain data');
    const ditto = apple('/usr/bin/ditto', ['ditto', '/Users/u/Library/Keychains', '/Users/u/Documents/.k']);
    const f = hits(capture([proc('200:1', [ditto])]));
    expect(f.map(x => x.severity)).toEqual(['high']);
    expect(f[0]!.mitre).toEqual(['T1005', 'T1074.001', 'T1555.001']);
    expect(credentialStore('/Users/u/Library/KeychainsX')).toBeNull();
    expect(credentialStore('/Users/u/MyLibrary/Keychains')).toBeNull();
  });
  test('a backup volume is not flagged', () => {
    const p = proc('200:1', [img({ path: '/usr/local/bin/bak', signingId: null })], { fileOps: [op('create', '/Volumes/Backup/Login Data')] });
    expect(hits(capture([p]))).toEqual([]);
  });
  test('a dot-folder directly under home is not a staging place', () => {
    const p = proc('200:1', [img({ path: '/usr/local/bin/bak', signingId: null })], { fileOps: [op('create', '/Users/u/.config/Login Data')] });
    expect(hits(capture([p]))).toEqual([]);
  });
  test('credential-store-copy tolerates a capture with missing data', () => {
    const bare = img({ path: null, args: null, signingId: null });
    const p = proc('200:1', [bare]);
    expect(() => analyze(capture([p]))).not.toThrow();
    expect(hits(capture([p]))).toEqual([]);
    const ghost = proc('300:1', [], { ghost: true });
    expect(hits(capture([ghost]))).toEqual([]);
  });
});
