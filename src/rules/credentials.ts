import { basename, normPath } from '../model/util';

/** What a credential store holds, as the learner reads it. */
type StoreLabel = 'login keychain' | 'browser logins or cookies' | 'Notes database' | 'Firefox logins' | 'saved Wi-Fi/keychain data';

/** Files that hold credentials, by lower-case basename (a `-wal`, `-shm` or `-journal` suffix is stripped first). */
const STORE_FILES: Record<string, StoreLabel> = {
  'login.keychain-db': 'login keychain',
  'keychain-2.db': 'saved Wi-Fi/keychain data',
  'seed.seco': 'saved Wi-Fi/keychain data',
  'login data': 'browser logins or cookies',
  'cookies': 'browser logins or cookies',
  'web data': 'browser logins or cookies',
  'local state': 'browser logins or cookies',
  'cookies.binarycookies': 'browser logins or cookies',
  'cookies.sqlite': 'Firefox logins',
  'key4.db': 'Firefox logins',
  'logins.json': 'Firefox logins',
  'notestore.sqlite': 'Notes database',
};
const SQLITE_SIDE_FILE = /-(?:wal|shm|journal)$/;

/** The label of the credential store a path names (a browser's logins or cookies, a keychain, the Notes database), else null. */
export function credentialStore(path: string): string | null {
  const p = normPath(path).toLowerCase();
  const name = basename(p).replace(SQLITE_SIDE_FILE, '');
  if (Object.hasOwn(STORE_FILES, name)) return STORE_FILES[name]!;
  if (p.includes('/library/keychains/') || p.endsWith('/library/keychains')) return basename(p).startsWith('login.keychain') ? 'login keychain' : 'saved Wi-Fi/keychain data';
  if (p.includes('/local extension settings/')) return 'browser logins or cookies';
  return null;
}

/** A browser engine's own program: a Chromium-family or Firefox bundle, or a headless build that ships without one. */
const BROWSER_BUNDLE = /\/(?:(?:Google Chrome|Microsoft Edge|Brave Browser|Firefox|Opera)[^/]*|Chromium|Arc|Vivaldi)\.app\//i;
const BROWSER_PROGRAMS = new Set(['chrome-headless-shell', 'headless_shell', 'firefox']);

/**
 * True when this image is a browser engine writing its own profile: a path inside a Chromium-family or Firefox bundle,
 * or a headless build. Automation drives a throwaway profile in a temporary folder with an ad-hoc signed browser, and
 * the browser is the one program that is meant to write these files. It is judged by path, so a stealer placed inside a
 * path that looks like a browser bundle is a known limit.
 */
export function isBrowserEngine(path: string | null): boolean {
  return path !== null && (BROWSER_BUNDLE.test(path) || BROWSER_PROGRAMS.has(basename(path)));
}

/** Tools that copy, pack or read a file's contents; one of them naming a credential store is how it is staged or read. */
export const COPY_TOOLS: Set<string> = new Set(['cp', 'ditto', 'rsync', 'scp', 'zip', 'tar', 'sqlite3', 'cat']);
