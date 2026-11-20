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

/**
 * Files a developer's tools keep in the home folder and that give access to servers and cloud accounts: SSH private keys,
 * AWS, Kubernetes, Docker and Google Cloud credentials, and the cleartext logins of netrc and git. `home` says whether the
 * file sits where its own tool keeps it (`~/.ssh/id_rsa`): ssh-keygen and `aws configure` write those, so only a copy somewhere
 * else (`~/.docks/.ssh/id_rsa`, `/tmp/x/.aws/credentials`) is a sign of theft. Public keys, `known_hosts` and config files are not credentials.
 */
const HOME_DIR = '(?:/users/[^/]+|/var/root|/root)';
const DEVELOPER_CREDENTIALS: { label: string; any: RegExp; home: RegExp; folder: string | null }[] = [
  { label: 'SSH private key', folder: '/.ssh/', any: /\/\.ssh\/id_[^/]+$/, home: new RegExp(`^${HOME_DIR}/\\.ssh/id_[^/]+$`) },
  { label: 'AWS credentials', folder: '/.aws/', any: /\/\.aws\/credentials$/, home: new RegExp(`^${HOME_DIR}/\\.aws/credentials$`) },
  { label: 'Kubernetes credentials', folder: '/.kube/', any: /\/\.kube\/config$/, home: new RegExp(`^${HOME_DIR}/\\.kube/config$`) },
  { label: 'Docker credentials', folder: '/.docker/', any: /\/\.docker\/config\.json$/, home: new RegExp(`^${HOME_DIR}/\\.docker/config\\.json$`) },
  { label: 'Google Cloud credentials', folder: '/gcloud/', any: /\/gcloud\/(?:credentials\.db|application_default_credentials\.json|access_tokens\.db)$/,
    home: new RegExp(`^${HOME_DIR}/\\.config/gcloud/(?:credentials\\.db|application_default_credentials\\.json|access_tokens\\.db)$`) },
  { label: 'saved passwords (netrc or git)', folder: null, any: /\/\.(?:netrc|git-credentials)$/, home: new RegExp(`^${HOME_DIR}/\\.(?:netrc|git-credentials)$`) },
];
/**
 * `base` is the folder that holds the tool's own folder (`/Users/u/proj` for `/Users/u/proj/.aws/credentials`), so a rule can
 * judge where the copy sits without counting the tool's own hidden folder as a hiding place.
 */
export function developerCredential(path: string): { label: string; home: boolean; base: string } | null {
  const p = normPath(path).toLowerCase();
  if (p.endsWith('.pub')) return null;
  for (const c of DEVELOPER_CREDENTIALS) {
    if (!c.any.test(p)) continue;
    const real = normPath(path);
    const at = c.folder === null ? real.lastIndexOf('/') : real.toLowerCase().lastIndexOf(c.folder);
    let base = at > 0 ? real.slice(0, at) : '';
    if (c.label === 'Google Cloud credentials' && base.toLowerCase().endsWith('/.config')) base = base.slice(0, -'/.config'.length);
    return { label: c.label, home: c.home.test(p), base };
  }
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
