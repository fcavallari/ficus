import type { CaptureModel, Image, PersistenceItem, ProcId, Process } from '../model/types';
import { basename, imageAt, normPath, timeMs } from '../model/util';
import {
  CURL_SPEC, hasOpt, hasShortFlag, looksLikeUrl, optValues, osascriptArgs, parseOpts, PIPE_LANGS, readsStdin,
  SECURITY_FIND_SPEC, securityArgs, stagingPlace, tarCreates, WGET_SPEC, type PipeLang,
} from './args';
import { PASTE_WINDOW_MS, agentRuntime, originalParentImage, siblings, sourcesAgentSnapshot, underAgentShell } from './context';
import { COPY_TOOLS, credentialStore, isBrowserEngine } from './credentials';
import { fileLedger } from './ledger';
import { HOME, LOCATION_WORDS, hiddenName, inBuildDir, oddLocation, resolvePath, strongPlace, type LocationKind, type OddLocation } from './locations';

export type Severity = 'high' | 'med' | 'low';
export const SEVERITY_RANK: Record<Severity, number> = { high: 3, med: 2, low: 1 };
export interface RuleCtx { m: CaptureModel; p: Process; img: Image; imgIndex: number }
/** What a match reports. `mitre`, `title` and `explanation` override the rule's own for this finding. */
export interface MatchResult { evidence: string; severity?: Severity; mitre?: string[]; title?: string; explanation?: string }
export interface Rule {
  id: string; title: string; severity: Severity; explanation: string;
  /** Every MITRE ID the rule can cite; a finding cites the subset its trigger fits. Empty only for a trait rule. */
  mitre: string[];
  /** A trait of the binary (unsigned, ad-hoc) rather than a technique: it cites no MITRE ID. */
  trait?: boolean;
  /** Context-only unless the process is in a flagged chain (or a recon burst): always, or only for low findings. */
  gated?: 'always' | 'when-low';
  /** 'image' runs on every exec'd image; 'process' once per captured process, exec'd or fork-only; 'persistence' per launch item. */
  scope: 'image' | 'process' | 'persistence';
  match?(ctx: RuleCtx): MatchResult | null;                                  // scope 'image'
  matchProcess?(p: Process, m: CaptureModel): MatchResult | null;          // scope 'process'
  matchItem?(item: PersistenceItem, m: CaptureModel): MatchResult | null;  // scope 'persistence'
}

export const SHELLS: Set<string> = new Set([
  '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/dash', '/bin/ksh', '/bin/csh', '/bin/tcsh',
]);
const SHELL_NAMES = new Set([...SHELLS].map(basename));
/** Script interpreters, versioned names included (python3.11, perl5.30). */
const INTERPRETER = /^(?:python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|osascript|node|php)$/;

const MAX_EVIDENCE = 300;

export function cmdline(img: Image): string {
  const s = img.args && img.args.length > 0 ? img.args.join(' ') : (img.path ?? '');
  return s.length > MAX_EVIDENCE ? `${s.slice(0, MAX_EVIDENCE)}…` : s;
}

function rest(img: Image): string[] {
  return img.args?.slice(1) ?? [];
}

export const isAdhoc = (img: Image): boolean => (img.csFlags & 0x2) !== 0;
/** No signature at all; an empty signing ID counts as none. */
export const isUnsigned = (img: Image): boolean => !img.isPlatform && !img.signingId;

// ---------------------------------------------------------------------------------------------------------------
// Credential stores

/** Where a credential store is staged: a normal install never keeps one in these places. A volume is a backup. */
const STAGING_KINDS: ReadonlySet<LocationKind> = new Set<LocationKind>(['temp', 'shared', 'downloads', 'hidden']);
const CREDENTIAL_MITRE: Record<string, string> = {
  'login keychain': 'T1555.001', 'saved Wi-Fi/keychain data': 'T1555.001',
  'browser logins or cookies': 'T1555.003', 'Firefox logins': 'T1555.003',
};
const CREDENTIAL_COPY_EXPLANATION = 'Copied, packed or read a file that holds credentials: a browser\'s saved logins or cookies, a keychain, or the Notes database. Stealers stage these files in a temporary, shared, Downloads or hidden folder before uploading them, and the tools that do it (cp, ditto, rsync, scp, zip, tar, sqlite3, cat) are ordinary ones. Backup tools and Migration Assistant copy the same files for legitimate reasons, so check what ran it and where the copy went. A browser engine writing its own profile (browser automation does this in a temporary folder) is ignored. High when the program is unsigned, ad-hoc signed or runs from an odd place, or when a copy tool also names a staging place.';

/** The path an argument names: `--file=/x` is `/x`, an option alone names nothing. */
function pathArgument(a: string): string | null {
  if (!a.startsWith('-')) return a;
  return a.startsWith('--') && a.includes('=') ? a.slice(a.indexOf('=') + 1) : null;
}

/** True when the path, or the folder it names, is in a strong place (a copy into `/tmp` or a hidden folder counts). */
function inStrongPlace(path: string): boolean {
  const dir = path.replace(/\/+$/, '');
  return oddLocation(path)?.strength === 'strong' || strongPlace(normPath(`${dir}/`)) !== null || oddLocation(`${dir}/x`)?.strength === 'strong';
}

/** The writer's judgment: unsigned, ad-hoc signed, or run from a strong odd place. */
function writerIsOdd(p: Process): boolean {
  const last = [...p.images].reverse().find(i => !i.inherited);
  if (!last) return false;
  return isUnsigned(last) || isAdhoc(last) || (last.path !== null && oddLocation(last.path)?.strength === 'strong');
}

/**
 * Team IDs Apple signs its non-platform apps with. 59GAB85EFG is Apple's developer-tools team (unverified here: no
 * Xcode on the machine it was checked on); the others were read with `codesign -dv` from Mac App Store apps: iWork
 * (Keynote, Numbers, Pages), GarageBand and iMovie. Apple uses more than one team, so this is a list to extend.
 */
const APPLE_TEAM_IDS: ReadonlySet<string> = new Set(['59GAB85EFG', '74J34U3R6X', 'F3LWYJ7GM7', 'PTN9T2S29T']);
const claimsApple = (img: Image): boolean => img.signingId !== null && img.signingId.toLowerCase().startsWith('com.apple.');

/**
 * Apple's own code: a platform binary, or a `com.apple.*` signing ID with a real (not ad-hoc) signature from one of
 * Apple's team IDs, or with no team ID at all and a path only Apple writes to. A signing ID is the signer's own choice,
 * and a self-signed certificate carries no team ID, so neither the name nor a missing team ID proves anything on its
 * own: under another team's certificate, or from /tmp, it is a spoof.
 */
function isAppleSigned(img: Image): boolean {
  if (img.isPlatform) return true;
  if (!claimsApple(img) || isAdhoc(img)) return false;
  if (img.teamId) return APPLE_TEAM_IDS.has(img.teamId);
  return img.path !== null && appleProgramPath(img.path, true);
}

const APPLE_MASQUERADE_EXPLANATION = 'Code wearing an Apple name it does not have. Two forms: a program that signed itself with a `com.apple.…` signing ID without being Apple\'s (Apple\'s own code is platform-signed or carries one of Apple\'s team IDs, and anyone can pick a signing ID, ad-hoc, self-signed with no team ID, or under a Developer ID certificate), or a program that is not Apple\'s writing a launch plist labelled `com.apple.…`, so the persistence looks like part of macOS. High in a user\'s `~/Library/LaunchAgents` or when the writer is unsigned or ad-hoc signed; med otherwise. Apple\'s installers and updaters write such plists legitimately, which is why a platform binary or a genuine Apple signature is never flagged.';

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

/**
 * Apple tools that are setuid or setgid by design, by signing ID (checked with find -perm and codesign, plus two seen in
 * captures). com.apple.sudo and com.apple.security_authtrampoline were not verified with codesign: reading their
 * signatures needs root.
 */
export const SETUID_ALLOW: Set<string> = new Set([
  'com.apple.ps', 'com.apple.top', 'com.apple.write', 'com.apple.atrm', 'com.apple.batch', 'com.apple.crontab',
  'com.apple.newgrp', 'com.apple.su', 'com.apple.sudo', 'com.apple.quota', 'com.apple.login', 'com.apple.traceroute',
  'com.apple.traceroute6', 'com.apple.postqueue', 'com.apple.postdrop', 'com.apple.authopen',
  'com.apple.security_authtrampoline', 'com.apple.RemoteDesktopAgent', 'com.apple.loginwindow',
]);

/**
 * What one mismatch means. Root running with a user's effective id gave privileges up rather than borrowing them
 * (loginwindow, or a vendor daemon acting for the console user): it can take them back, but that is not a climb. The
 * uid pair decides when it differs; the gid pair only when the uids match. A process whose real and effective user is
 * root already holds every privilege, so a different effective group gives it nothing new.
 */
type MismatchKind = 'escalation' | 'uid-drop' | 'gid-drop' | 'root-group';
function mismatchKind(c: { ruid: number; euid: number; rgid: number; egid: number }): MismatchKind {
  if (c.euid !== c.ruid) return c.ruid === 0 ? 'uid-drop' : 'escalation';
  if (c.rgid === 0 && c.egid !== 0) return 'gid-drop';
  return c.ruid === 0 ? 'root-group' : 'escalation';
}
const PRIVILEGE_DROP = 'Running as root with a user\'s effective id: it dropped its privileges and can take them back. Common for system and vendor daemons acting for the logged-in user; context, not escalation.';
const GROUP_DROP = 'Its real group is wheel (gid 0) but its effective group is another one: it dropped its group privileges and can take them back. Context, not escalation.';
const UID_MISMATCH_EXPLANATION = 'Its effective user or group id differs from its real one, so the process holds the privileges of another account. That is what a setuid or setgid binary does, or a process that called setuid(). Apple ships a few setuid tools (ps, sudo, su, crontab and others), so those are expected; the same behaviour from anything else is a way to climb to root.';
const MIXED_NOTE = 'Entries marked drop or root group are not climbs: root giving its privileges up, or root running with another group, is context. The grade comes from the others.';
const KIND_MARK: Record<MismatchKind, string> = { escalation: '', 'uid-drop': 'drop', 'gid-drop': 'drop', 'root-group': 'root group' };
const ROOT_GROUP = 'Its real and effective user is root, so it already holds every privilege; a different effective group gives it nothing new. Context, not escalation.';

// ---------------------------------------------------------------------------------------------------------------
// Recon and security settings

/** Discovery tools, each with the technique it fits and what it finds out. */
const RECON_KINDS = {
  process: { mitre: 'T1057', what: 'Lists the running processes.' },
  network: { mitre: 'T1016', what: 'Reads the network configuration (interfaces, DNS, proxies).' },
  wifi: { mitre: 'T1016.002', what: 'Reads Wi-Fi information (the current network, or nearby ones).' },
  security: { mitre: 'T1518.001', what: 'Checks the security settings (System Integrity Protection, Gatekeeper).' },
  user: { mitre: 'T1033', what: 'Finds out which user it is running as.' },
  system: { mitre: 'T1082', what: 'Gathers information about the machine (hardware, macOS version, name).' },
} as const;
type ReconKind = keyof typeof RECON_KINDS;
export const RECON_TOOLS: Map<string, ReconKind> = new Map<string, ReconKind>([
  ['ps', 'process'], ['networksetup', 'network'], ['scutil', 'network'], ['airport', 'wifi'],
  ['csrutil', 'security'], ['spctl', 'security'], ['whoami', 'user'], ['id', 'user'],
  ['system_profiler', 'system'], ['sw_vers', 'system'], ['sysctl', 'system'], ['ioreg', 'system'], ['uname', 'system'], ['hostname', 'system'],
]);
const RECON_TAIL = ' Attackers do this to size up a machine, but so does plenty of normal software, so on its own it is only context.';

const SPCTL_DISABLE = ['--master-disable', '--global-disable', '--disable'];
/** spctl options that change Gatekeeper rather than read it. */
const SPCTL_WRITES = [...SPCTL_DISABLE, '--add', '--remove', '--enable', '--master-enable', '--global-enable', '--reset-default'];
const NETWORK_REDIRECTS: Record<string, string> = {
  '-setwebproxy': 'web proxy', '-setsecurewebproxy': 'secure web proxy', '-setautoproxyurl': 'automatic proxy URL',
  '-setsocksfirewallproxy': 'SOCKS proxy', '-setdnsservers': 'DNS servers',
};
/** csrutil subcommands that change SIP rather than report it. */
const CSRUTIL_WRITES = ['disable', 'enable', 'clear', 'add', 'remove'];
/** networksetup switches that turn a proxy on or off: `-setwebproxystate <service> on`. */
const PROXY_SWITCHES = ['-setwebproxystate', '-setsecurewebproxystate', '-setautoproxystate', '-setproxyautodiscovery', '-setsocksfirewallproxystate'];
/** networksetup options that change the configuration rather than read it. */
const NETWORKSETUP_WRITE = /^-(?:set|create|delete|remove|add|order|switch|import|detect)/i;

/** add-trusted-cert options that take a value; -d (admin) and the like do not. */
const TRUSTED_CERT_SPEC = { shortValues: 'rpaseuktio', longValues: [] };

/** spctl options that name a rule, and options whose value is not a rule (`--type execute`). */
const SPCTL_NAMING = ['--label', '--rule', '--path', '--hash', '--anchor', '--requirement'];
const SPCTL_VALUES = ['--type', '-t', '--context', '--priority'];
function spctlNamesRule(a: string[]): boolean {
  for (let i = 0; i < a.length; i++) {
    const x = a[i]!;
    if (SPCTL_NAMING.some(o => x === o || x.startsWith(`${o}=`))) return true;
    if (SPCTL_VALUES.includes(x)) { i++; continue; }
    if (!x.startsWith('-')) return true;                                 // a path to the app or file
  }
  return false;
}

const MACOS15 = 'From macOS 15, spctl no longer supports changing the rule database or the global state, so there it is only an attempt.';

/** A command that weakens a macOS protection or redirects traffic, with what it tried to do. */
function settingChange(n: string, a: string[], cmd: string): MatchResult | null {
  if (n === 'spctl') {
    const off = a.find(x => SPCTL_DISABLE.includes(x));
    if (off === '--global-disable' || off === '--master-disable') {
      return { evidence: cmd, severity: 'high', mitre: ['T1562.001'], title: 'Tried to turn Gatekeeper off',
        explanation: `Ran \`spctl ${off}\`, which asks macOS to turn Gatekeeper off. On macOS 14 and earlier (as root) this disables it; from macOS 15 it only reveals the "Allow applications from Anywhere" option in Privacy & Security, which someone must still pick.` };
    }
    if (off === '--disable') {
      // A rule named by --label, --rule, --path, --hash, --anchor, --requirement or a bare path. Which way that moves
      // Gatekeeper (an allow rule off is stricter, a deny rule off is looser) can't be told from the arguments, so med.
      const named = spctlNamesRule(a);
      return named
        ? { evidence: cmd, severity: 'med', mitre: ['T1562.001'], title: 'Tried to change a Gatekeeper rule',
          explanation: `Ran \`spctl --disable\` on a named Gatekeeper rule. Disabling a rule that allows software makes Gatekeeper stricter; disabling one that blocks software lets it through. Check which rule it named. ${MACOS15}` }
        : { evidence: cmd, severity: 'high', mitre: ['T1562.001'], title: 'Tried to disable Gatekeeper rules',
          explanation: `Ran \`spctl --disable\` with no rule named, which tries to disable Gatekeeper's assessment rules; on older macOS (as root) this may have stopped the checks. ${MACOS15}` };
    }
    if (a.includes('--add')) {
      return { evidence: cmd, severity: 'high', mitre: ['T1553.001'], title: 'Tried to add a Gatekeeper exception',
        explanation: `Ran \`spctl --add\`, which tries to add a Gatekeeper rule so the named app passes without the usual check. On older macOS (as root) this works. ${MACOS15}` };
    }
    return null;
  }
  if (n === 'csrutil' && a.includes('enable') && a.includes('--without')) {
    return { evidence: cmd, severity: 'high', mitre: ['T1562.001'], title: 'Tried to turn off part of System Integrity Protection',
      explanation: 'Ran `csrutil enable --without …`, which leaves System Integrity Protection on but turns off the protections it names. It only works from Recovery; seeing it on a normal boot means an attempt.' };
  }
  if (n === 'csrutil' && a.includes('disable')) {
    const root = a.includes('authenticated-root');
    return { evidence: cmd, severity: 'high', mitre: ['T1562.001'],
      title: root ? 'Tried to turn off the sealed system volume check' : 'Tried to turn off System Integrity Protection',
      explanation: `Ran \`${root ? 'csrutil authenticated-root disable' : 'csrutil disable'}\`, which turns off ${root ? 'the check that the system volume is Apple\'s sealed original' : 'System Integrity Protection'}. It only works from Recovery; seeing it on a normal boot means an attempt.` };
  }
  if (n === 'security') {
    const s = securityArgs(a);
    if (s?.sub === 'add-trusted-cert') {
      // -r sets the trust result; with none given it is trustRoot (`security add-trusted-cert -h`).
      const results = parseOpts(s.rest, TRUSTED_CERT_SPEC).shorts.filter(o => o.opt === 'r').map(o => o.value ?? '');
      const admin = hasShortFlag(s.rest, 'd') ? ', in the admin trust settings (every user)' : '';
      const hedge = ' Changing trust settings needs an administrator\'s interactive approval on current macOS, so this may only be an attempt.';
      if (results.length > 0 && results.every(r => r === 'deny' || r === 'unspecified')) {
        return { evidence: cmd, severity: 'med', mitre: ['T1553'], title: 'Tried to change a certificate\'s trust settings',
          explanation: `Ran \`security add-trusted-cert -r ${results.join('/')}\`, which sets a certificate's trust to ${results.join(' or ')}${admin} rather than trusting it.${hedge}` };
      }
      return { evidence: cmd, severity: 'high', mitre: ['T1553.004'], title: 'Tried to trust a certificate',
        explanation: `Ran \`security add-trusted-cert\`, which marks a certificate as a trusted root${admin}. A trusted root lets whoever holds its key intercept HTTPS traffic or sign things the Mac will accept.${hedge}` };
    }
    if (s?.sub === 'authorizationdb' && s.rest[0] === 'write') {
      return { evidence: cmd, severity: 'med', mitre: ['T1548'], title: 'Tried to change an authorization rule',
        explanation: 'Ran `security authorizationdb write`, which changes an authorization rule: who may do what, and whether a password is asked for. Malware loosens these rules to get admin rights without asking. Writing the rules needs admin rights, so this may only be an attempt.' };
    }
    return null;
  }
  if (n === 'networksetup') {
    const flag = a.find(x => Object.hasOwn(NETWORK_REDIRECTS, x.toLowerCase()));
    if (flag !== undefined) {
      const values = a.slice(a.indexOf(flag) + 2);
      // `-setdnsservers <service> Empty` clears the list: nothing is redirected.
      if (flag.toLowerCase() === '-setdnsservers' && values.length > 0 && values.every(v => /^empty$/i.test(v))) return null;
      return { evidence: cmd, severity: 'med', mitre: ['T1557'], title: 'Web proxy or DNS changed',
        explanation: `Changed the ${NETWORK_REDIRECTS[flag.toLowerCase()]} with \`networksetup ${flag}\`, which redirects web or DNS traffic through a server someone chose. A common adware trick.` };
    }
    // `-setwebproxystate <service> on|off`: the value is the argument after the service name.
    const sw = a.find(x => PROXY_SWITCHES.includes(x.toLowerCase()));
    if (sw !== undefined && /^on$/i.test(a[a.indexOf(sw) + 2] ?? '')) {
      return { evidence: cmd, severity: 'med', mitre: ['T1557'], title: 'Proxy setting turned on',
        explanation: sw.toLowerCase() === '-setproxyautodiscovery'
          ? 'Turned a proxy setting on with `networksetup -setproxyautodiscovery … on`: web traffic then uses whatever proxy the network advertises (WPAD), which an attacker on the network can set.'
          : `Turned a proxy setting on with \`networksetup ${sw} … on\`, so web traffic goes through whatever proxy is configured. A common adware trick.` };
    }
  }
  return null;
}

/** What a recon tool finds out with these arguments, or null when the arguments make it a change, not a read. */
function reconKind(img: Image): ReconKind | null {
  const n = basename(img.path);
  const kind = RECON_TOOLS.get(n);
  if (kind === undefined) return null;
  const a = rest(img);
  if (n === 'spctl' && a.some(x => SPCTL_WRITES.includes(x))) return null;
  if (n === 'networksetup' && a.some(x => NETWORKSETUP_WRITE.test(x))) return null;
  if (n === 'sysctl' && (hasShortFlag(a, 'w') || a.some(x => x.includes('=')))) return null;
  if (n === 'csrutil' && a.some(x => CSRUTIL_WRITES.includes(x))) return null;
  if (n === 'scutil') {
    if (a.includes('--set')) return null;
    if (a.includes('--get')) return 'system';
  }
  return kind;
}

// ---------------------------------------------------------------------------------------------------------------
// Keychain

/** Browser "Safe Storage" keychain entries (service "Chrome Safe Storage", account "Chrome", …): they decrypt saved logins and cookies. */
const SAFE_STORAGE = /safe storage$/i;
const BROWSER_ACCOUNT = /^(?:google )?(?:chrome|chromium|brave|microsoft edge|edge|opera|vivaldi|arc)(?: browser)?$/i;
/** Crypto wallet apps, by whole name. */
const WALLET = /\b(?:exodus|electrum|metamask|ledger live|atomic wallet|coinomi)\b/i;

function keychainFinding(args: string[]): MatchResult | null {
  const s = securityArgs(args);
  if (s === null) return null;
  const cmd = `security ${s.sub}`;
  if (s.sub === 'find-generic-password' || s.sub === 'find-internet-password') {
    const o = parseOpts(s.rest, SECURITY_FIND_SPEC);
    const prints = hasOpt(o, 'g') || hasOpt(o, 'w');
    if (!prints) {
      return { evidence: '', severity: 'low',
        explanation: `Looked up a keychain item's attributes, not its secret, with \`${cmd}\` (no -g or -w). On its own this is only context.` };
    }
    const vals = (letter: string) => optValues(o, letter, []).filter((v): v is string => !!v);
    const services = vals('s');
    const names = [...services, ...vals('a'), ...vals('l')];
    // A browser name as the account counts only when no other service is named: `-s mysvc -a Edge` is someone else's item.
    const safeService = services.some(v => SAFE_STORAGE.test(v));
    const browser = safeService || vals('l').some(v => SAFE_STORAGE.test(v))
      || ((services.length === 0 || safeService) && vals('a').some(v => BROWSER_ACCOUNT.test(v)));
    if (browser) {
      return { evidence: '', severity: 'high',
        explanation: safeService || vals('l').some(v => SAFE_STORAGE.test(v))
          ? `Printed an app's Safe Storage encryption key with \`${cmd}\` (Chromium-based browsers and Electron apps keep their saved passwords and cookies behind it). Stealers grab these keys first.`
          : `Printed a browser's Safe Storage key with \`${cmd}\` (the browser named as the account). That key decrypts the browser's saved passwords and cookies; stealers grab it first.` };
    }
    if (names.some(v => WALLET.test(v))) {
      return { evidence: '', severity: 'high',
        explanation: `Printed a crypto wallet's keychain entry with \`${cmd}\`. Stealers go after wallet passwords to empty the wallet.` };
    }
    return { evidence: '', severity: 'med',
      explanation: `Ran \`${cmd}\` with -g or -w, which prints a saved password. Tools such as gh and git credential helpers do this too; check which item it asked for.` };
  }
  if (s.sub === 'dump-keychain') {
    return hasShortFlag(s.rest, 'd')
      ? { evidence: '', severity: 'high', explanation: 'Ran `security dump-keychain -d`, which prints every item in a keychain together with its secret.' }
      : { evidence: '', severity: 'low', explanation: 'Listed the items in a keychain with `security dump-keychain`: names and attributes only (with -d it would include the secrets). On its own this is only context.' };
  }
  if (s.sub === 'unlock-keychain') {
    return { evidence: '', severity: 'low', explanation: 'Unlocked a keychain with `security unlock-keychain`, so its items can be read. On its own this is only context.' };
  }
  if (s.sub === 'export') {
    return { evidence: '', severity: 'low', explanation: 'Exported keys or certificates out of a keychain with `security export`. On its own this is only context.' };
  }
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Odd locations (program and script)

/** "Ran a program from a temporary folder, …": the explanation of an odd-location-exec finding, from what triggered it. */
function oddLocationExplanation(hits: { what: 'program' | 'script'; where: OddLocation }[]): string {
  const parts = hits.map(h => `${h.what} from ${LOCATION_WORDS[h.where.kind].long}`);
  const weakOnly = hits.every(h => h.where.strength === 'weak');
  return `Ran a ${parts.join(', and a ')}, not from /Applications or a system folder.`
    + (weakOnly ? ' On its own this is a weak signal.' : ' Malware is commonly run from places like this.');
}

// ---------------------------------------------------------------------------------------------------------------
// Persistence

const LAUNCH_DIR = /^(?:\/Users\/[^/]+\/Library\/LaunchAgents|\/Library\/Launch(?:Agents|Daemons))\/[^/]+\.plist$/i;
/** A launch plist labelled as Apple's (`com.apple.…`, hidden or not) in a place only third parties write to. */
export const APPLE_LABEL_PLIST = /^(?:\/Users\/[^/]+\/Library\/LaunchAgents|\/Library\/Launch(?:Agents|Daemons))\/\.?com\.apple\.[^/]+\.plist$/i;
/** Where Apple's own programs live. /usr/local is not Apple's: it is where third-party tools install. The volume ignores letter case. */
const APPLE_PROGRAM_DIRS = /^\/(?:System|usr(?!\/local\/)|bin|sbin|Library\/Apple)\//i;
/** Where Apple's developer tools live: the Command Line Tools and Xcode ship tools that carry no team ID of their own. */
const APPLE_TOOL_DIRS = /^\/(?:Library\/Developer|Applications\/Xcode[^/]*\.app)\//i;
const DOT_SEGMENT = /(?:^|\/)\.{1,2}(?:\/|$)/;

/** True when the path is somewhere only Apple's own programs live. A path with a `.` or `..` segment is never trusted: it can lead anywhere. */
function appleProgramPath(path: string, withDeveloperTools = false): boolean {
  const n = normPath(path);
  if (DOT_SEGMENT.test(n)) return false;
  return APPLE_PROGRAM_DIRS.test(n) || (withDeveloperTools && APPLE_TOOL_DIRS.test(n));
}
const DAEMON_DIR = /^\/Library\/LaunchDaemons\//i;
const ALL_USERS_AGENT_DIR = /^\/Library\/LaunchAgents\//i;
const USER_AGENT_DIR = /^\/Users\/[^/]+\/Library\/LaunchAgents\//i;
/** Platform tools that write whatever they are told to: copiers, shells, interpreters and a downloader. */
const GENERAL_TOOL = /^(?:cp|mv|ditto|tee|cat|curl|sh|bash|zsh|dash|ksh|csh|tcsh|osascript|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*)$/;

type LaunchKind = 'agent' | 'daemon' | 'login' | 'app' | 'user' | null;
/** The kind of launch item, from the btm item type (0 user item, 1 app, 2 login item, 3 agent, 4 daemon) or its plist directory. */
function launchKind(itemType: number | null, plistPath: string | null): LaunchKind {
  const byType: LaunchKind[] = ['user', 'app', 'login', 'agent', 'daemon'];
  if (itemType !== null && byType[itemType] !== undefined) return byType[itemType]!;
  if (plistPath === null) return null;
  const n = normPath(plistPath);
  return DAEMON_DIR.test(n) ? 'daemon' : ALL_USERS_AGENT_DIR.test(n) || USER_AGENT_DIR.test(n) ? 'agent' : null;
}
const LAUNCH_MITRE: Record<NonNullable<LaunchKind>, string> = {
  agent: 'T1543.001', daemon: 'T1543.004', login: 'T1547.015', app: 'T1547.015', user: 'T1547.015',
};
const launchMitre = (k: LaunchKind): string[] => (k === null ? ['T1543.001', 'T1543.004'] : [LAUNCH_MITRE[k]]);
const LAUNCH_TITLE: Record<NonNullable<LaunchKind>, string> = {
  agent: 'Launch agent registered', daemon: 'Launch daemon registered', login: 'Login item registered',
  app: 'App registered to open at login', user: 'Login item registered (user item)',
};
/** When launchd actually starts the program: whatever the plist asks for. */
const TRIGGERS = 'and starts the program it names when the plist says: at load (RunAtLoad), to keep it running (KeepAlive), on a schedule (StartInterval, StartCalendarInterval) or when files change (WatchPaths), for example';
/** Where launchd loads an agent or daemon plist from this place: "…loads it <when> …". */
function launchdStarts(kind: 'agent' | 'daemon', plistPath: string | null): { scope: string; when: string } {
  if (kind === 'daemon') return { scope: '', when: 'at boot, usually to run as root,' };
  const n = plistPath !== null ? normPath(plistPath) : '';
  if (ALL_USERS_AGENT_DIR.test(n)) return { scope: ' for every user', when: 'whenever anyone logs in' };
  if (USER_AGENT_DIR.test(n)) return { scope: ' for this user', when: 'each time this user logs in' };
  return { scope: '', when: 'at login' };
}
function launchExplanation(kind: NonNullable<LaunchKind>, plistPath: string | null): string {
  if (kind === 'agent' || kind === 'daemon') {
    const { scope, when } = launchdStarts(kind, plistPath);
    return `Registered a launch ${kind}${scope}: launchd loads it ${when} ${TRIGGERS}.`;
  }
  return {
    login: 'Registered a login item: macOS opens it each time this user logs in.',
    app: 'Registered an app to open each time this user logs in.',
    user: 'Added a login item to the user\'s list: macOS opens it each time this user logs in.',
  }[kind];
}

/** Where a launch item's program sits, worded for persistence: why that place makes it worse. */
const PERSIST_WORDS: Record<LocationKind, string> = {
  translocated: 'inside a translocated app (a quarantined download macOS ran from a random read-only copy)',
  temp: 'in /tmp or /var/tmp, which every user and process can write to',
  shared: 'in /Users/Shared, which every user can write to',
  downloads: 'in the Downloads folder, which the user can write to',
  volume: 'on a mounted disk image or external volume, which can be swapped or disappear',
  hidden: 'in a hidden folder in the home folder, which the user can write to',
  'home-dot': 'in a dot-folder in the home folder, which the user can write to',
  tooling: 'inside a project build or tooling folder in the home folder, which the user can write to',
  'go-build': 'in a Go build folder in the per-user temporary area, which the user (or anything running as them) can write to',
};

const APP_BUNDLE_EXE = /\.app\/Contents\/MacOS\/[^/]+$/i;
const HOME_CACHES = /^\/Users\/[^/]+\/Library\/Caches\//i;

/**
 * What a launch item runs, as an absolute path. The event's executable path is optional, and its item URL may be the app
 * itself (a login item) or relative to the app URL; so: an absolute executable, else the executable joined to the app,
 * else the app bundle. null when nothing can be placed.
 */
export function launchTarget(item: PersistenceItem): { path: string; isApp: boolean } | null {
  const exe = item.executablePath !== null && item.executablePath !== '' ? item.executablePath : null;
  const app = item.appPath !== null && item.appPath.startsWith('/') ? trimSlash(item.appPath) : null;
  if (exe !== null && exe.startsWith('/')) return { path: exe, isApp: false };
  if (exe !== null) return app !== null ? { path: resolvePath(exe, app), isApp: false } : null;
  return app !== null ? { path: app, isApp: true } : null;
}

/** True when a captured Apple-signed image sits at the launch target (an app target: anywhere inside the bundle). */
function appleSignedAt(m: CaptureModel, target: { path: string; isApp: boolean }): boolean {
  const key = normPath(target.path).toLowerCase();
  return [...m.processes.values()].some(q => q.images.some(i => {
    if (!isAppleSigned(i) || i.path === null) return false;
    const ip = normPath(i.path).toLowerCase();
    return target.isApp ? ip.startsWith(`${key}/`) : ip === key;
  }));
}

/**
 * How bad a launch item is, from what it runs. High when it runs a shell or interpreter, sits anywhere a user process
 * can write (temporary folders, /Users/Shared, Downloads, ~/Library/Caches, hidden folders, or a loose program anywhere
 * in a home folder), or ran unsigned or ad-hoc signed in this capture. An app bundle in a home folder that was not seen
 * unsigned (a per-user updater such as GoogleUpdater) stays med, as does everything else.
 */
function persistenceSeverity(target: { path: string; isApp: boolean } | null, m: CaptureModel): { severity: Severity; reason: string } {
  if (target === null) return { severity: 'med', reason: 'the event names no program it can place' };
  const what = target.isApp ? 'the app' : 'the program';
  const n = basename(target.path);
  if (!target.isApp && SHELL_NAMES.has(n)) return { severity: 'high', reason: `it runs a shell (${n})` };
  if (!target.isApp && INTERPRETER.test(n)) return { severity: 'high', reason: `it runs a script interpreter (${n})` };
  const p = normPath(target.path);
  const where = oddLocation(target.isApp ? `${p}/` : p);
  if (where !== null) {
    // /tmp and /var/tmp are world-writable; /var/folders/…/T belongs to one user.
    const words = where.kind === 'temp' && /^\/var\/folders\//i.test(p)
      ? 'in the per-user temporary folder (/var/folders/…), which the user (or anything running as them) can write to'
      : PERSIST_WORDS[where.kind];
    return { severity: 'high', reason: `${what} is ${words}` };
  }
  if (HOME_CACHES.test(p)) return { severity: 'high', reason: `${what} is in ~/Library/Caches, which the user can write to` };
  const key = p.toLowerCase();
  const matches = (i: Image) => {
    if (i.path === null) return false;
    const ip = normPath(i.path).toLowerCase();
    return target.isApp ? ip.startsWith(`${key}/`) : ip === key;
  };
  const seen = [...m.processes.values()].flatMap(q => q.images).filter(matches);
  const bad = seen.find(i => isUnsigned(i) || (!i.isPlatform && isAdhoc(i)));
  if (bad) return { severity: 'high', reason: `${what} ran ${isUnsigned(bad) ? 'unsigned' : 'ad-hoc signed'} in this capture` };
  if (HOME.test(p)) {
    if (!target.isApp && !APP_BUNDLE_EXE.test(p)) return { severity: 'high', reason: 'a loose program in a home folder, which the user (or anything running as them) can overwrite' };
    const team = seen.find(i => i.teamId !== null)?.teamId;
    return { severity: 'med', reason: team ? `an app bundle in a home folder, signed by team ${team}`
      : seen.length > 0 ? 'an app bundle in a home folder; it ran signed without a team ID'
      : 'an app bundle in a home folder; its signature was not seen in this capture' };
  }
  return { severity: 'med', reason: `${what} is in a system, /Applications or package-manager location` };
}

/** Apple's own system daemons (smd, backgroundtaskmanagementd) instigate most launch item registrations. */
export const SYSTEM_DIRS = /^\/(?:System|usr\/libexec|usr\/sbin)\//;

/**
 * The process a persistence finding attaches to, and through which link: the app that registered the item, else the
 * instigator (the XPC caller), else the plist's creator; null means a standalone row. An app or instigator counts
 * only when it is a captured process with a known path and is not an Apple platform binary under /System,
 * /usr/libexec or /usr/sbin: pinning a finding on smd would point at the messenger, and a pathless ghost cannot be
 * told apart from it.
 */
export function persistenceOwner(m: CaptureModel, item: PersistenceItem): { id: ProcId; via: 'app' | 'instigator' | 'creator' } | null {
  for (const via of ['app', 'instigator'] as const) {
    const id = item[via];
    const p = id !== null ? m.processes.get(id) : undefined;
    const img = p && !p.ghost ? imageAt(p, item.seq) : undefined;
    if (!img || img.path === null) continue;
    if (img.isPlatform && SYSTEM_DIRS.test(img.path)) continue;
    return { id: p!.id, via };
  }
  return item.creator !== null && m.processes.has(item.creator) ? { id: item.creator, via: 'creator' } : null;
}

/** "Evil (pid 900)", or "a standalone launch item" when the registration attaches to no process. */
function ownerName(m: CaptureModel, owner: { id: ProcId } | null, seq: number): string {
  const p = owner ? m.processes.get(owner.id) : undefined;
  if (!p) return 'a standalone launch item row';
  const img = imageAt(p, seq);
  return `${basename(img?.path ?? null) || 'pid'} (pid ${p.pid})`;
}

const PERSISTENCE_EXPLANATION = 'Something registered itself to run automatically at login or boot.';
const PLIST_GENERIC = `Wrote a launch agent or daemon plist: launchd loads it at login or boot ${TRIGGERS}.`;

function plistBase(plists: string[]): string {
  const kinds = new Set(plists.map(h => launchKind(null, h)));
  if (kinds.size !== 1) return PLIST_GENERIC;
  const kind = [...kinds][0];
  if (kind !== 'agent' && kind !== 'daemon') return PLIST_GENERIC;
  const scopes = new Set(plists.map(h => launchdStarts(kind, h).scope));
  const { scope, when } = scopes.size === 1 ? launchdStarts(kind, plists[0]!) : launchdStarts(kind, null);
  return `Wrote a launch ${kind} plist${scope}: launchd loads it ${when} ${TRIGGERS}.`;
}

// ---------------------------------------------------------------------------------------------------------------
// Pipes

/** The language an exec'd image reads from a piped stdin, or null. */
export function pipeLang(img: Image): PipeLang | null {
  if (img.stdinIsPipe !== true || img.script !== null || !img.args) return null;
  const lang = PIPE_LANGS.find(([re]) => re.test(basename(img.path)))?.[1];
  return lang && readsStdin(lang, img.args) ? lang : null;
}

/** openssl digest commands, where -d means debug output rather than decode. */
const OPENSSL_DIGESTS = /^(?:dgst|md4|md5|sha1|sha224|sha256|sha384|sha512|rmd160|ripemd160)$/;

// ---------------------------------------------------------------------------------------------------------------
// Pasted commands (ClickFix)

const PASTE_CHAIN_EXPLANATION = 'A shell, interpreter or osascript read its commands from a pipe a moment after a sibling process (same parent, within 3 s) decoded data (base64 -d, openssl enc -d, xxd -r) or fetched it with a curl, nscurl or wget flag that skips certificate checks or sets a custom user agent. That is the line a ClickFix page tells the user to paste into Terminal: fetch or decode a payload and run it without a file on disk. A plain `curl -fsSL … | bash`, the installer pattern of Homebrew and many tools, does not match this rule (shell-from-pipe still flags it). AI coding agents decode and fetch through their own shell-snapshot shells, so those are ignored.';

/** The first non-inherited image of a process: what it exec'd as soon as it was forked. */
const firstExec = (p: Process): Image | undefined => p.images.find(i => !i.inherited);

/** A process that runs commands read from a pipe: a shell or interpreter, or an osascript running its script from stdin. */
function readsPastedCommands(img: Image): boolean {
  if (pipeLang(img) !== null) return true;
  return basename(img.path) === 'osascript' && img.stdinIsPipe === true && img.args !== null && osascriptArgs(rest(img)).source === 'stdin';
}

/** What a sibling's image does for a paste chain: decode data, or fetch it with a flag that hides the fetch from checks. */
function pasteHelper(img: Image): 'decode' | 'fetch' | null {
  if (!img.args) return null;
  const n = basename(img.path);
  const a = rest(img);
  if (n === 'base64') return hasShortFlag(a, 'd') || hasShortFlag(a, 'D') || a.includes('--decode') ? 'decode' : null;
  if (n === 'openssl') return a[0] === 'enc' && a.includes('-d') ? 'decode' : null;
  if (n === 'xxd') return hasShortFlag(a, 'r') ? 'decode' : null;
  if (n === 'curl' || n === 'nscurl') {
    const o = parseOpts(a, CURL_SPEC);
    return hasOpt(o, 'k', ['--insecure']) || hasOpt(o, 'A', ['--user-agent']) ? 'fetch' : null;
  }
  if (n === 'wget') return hasOpt(parseOpts(a, WGET_SPEC), null, ['--no-check-certificate']) ? 'fetch' : null;
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Parents that should not run commands

const RISKY_PARENT_EXPLANATION = 'An app that has no business running commands ran one: Script Editor, an AppleScript applet or an Automator application stub; Word, Excel or PowerPoint (a macro or a booby-trapped document); or a developer tool (VS Code, Cursor, Windsurf, Xcode, dotnet, node, bun) running a download-and-run or an osascript. Droppers disguised as documents, scripts and project folders use these as the first step. Microsoft AutoUpdate and AI coding agents are ignored.';

type RiskyParent = 'script' | 'office' | 'developer';
const RISKY_PARENT_LABEL: Record<RiskyParent, string> = { script: 'Script Editor or an AppleScript applet', office: 'Office app', developer: 'developer tool' };

const SCRIPT_APP_SIGNING_ID = 'com.apple.ScriptEditor2';
const OFFICE_APP = /\/Microsoft (?:Word|Excel|PowerPoint)\.app\//;
const OFFICE_UPDATER = '/Microsoft AutoUpdate.app/';
/** Microsoft's own Apple team ID: a folder name is anyone's to choose, so the updater is told by its signature. */
const MICROSOFT_TEAM_ID = 'UBF8T346G9';
const DEVELOPER_APP = /\/(?:Visual Studio Code|Cursor|Windsurf|Xcode)\.app\//;
const DEVELOPER_PROGRAMS = new Set(['xcodebuild', 'XCBBuildService', 'dotnet', 'node', 'bun']);
const SCRIPT_APP_CHILDREN = new Set(['curl', 'nscurl', 'osascript', 'codesign', 'xattr', 'chmod', 'launchctl']);
const OFFICE_CHILDREN = new Set(['osascript', 'curl', 'chmod']);

/** True when this image is Microsoft AutoUpdate: inside a bundle of that name and signed by Microsoft. */
const isOfficeUpdater = (img: Image | undefined): boolean => img !== undefined && (img.path ?? '').includes(OFFICE_UPDATER) && img.teamId === MICROSOFT_TEAM_ID;

/** Which kind of risky parent this path or signing ID is, or null. Microsoft AutoUpdate, as signed by Microsoft, is never one. */
function riskyParentClass(img: Image | undefined): RiskyParent | null {
  if (img === undefined) return null;
  const path = img.path ?? '';
  if (img.signingId === SCRIPT_APP_SIGNING_ID || path.endsWith('/Contents/MacOS/applet') || path.includes('Automator Application Stub')) return 'script';
  if (isOfficeUpdater(img)) return null;
  if (OFFICE_APP.test(path)) return 'office';
  const name = basename(path);
  return DEVELOPER_APP.test(path) || DEVELOPER_PROGRAMS.has(name) || name.startsWith('Code Helper') ? 'developer' : null;
}

/** The text a shell is told to run with -c, or null when it has no -c. */
function shellCommand(img: Image): string | null {
  const a = rest(img);
  const i = a.findIndex(x => /^-[A-Za-z]*c[A-Za-z]*$/.test(x));
  return i < 0 ? null : a.slice(i + 1).join(' ');
}

/** A shell command that fetches and then hides or runs it: nohup, a pipe into an interpreter, or a fetch with certificate checks turned off. */
function downloadAndRun(command: string): boolean {
  if (!/\b(?:curl|wget)\b/.test(command)) return false;
  if (/\bnohup\b/.test(command) || /(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:\S*\/)?(?:sh|bash|zsh|node|python[0-9.]*)(?![\w./-])/.test(command)) return true;
  // The flag that skips certificate checks belongs to the fetch itself and differs by tool: curl -k or --insecure, but
  // wget --no-check-certificate (wget -k is --convert-links). `curl … && tar -xkf` or `du -sk` are not it.
  return command.split(/&&|\|\||[;|&\n]/).some(part =>
    (/\bcurl\b/.test(part) && /(?:^|\s)-[A-Za-z]*k[A-Za-z]*(?=\s|$)|--insecure/.test(part))
    || (/\bwget\b/.test(part) && /--no-check-certificate/.test(part)));
}

/** Does this program, run by a parent of this class, count? A developer parent only counts for a download-and-run or osascript. */
function riskyChild(cls: RiskyParent, img: Image): boolean {
  const n = basename(img.path);
  const shell = img.path !== null && SHELLS.has(img.path);
  if (cls === 'developer') {
    if (n === 'osascript') return true;
    const command = shell ? shellCommand(img) : null;
    return command !== null && downloadAndRun(command);
  }
  if (shell || n === 'osascript' || n === 'curl') return true;
  return cls === 'script'
    ? SCRIPT_APP_CHILDREN.has(n) || /^python[0-9.]*$/.test(n)
    : OFFICE_CHILDREN.has(n) || /^(?:python|perl|ruby)[0-9.]*$/.test(n);
}

/** The parent that makes this process risky: its class and path, looking at the original parent and (for Office) the responsible process. */
function riskyParent(m: CaptureModel, p: Process): { cls: RiskyParent; path: string; how: string } | null {
  const parent = originalParentImage(m, p);
  const cls = riskyParentClass(parent);
  if (parent !== undefined && cls !== null) return { cls, path: parent.path ?? '', how: '' };
  const resp = p.responsible !== null ? m.processes.get(p.responsible) : undefined;
  const respImage = resp ? imageAt(resp, p.firstSeq) : undefined;
  // Office's own children are often launched through a plain shell: the responsible process is still the document's app.
  // Microsoft AutoUpdate anywhere in the chain is the updater, not a document.
  if (riskyParentClass(respImage) === 'office' && !isOfficeUpdater(parent)) return { cls: 'office', path: respImage?.path ?? '', how: ' (responsible process)' };
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Dropped, then executed

/** A file counts as freshly dropped when it was created or renamed into place at most this long before it ran. */
export const DROP_WINDOW_MS = 15_000;
/** Run-and-delete: the file was unlinked at most this long after it ran. */
export const DELETE_WINDOW_MS = 60_000;

const DROPPED_EXPLANATION = 'A file ran within 15 s of a process writing it, from a place a normal install does not run from (a temporary folder, Downloads, /Users/Shared, a mounted volume, a hidden folder) or under a hidden name in a home folder. Downloaded or unpacked code is staged and run right away: the `curl -o` then run pattern, which never passes Gatekeeper because curl sets no quarantine flag. High when the file is unsigned or ad-hoc signed, has a hidden name, or was deleted within 60 s of running (run and delete); med otherwise. Compilers and build tools run what they just built, so a toolchain as the writer is ignored, and so are Go\'s build folders.';

/** Writers whose output is meant to be run at once: compilers, linkers, build systems and package managers. */
const TOOLCHAIN = new Set([
  'go', 'link', 'cargo', 'rustc', 'rust-lld', 'swift', 'swiftc', 'swift-frontend', 'clang', 'clang++', 'gcc', 'cc', 'ld', 'lld', 'ld64.lld', 'zig',
  'xcodebuild', 'make', 'cmake', 'ninja', 'brew',
]);

/** A path worth checking for a drop: a strong odd place, or a hidden file name under home outside a build or tooling folder. */
function dropCandidate(path: string): boolean {
  if (oddLocation(path)?.strength === 'strong') return true;
  return hiddenName(path) && HOME.test(normPath(path)) && !inBuildDir(path);
}

export const RULES: Rule[] = [
  {
    id: 'fake-prompt', title: 'Dialog box from osascript', severity: 'high',
    explanation: 'Shows a dialog box from an osascript script (AppleScript `display dialog`, or JavaScript for Automation `displayDialog`). Info-stealers use this to fake a system password prompt.',
    mitre: ['T1056.002'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'osascript' || !img.args) return null;
      const text = img.args.join(' ');
      if (!/display dialog|displayDialog|hidden answer|hiddenAnswer/i.test(text)) return null;
      return {
        evidence: cmdline(img),
        explanation: /hidden answer|hiddenAnswer/i.test(text)
          ? 'Shows a dialog box that asks for typed text and hides it as dots, the way a password prompt does. Info-stealers use this to fake a system password prompt.'
          : 'Shows a dialog box from an osascript script (AppleScript `display dialog`, or JavaScript for Automation `displayDialog`). Info-stealers use this to fake a system password prompt, or a fake error message once they are done.',
      };
    },
  },
  {
    id: 'osascript-script', title: 'osascript script from a file in an odd place, or from a pipe', severity: 'med',
    explanation: 'osascript ran a script (AppleScript, or JavaScript for Automation) from a file in a temporary, download, shared or hidden folder, a mounted volume or a translocated app, or piped into it with no file on disk.',
    mitre: ['T1059.002', 'T1059.007'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'osascript' || !img.args) return null;
      const o = osascriptArgs(rest(img));
      const mitre = o.js ? ['T1059.007'] : ['T1059.002'];
      const what = o.js ? 'a JavaScript for Automation script' : 'an AppleScript';
      if (o.source === 'stdin') {
        return img.stdinIsPipe === true
          ? { evidence: `${cmdline(img)} with stdin from a pipe`, mitre,
            explanation: `osascript ran ${what} piped into it, so there is no script file on disk to inspect.` }
          : null;
      }
      if (o.source !== 'file') return null;
      const file = resolvePath(o.file!, img.cwd);
      const where = oddLocation(file);
      if (where === null || where.strength !== 'strong') return null;
      return {
        evidence: `${cmdline(img)} (script ${file}, ${LOCATION_WORDS[where.kind].short})`, mitre,
        explanation: `osascript ran ${what} file from ${LOCATION_WORDS[where.kind].long}. Malware drops scripts in places like this and runs them with osascript.`,
      };
    },
  },
  {
    id: 'keychain-access', title: 'Keychain read with security', severity: 'high', gated: 'when-low',
    explanation: 'Ran `security` against the macOS keychain. High when it prints an app\'s Safe Storage key (Chromium-based browsers and Electron apps) or a crypto wallet entry (find-generic-password / find-internet-password with -g or -w), or dumps every secret (dump-keychain -d); med when it prints any other saved password; low (context only) for attribute lookups, unlock-keychain, export and dump-keychain without -d.',
    mitre: ['T1555.001'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'security') return null;
      const res = keychainFinding(rest(img));
      return res ? { ...res, evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'security-setting-change', title: 'Security setting changed', severity: 'high',
    explanation: 'Tried to weaken a macOS protection: turn Gatekeeper off, change a Gatekeeper rule, or add an exception (spctl --master-disable, --global-disable, --disable, --add), turn System Integrity Protection off in whole or part (csrutil disable, csrutil authenticated-root disable, csrutil enable --without), trust a root certificate or change the trust settings of a certificate (security add-trusted-cert), or change an authorization rule (security authorizationdb write); or pointed web or DNS traffic elsewhere (networksetup -setwebproxy, -setsecurewebproxy, -setautoproxyurl, -setsocksfirewallproxy, -setdnsservers, or switching a proxy on).',
    mitre: ['T1562.001', 'T1553.001', 'T1553.004', 'T1553', 'T1548', 'T1557'], scope: 'image',
    match: ({ img }) => settingChange(basename(img.path), rest(img), cmdline(img)),
  },
  {
    id: 'dscl-authonly', title: 'Password check with dscl', severity: 'high',
    explanation: 'Checks whether a password is correct for a local account. Stealers run it to verify a password the attacker just phished with a fake prompt.',
    mitre: ['T1056.002'], scope: 'image',
    match: ({ img }) =>
      basename(img.path) === 'dscl' && rest(img).some(a => a === '-authonly' || a === 'authonly') ? { evidence: cmdline(img) } : null,
  },
  {
    id: 'persistence-item', title: 'Launch item registered', severity: 'high',
    explanation: PERSISTENCE_EXPLANATION,
    mitre: ['T1543.001', 'T1543.004', 'T1547.015'], scope: 'persistence',
    matchItem: (item, m) => {
      if (item.kind !== 'add') return null;
      const app = item.appPath !== null ? trimSlash(item.appPath) : null;
      const target = launchTarget(item);
      // The item URL is a plist only for launch agents and daemons; for a login item it is usually the app.
      const itemPath = item.plistPath;
      const evidence = [
        itemPath !== null ? `${/\.plist$/i.test(itemPath) ? 'plist' : 'item'} ${itemPath}` : null,
        target !== null && !target.isApp ? `runs ${target.path}` : item.executablePath ? `runs ${item.executablePath}` : null,
        app !== null ? `app ${app}` : null,
      ].filter(Boolean).join('; ') || 'launch item with no paths';
      const base = persistenceSeverity(target, m);
      // An Apple-named plist that runs something Apple did not ship is the masquerade `apple-masquerade` describes.
      const wearsApple = target !== null && item.plistPath !== null && APPLE_LABEL_PLIST.test(normPath(item.plistPath))
        && !appleProgramPath(target.path) && !appleSignedAt(m, target);
      const note = wearsApple ? `Apple-named plist but runs ${target.path}` : null;
      const severity: Severity = wearsApple ? 'high' : base.severity;
      const reason = note === null ? base.reason : base.severity === 'high' ? `${base.reason}; ${note}` : note;
      const kind = launchKind(item.itemType, item.plistPath);
      return {
        evidence: `${evidence}; ${severity}: ${reason}`, severity, mitre: launchMitre(kind),
        ...(kind !== null ? { title: LAUNCH_TITLE[kind], explanation: launchExplanation(kind, item.plistPath) } : {}),
      };
    },
  },
  {
    id: 'persistence-plist', title: 'Launch agent/daemon plist written', severity: 'high',
    explanation: `${PLIST_GENERIC} Says whether a registration event in the capture accounts for it, and which process that registration is attributed to.`,
    mitre: ['T1543.001', 'T1543.004'], scope: 'process',
    matchProcess: (p, m) => {
      const unregistered: string[] = [];
      const elsewhere = new Map<string, string>();     // plist -> who its registration is attributed to
      const seen = new Set<string>();
      for (const op of p.fileOps) {
        // A temp file renamed over the plist counts through the rename's destination.
        const target = op.kind === 'create' ? op.path : op.kind === 'rename' ? op.toPath : undefined;
        if (target === undefined) continue;
        const n = normPath(target);
        const key = n.toLowerCase();
        if (!LAUNCH_DIR.test(n) || seen.has(key)) continue;
        seen.add(key);
        const items = m.persistence.filter(it => it.kind === 'add' && it.plistPath !== null && normPath(it.plistPath).toLowerCase() === key);
        if (items.length === 0) { unregistered.push(target); continue; }
        const owners = items.map(it => ({ it, owner: persistenceOwner(m, it) }));
        if (owners.some(o => o.owner?.id === p.id)) continue;   // the registration's own finding is on this process
        elsewhere.set(target, [...new Set(owners.map(o => ownerName(m, o.owner, o.it.seq)))].join(', '));
      }
      const hits = [...unregistered, ...elsewhere.keys()];
      if (hits.length === 0) return null;
      const kinds = new Set(hits.map(h => launchKind(null, normPath(h))));
      const only = kinds.size === 1 ? [...kinds][0]! : null;
      const names = [...new Set(elsewhere.values())].join(', ');
      const suffix = elsewhere.size === 0 ? ' No registration event in the capture accounts for it.'
        : unregistered.length === 0 ? ` Its registration in the capture is attributed to ${names}, so that finding is on that row.`
        : ` Some have no registration event in the capture; the registration of the others is attributed to ${names}.`;
      return {
        evidence: `wrote ${hits.map(h => (elsewhere.has(h) ? `${h} (registration attributed to ${elsewhere.get(h)})` : h)).join(', ')}`,
        mitre: [...new Set([...kinds].flatMap(launchMitre))].sort(),
        explanation: `${plistBase(hits)}${suffix}`,
        ...(only === 'agent' ? { title: 'Launch agent plist written' } : only === 'daemon' ? { title: 'Launch daemon plist written' } : {}),
      };
    },
  },
  {
    id: 'launchctl-load', title: 'launchctl loaded a job', severity: 'high',
    explanation: 'Loads a launch agent/daemon immediately instead of waiting for login.',
    mitre: ['T1569.001'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'launchctl') return null;
      const sub = img.args?.[1];
      return sub === 'load' || sub === 'bootstrap' || sub === 'submit' ? { evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'quarantine-strip', title: 'Quarantine flag removed', severity: 'high',
    explanation: "Removed the quarantine flag macOS puts on downloaded files, so Gatekeeper won't check it.",
    mitre: ['T1553.001'], scope: 'image',
    match: ({ img }) => {
      if (basename(img.path) !== 'xattr') return null;
      const a = rest(img);
      return hasShortFlag(a, 'c') || (hasShortFlag(a, 'd') && a.includes('com.apple.quarantine'))
        ? { evidence: cmdline(img) } : null;
    },
  },
  {
    id: 'payload-decode', title: 'Data decoded on the fly', severity: 'med',
    explanation: 'Decoded or decrypted data on the fly, a common way to unpack a hidden payload.',
    mitre: ['T1140'], scope: 'image',
    match: ({ img }) => {
      const n = basename(img.path);
      const a = rest(img);
      // openssl options are single-dash words, never clusters: only `-d` itself means decode/decrypt (`-md`, `-days` do not).
      // In the digest commands (dgst, sha256, md5…) -d means debug output.
      if (n === 'openssl' && a.includes('-d') && !OPENSSL_DIGESTS.test(a[0] ?? '')) return { evidence: cmdline(img) };
      if (n === 'base64' && (hasShortFlag(a, 'd') || hasShortFlag(a, 'D') || a.includes('--decode'))) return { evidence: cmdline(img) };
      return null;
    },
  },
  {
    id: 'shell-from-pipe', title: 'Shell or interpreter reading commands from a pipe', severity: 'med',
    explanation: "A shell, or python, perl or ruby, ran commands piped into it (the `curl … | bash` pattern), so there's no script file on disk to inspect. Version and help probes before the script starts do not count: --version and --help; for python also -V, -VV, -h; for perl -v, -V, -h; for ruby -h, -v (also in a cluster such as -wv) and -V, which ruby rejects as invalid and exits. A ruby -v probe, alone or in a cluster, followed by - still reads the piped script.",
    mitre: ['T1059.004', 'T1059.006', 'T1059'], scope: 'image',
    match: ({ p, img, imgIndex }) => {
      const lang = pipeLang(img);
      if (lang === null) return null;
      // Once per process: /bin/sh re-execs /bin/bash and perl re-execs perl5.30 with the same arguments.
      if (p.images.slice(0, imgIndex).some(i => !i.inherited && i.path !== null && pipeLang(i) !== null)) return null;
      const n = basename(img.path);
      return {
        evidence: `${cmdline(img)} with stdin from a pipe`, mitre: [lang.mitre],
        explanation: SHELL_NAMES.has(n)
          ? "A shell ran commands piped into it (the `curl … | bash` pattern), so there's no script file on disk to inspect."
          : `${n} ran a script piped into it (the \`curl … | ${n}\` pattern), so there's no script file on disk to inspect.`,
      };
    },
  },
  {
    id: 'shell-under-app', title: 'App launched a shell', severity: 'med',
    explanation: 'An app launched a shell. Malicious apps and droppers do this to run commands.',
    mitre: ['T1059.004'], scope: 'image',
    match: ({ m, p, img, imgIndex }) => {
      if (img.path === null || !SHELLS.has(img.path)) return null;
      // Once per process: macOS /bin/sh re-execs /bin/bash, which would repeat the finding.
      if (imgIndex !== p.images.findIndex(i => !i.inherited && i.path !== null && SHELLS.has(i.path))) return null;
      const parent = originalParentImage(m, p)?.path ?? null;
      if (parent === null || !parent.includes('.app/')) return null;
      if (/\/(?:Terminal|iTerm2?|Visual Studio Code|Code|Cursor|Xcode|Claude|Warp|Ghostty|Alacritty|kitty|WezTerm)\.app\//.test(parent)
        || parent.includes('Code Helper')) return null;
      return { evidence: `${parent} ran ${cmdline(img)}` };
    },
  },
  {
    id: 'download', title: 'Download to disk', severity: 'med',
    explanation: 'Fetched something from the network and wrote it to disk.',
    mitre: ['T1105'], scope: 'image',
    match: ({ p, img }) => {
      const n = basename(img.path);
      if (n !== 'curl' && n !== 'wget') return null;
      const a = rest(img);
      // `-`, /dev/null, /dev/stdout, /dev/stderr and /dev/fd/N are not files on disk.
      const isFile = (t: string | undefined): boolean =>
        t !== undefined && t !== '-' && !/^\/dev\/(?:null|stdout|stderr|fd\/\d+)$/.test(t);
      if (n === 'wget') {
        const o = parseOpts(a, WGET_SPEC);
        // --spider only checks that the URL exists; --version and --help print and exit.
        if (hasOpt(o, 'V', ['--spider', '--version', '--help']) || hasOpt(o, 'h')) return null;
        if (!o.positionals.some(looksLikeUrl) && !hasOpt(o, 'i', ['--input-file'])) return null;
        // wget saves to a file named after the URL unless -O / --output-document says otherwise; its -o is the log file.
        const targets = optValues(o, 'O', ['--output-document']);
        if (targets.length === 0) return { evidence: `${cmdline(img)}; wget saves to a file named after the URL by default` };
        if (targets.some(isFile)) return { evidence: cmdline(img) };
      } else {
        // curl writes to stdout unless -o / --output names a file (not /dev/null or -) or -O / --remote-name names it after the URL.
        const o = parseOpts(a, CURL_SPEC);
        if (hasOpt(o, 'O', ['--remote-name', '--remote-name-all']) || optValues(o, 'o', ['--output']).some(isFile)) return { evidence: cmdline(img) };
      }
      const created = p.fileOps.find(op => op.kind === 'create');
      return created ? { evidence: `${cmdline(img)}; created ${created.path}` } : null;
    },
  },
  {
    id: 'archive-staging', title: 'Files packed into an archive', severity: 'med',
    explanation: 'Packed files into an archive. Stealers stage collected data this way before sending it out.',
    mitre: ['T1560.001'], scope: 'image',
    match: ({ img }) => {
      const n = basename(img.path);
      const a = rest(img);
      const tool = n === 'ditto' && hasShortFlag(a, 'c') ? 'ditto' : n === 'zip' ? 'zip' : n === 'tar' && tarCreates(a) ? 'tar' : null;
      if (tool === null) return null;
      const where = stagingPlace(tool, a, img.cwd);
      if (where === null) return { evidence: cmdline(img), severity: 'med' };
      return {
        evidence: `${cmdline(img)} (staged in ${LOCATION_WORDS[where.kind].short})`, severity: 'high',
        explanation: `Packed files into an archive, in or from ${LOCATION_WORDS[where.kind].long}. Stealers stage collected data this way before sending it out.`,
      };
    },
  },
  {
    id: 'odd-location-exec', title: 'Ran from an unusual location', severity: 'med', gated: 'when-low',
    explanation: 'Ran a program or script from a temporary folder, Downloads, /Users/Shared, a mounted volume, a translocated app or a hidden folder, not from /Applications or a system folder.',
    mitre: ['T1204.002'], scope: 'image',
    match: ({ img }) => {
      const hits: { severity: Severity; evidence: string; what: 'program' | 'script'; where: OddLocation }[] = [];
      const where = img.path !== null ? oddLocation(img.path) : null;
      if (where !== null) {
        const adhoc = isAdhoc(img);
        const weak: Severity = isUnsigned(img) ? 'med' : 'low';
        const strong: Severity = isUnsigned(img) || adhoc ? 'high' : img.teamId !== null ? 'low' : 'med';
        const signing = !img.signingId ? 'unsigned'
          : adhoc ? `ad-hoc signed (${img.signingId})`
          : img.teamId !== null ? `signed by team ${img.teamId}` : `signed (${img.signingId})`;
        hits.push({
          severity: where.strength === 'strong' ? strong : weak, what: 'program', where,
          evidence: `${img.path} (${LOCATION_WORDS[where.kind].short}), ${signing}`,
        });
      }
      // A script has no signature of its own, so its location alone never makes it high.
      const scriptWhere = img.script !== null ? oddLocation(img.script) : null;
      if (scriptWhere !== null) {
        hits.push({
          severity: scriptWhere.strength === 'strong' ? 'med' : 'low', what: 'script', where: scriptWhere,
          evidence: `script ${img.script} (${LOCATION_WORDS[scriptWhere.kind].short})`,
        });
      }
      if (hits.length === 0) return null;
      const severity = hits.reduce<Severity>((s, h) => (SEVERITY_RANK[h.severity] > SEVERITY_RANK[s] ? h.severity : s), 'low');
      return { evidence: hits.map(h => h.evidence).join('; '), severity, explanation: oddLocationExplanation(hits) };
    },
  },
  {
    id: 'unsigned', title: 'Unsigned binary', severity: 'med', trait: true,
    explanation: 'Not signed at all. Unsigned binaries are a common trait of malware; not a technique by itself.',
    mitre: [], scope: 'image',
    match: ({ img }) => isUnsigned(img) ? { evidence: `${img.path} has no code signature` } : null,
  },
  {
    id: 'adhoc', title: 'Ad-hoc signed binary', severity: 'low', trait: true, gated: 'always',
    explanation: 'Ad-hoc signed: it carries a signature but no developer identity. Common for Homebrew and locally built tools, and for malware; a trait, not a technique by itself.',
    mitre: [], scope: 'image',
    match: ({ img }) =>
      !img.isPlatform && !!img.signingId && isAdhoc(img)
        ? { evidence: `${img.path} is ad-hoc signed (${img.signingId}), with no developer identity` } : null,
  },
  {
    id: 'orphaned', title: 'Detached from its parent', severity: 'low',
    explanation: 'Detached from the process that started it, so it keeps running after its parent exits and no longer shows up under it. Malware double-forks like this to break the link to whatever launched it.',
    mitre: ['T1036.009'], scope: 'process',
    matchProcess: (p, m) => {
      if (p.ppid !== 1 || p.originalPpid === null || p.originalPpid === 1) return null;
      const parent = originalParentImage(m, p)?.path ?? null;
      if (basename(parent) === 'xpcproxy') return null;
      return { evidence: `parent pid ${p.originalPpid}${parent ? ` (${basename(parent)})` : ''} gone; now under launchd` };
    },
  },
  {
    id: 'uid-mismatch', title: 'Running with borrowed privileges', severity: 'high', gated: 'when-low',
    explanation: UID_MISMATCH_EXPLANATION,
    mitre: ['T1548.001'], scope: 'process',
    matchProcess: (p) => {
      const list = p.credMismatches;
      if (!list || list.length === 0) return null;
      // Each image the process ran is judged on its own (an allow-listed tool can exec a shell that keeps euid 0); the
      // finding takes the worst. A drop from root, or a group change by root, is always low and explains itself when
      // nothing else climbed.
      let severity: Severity = 'low';
      let escalation = false;
      const kinds = new Set<MismatchKind>();
      const parts: { diffs: string; name: string; kind: MismatchKind }[] = [];
      for (const c of list) {
        const image = p.images[c.imgIndex];
        const diffs: string[] = [];
        if (c.euid !== c.ruid) diffs.push(`euid ${c.euid} ≠ ruid ${c.ruid}`);
        if (c.egid !== c.rgid) diffs.push(`egid ${c.egid} ≠ rgid ${c.rgid}`);
        const name = basename(image?.path ?? null);
        const kind = mismatchKind(c);
        if (!parts.some(x => x.diffs === diffs.join(', ') && x.name === name && x.kind === kind)) parts.push({ diffs: diffs.join(', '), name, kind });
        kinds.add(kind);
        if (kind !== 'escalation') continue;
        escalation = true;
        // Only a real Apple platform binary earns the allow list: a copy named sudo in /tmp does not.
        const s: Severity = !image || !image.isPlatform ? 'high'
          : SETUID_ALLOW.has(image.signingId ?? '') ? 'low' : 'med';
        if (SEVERITY_RANK[s] > SEVERITY_RANK[severity]) severity = s;
      }
      // Next to an escalation, a drop or a root group change is marked so the reader does not count it as a climb.
      const mixed = escalation && kinds.size > 1;
      const evidence = parts.map(x => {
        const tags = [x.name, mixed ? KIND_MARK[x.kind] : ''].filter(Boolean).join(', ');
        return `${x.diffs}${tags ? ` (${tags})` : ''}`;
      }).join('; ');
      if (escalation) return mixed ? { evidence, severity, explanation: `${UID_MISMATCH_EXPLANATION} ${MIXED_NOTE}` } : { evidence, severity };
      // Nothing climbed: say what it did instead, the strongest kind first.
      if (kinds.has('uid-drop')) return { evidence, severity, title: 'Dropped privileges', explanation: PRIVILEGE_DROP };
      if (kinds.has('gid-drop')) return { evidence, severity, title: 'Dropped privileges', explanation: GROUP_DROP };
      return { evidence, severity, title: 'Root with another effective group', explanation: ROOT_GROUP };
    },
  },
  {
    id: 'recon', title: 'System or user discovery', severity: 'low', gated: 'always',
    explanation: `Runs a tool that reads the machine, its user, network, Wi-Fi, processes or security settings (ps, networksetup, scutil, airport, csrutil, spctl, whoami, id, system_profiler, sw_vers, sysctl, ioreg, uname, hostname). Forms that change a setting are not recon.${RECON_TAIL}`,
    mitre: ['T1057', 'T1016', 'T1016.002', 'T1518.001', 'T1033', 'T1082'], scope: 'image',
    match: ({ img }) => {
      const kind = reconKind(img);
      if (kind === null) return null;
      const { mitre, what } = RECON_KINDS[kind];
      return { evidence: cmdline(img), mitre: [mitre], explanation: `${what}${RECON_TAIL}` };
    },
  },
  {
    id: 'credential-store-copy', title: 'Credential store copied', severity: 'med',
    explanation: CREDENTIAL_COPY_EXPLANATION,
    mitre: ['T1555.001', 'T1555.003', 'T1005', 'T1074.001'], scope: 'process',
    matchProcess: (p) => {
      const evidence: string[] = [];
      const labels = new Set<string>();
      let staged = false;                 // a credential store landed in, or a copy tool names, a staging place
      let copyToPlace = false;            // a copy tool names a credential store and, apart from it, a strong place
      const seen = new Set<string>();
      // (a) A credential store created, or renamed into place, in a temporary, shared, Downloads or hidden folder, by something other than a browser.
      for (const op of p.fileOps) {
        const target = op.kind === 'create' ? op.path : op.kind === 'rename' ? op.toPath : undefined;
        if (target === undefined) continue;
        const label = credentialStore(target);
        const where = oddLocation(target);
        if (label === null || where === null || where.strength !== 'strong' || !STAGING_KINDS.has(where.kind)) continue;
        // A browser engine writing its own profile is not theft; automation does it in a temporary folder with an ad-hoc browser.
        if (isBrowserEngine(imageAt(p, op.seq)?.path ?? null)) continue;
        const key = normPath(target).toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        evidence.push(`${op.kind === 'create' ? 'created' : 'renamed to'} ${target} (${label}, in ${LOCATION_WORDS[where.kind].short})`);
        labels.add(label);
        staged = true;
      }
      // (b) A copy tool with a credential store among its arguments.
      for (const img of p.images) {
        if (img.inherited || !COPY_TOOLS.has(basename(img.path)) || !img.args) continue;
        const named = img.args.slice(1).flatMap(a => { const x = pathArgument(a); return x === null ? [] : [resolvePath(x, img.cwd)]; });
        const found = named.flatMap((x, i) => { const l = credentialStore(x); return l === null ? [] : [{ i, l }]; });
        if (found.length === 0) continue;
        for (const { l } of found) labels.add(l);
        evidence.push(`${cmdline(img)} (${found[0]!.l})`);
        // Another argument in a strong place: the copy goes to, or comes from, a staging place.
        if (found.some(f => named.some((x, i) => i !== f.i && inStrongPlace(x)))) { staged = true; copyToPlace = true; }
      }
      if (evidence.length === 0) return null;
      const mitre = new Set(['T1005']);
      for (const l of labels) if (CREDENTIAL_MITRE[l]) mitre.add(CREDENTIAL_MITRE[l]!);
      if (staged) mitre.add('T1074.001');
      return {
        evidence: evidence.join('; '), severity: copyToPlace || writerIsOdd(p) ? 'high' : 'med',
        mitre: [...mitre].sort(),
      };
    },
  },
  {
    id: 'apple-masquerade', title: 'Pretends to be Apple', severity: 'high',
    explanation: APPLE_MASQUERADE_EXPLANATION,
    mitre: ['T1036.005', 'T1543.001', 'T1543.004'], scope: 'image',
    match: ({ p, img, imgIndex }) => {
      const evidence: string[] = [];
      const mitre = new Set<string>();
      let severity: Severity = 'med';
      // (a) Code that signs itself with an Apple signing ID: anyone can pick one, with an ad-hoc signature, a self-signed
      // certificate (no team ID) or another team's certificate. Apple's own code is platform-signed, or carries one of
      // Apple's team IDs, or sits in a place only Apple writes to.
      if (claimsApple(img) && !isAppleSigned(img)) {
        const who = img.path ?? 'a program';
        evidence.push(isAdhoc(img) ? `${who} is ad-hoc signed as ${img.signingId}`
          : img.teamId ? `${who} claims the signing ID ${img.signingId} but is signed by team ${img.teamId}`
          : `${who} claims the signing ID ${img.signingId} but has no Apple team ID`);
        mitre.add('T1036.005');
        severity = 'high';
      }
      // (b) A com.apple launch plist written by code that is not Apple's. The process's writes are judged once, under its
      // first exec'd image: a fork-only writer is skipped here because persistence-plist covers it.
      if (p.images.findIndex(i => !i.inherited) === imgIndex) {
        const seen = new Set<string>();
        for (const f of p.fileOps) {
          const target = f.kind === 'create' ? f.path : f.kind === 'rename' ? f.toPath : undefined;
          if (!target) continue;
          const n = normPath(target);
          if (!APPLE_LABEL_PLIST.test(n) || seen.has(n.toLowerCase())) continue;
          const writer = imageAt(p, f.seq);
          // Apple's installers write to /Library; in a user's own LaunchAgents a platform cp, tee, shell, osascript,
          // interpreter or curl is only copying someone's plist into place, however Apple-signed the tool is.
          if (writer === undefined || (isAppleSigned(writer) && !(USER_AGENT_DIR.test(n) && writer.isPlatform && GENERAL_TOOL.test(basename(writer.path))))) continue;
          seen.add(n.toLowerCase());
          evidence.push(`${writer.path ?? 'a program'} ${f.kind === 'create' ? 'created' : 'renamed to'} ${target}`);
          mitre.add('T1036.005');
          for (const t of launchMitre(launchKind(null, n))) mitre.add(t);
          if (USER_AGENT_DIR.test(n) || isUnsigned(writer) || isAdhoc(writer)) severity = 'high';
        }
      }
      return evidence.length === 0 ? null : { evidence: evidence.join('; '), severity, mitre: [...mitre].sort() };
    },
  },
  {
    id: 'clickfix-paste-chain', title: 'Pasted command: fetch, decode and run', severity: 'high',
    explanation: PASTE_CHAIN_EXPLANATION,
    mitre: ['T1204.004', 'T1059.004', 'T1140', 'T1105'], scope: 'image',
    match: ({ m, p, img, imgIndex }) => {
      if (!readsPastedCommands(img)) return null;
      // Once per process: /bin/sh re-execs /bin/bash with the same arguments and the same pipe.
      if (p.images.slice(0, imgIndex).some(i => !i.inherited && i.path !== null && readsPastedCommands(i))) return null;
      const readerMs = timeMs(firstExec(p)?.time ?? null);
      if (readerMs === null || underAgentShell(m, p)) return null;
      const found: { how: 'decode' | 'fetch'; line: string }[] = [];
      for (const s of siblings(m, p)) {
        const ms = timeMs(firstExec(s)?.time ?? null);
        if (ms === null || Math.abs(ms - readerMs) > PASTE_WINDOW_MS) continue;
        for (const i of s.images) {
          const how = i.inherited ? null : pasteHelper(i);
          if (how !== null) { found.push({ how, line: cmdline(i) }); break; }
        }
      }
      if (found.length === 0) return null;
      const mitre = new Set(['T1204.004']);
      if (pipeLang(img)?.mitre === 'T1059.004') mitre.add('T1059.004');
      for (const f of found) mitre.add(f.how === 'decode' ? 'T1140' : 'T1105');
      return {
        evidence: `${cmdline(img)} reads a pipe within ${PASTE_WINDOW_MS / 1000} s of ${found.map(f => f.line).join(' and ')}`,
        mitre: [...mitre].sort(),
      };
    },
  },
  {
    id: 'risky-parent-spawn', title: 'App that should not run commands ran one', severity: 'high',
    explanation: RISKY_PARENT_EXPLANATION,
    mitre: ['T1059.002', 'T1059.004', 'T1204.002'], scope: 'image',
    match: ({ m, p, img, imgIndex }) => {
      // Only the first program the process ran: /bin/sh re-execs /bin/bash, and a child may run on to something else.
      if (imgIndex !== p.images.findIndex(i => !i.inherited)) return null;
      const found = riskyParent(m, p);
      if (found === null || !riskyChild(found.cls, img)) return null;
      if (found.cls === 'developer') {
        // An agent's own spawns are expected: an npm-installed agent (node or bun running it) runs osascript and shells
        // itself, and an agent's snapshot shell counts only when its parent is that agent. The suspect's own command
        // line is never evidence of who it is: a snapshot path in a comment would let any payload through.
        const parent = originalParentImage(m, p);
        if (agentRuntime(parent) !== null || sourcesAgentSnapshot(img, parent)) return null;
      }
      const mitre = new Set<string>();
      if (found.cls === 'script') mitre.add('T1059.002');
      if (found.cls === 'office') mitre.add('T1204.002');
      if (img.path !== null && SHELLS.has(img.path)) mitre.add('T1059.004');
      if (basename(img.path) === 'osascript') mitre.add('T1059.002');
      return {
        evidence: `${RISKY_PARENT_LABEL[found.cls]}${found.path ? ` ${found.path}` : ''}${found.how} ran ${cmdline(img)}`,
        mitre: [...mitre].sort(),
      };
    },
  },
  {
    id: 'dropped-then-executed', title: 'Ran a file written just before', severity: 'med',
    explanation: DROPPED_EXPLANATION,
    mitre: ['T1105', 'T1204.002', 'T1070.004', 'T1564.001'], scope: 'image',
    match: ({ m, img }) => {
      if (img.inherited || img.path === null || !dropCandidate(img.path)) return null;
      const execMs = timeMs(img.time);
      if (execMs === null) return null;
      const key = normPath(img.path).toLowerCase();
      const ledger = fileLedger(m);
      // The latest drop of this path before the exec, if it is recent enough.
      let drop: { writer: ProcId; seq: number; ms: number } | null = null;
      for (const d of ledger.drops.get(key) ?? []) {
        if (d.ms === null || d.seq >= img.seq || execMs - d.ms < 0 || execMs - d.ms > DROP_WINDOW_MS) continue;
        if (drop === null || d.seq > drop.seq) drop = { writer: d.writer, seq: d.seq, ms: d.ms };
      }
      if (drop === null) return null;
      const writerProc = m.processes.get(drop.writer);
      // The writer is the image the process was running when it wrote. A toolchain name is only a name: a program that runs
      // from a strong odd place or has no signature at all does not earn the exemption (an ad-hoc one does: Go's linker is).
      const writerImage = writerProc ? imageAt(writerProc, drop.seq) : undefined;
      const writer = basename(writerImage?.path ?? null);
      const dubious = writerImage !== undefined && (isUnsigned(writerImage) || (writerImage.path !== null && oddLocation(writerImage.path)?.strength === 'strong'));
      if (TOOLCHAIN.has(writer) && !dubious) return null;
      let deleteMs: number | null = null;
      for (const u of ledger.unlinks.get(key) ?? []) {
        if (u.ms === null || u.seq <= img.seq || u.ms < execMs || u.ms - execMs > DELETE_WINDOW_MS) continue;
        if (deleteMs === null || u.ms < deleteMs) deleteMs = u.ms;
      }
      const hidden = hiddenName(img.path);
      const evidence = [`${img.path} was written by ${writer || 'another process'} ${Math.round((execMs - drop.ms) / 1000)} s before it ran`];
      if (deleteMs !== null) evidence.push(`deleted ${Math.round((deleteMs - execMs) / 1000)} s after`);
      const mitre = new Set(['T1105', 'T1204.002']);
      if (deleteMs !== null) mitre.add('T1070.004');
      if (hidden) mitre.add('T1564.001');
      return {
        evidence: evidence.join(', '),
        severity: deleteMs !== null || hidden || isUnsigned(img) || (!img.isPlatform && isAdhoc(img)) ? 'high' : 'med',
        mitre: [...mitre].sort(),
      };
    },
  },
];
