// Builds the one command line an agent hands to a person. The server never runs it: the person pastes it into
// Terminal, where the cleaner script asks for their password (sudo eslogger) and writes a cleaned capture.
// Anything the agent supplies ends up in the person's shell next to sudo, so it is validated and refused, never quoted.
import fs from 'node:fs';
import path from 'node:path';
import type { FicusPaths } from './home';

export interface RecordCommand {
  command: string;
  capture: string;
  instructions: string[];
}

// The cleaner finds ficus-clean.jq next to itself, so both files go to bin/ together.
export const CLEANER_FILES = ['ficus-clean.sh', 'ficus-clean.jq'] as const;

const DEFAULT_SECONDS = 600;
const MIN_SECONDS = 60;
const MAX_SECONDS = 1800;

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

// Characters that would end the double quotes the paths are wrapped in, or expand inside them.
const UNSAFE_IN_QUOTES = /["$`\\\n\r\0]/;

function checkedSeconds(seconds: number | undefined): number {
  const s = seconds ?? DEFAULT_SECONDS;
  if (!Number.isInteger(s) || s < MIN_SECONDS || s > MAX_SECONDS) {
    throw new RangeError(`seconds must be a whole number from ${MIN_SECONDS} to ${MAX_SECONDS}; got ${String(seconds)}.`);
  }
  return s;
}

function checkedDomains(domains: string[] | undefined): string[] {
  const list = domains ?? [];
  for (const d of list) {
    if (typeof d !== 'string' || !DOMAIN.test(d)) {
      throw new RangeError(
        `domain ${JSON.stringify(d)} is not a plain domain name such as "example.com" (letters, digits, hyphens and dots only).`,
      );
    }
  }
  return list;
}

function pad(n: number, width = 2): string {
  return String(n).padStart(width, '0');
}

// Local time, so the name matches the clock the person sees.
function captureName(now: Date): string {
  const day = `${pad(now.getFullYear(), 4)}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  const time = `${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `capture-${day}-${time}.cleaned.jsonl`;
}

function installCleaner(p: FicusPaths, scriptsDir: string): void {
  fs.mkdirSync(p.bin, { recursive: true });
  for (const name of CLEANER_FILES) {
    const source = fs.readFileSync(path.join(scriptsDir, name));
    const target = path.join(p.bin, name);
    let current: Buffer | undefined;
    try {
      current = fs.readFileSync(target);
    } catch {
      current = undefined;
    }
    if (!current || !current.equals(source)) fs.writeFileSync(target, source);
    fs.chmodSync(target, name.endsWith('.sh') ? 0o755 : 0o644);
  }
}

function duration(seconds: number): string {
  if (seconds % 60 !== 0) return `${seconds} seconds`;
  const m = seconds / 60;
  return m === 1 ? '1 minute' : `${m} minutes`;
}

export function recordCommand(
  p: FicusPaths,
  scriptsDir: string,
  opts: { seconds?: number; domains?: string[] },
  now: Date = new Date(),
): RecordCommand {
  const seconds = checkedSeconds(opts.seconds);
  const domains = checkedDomains(opts.domains);
  for (const dir of [p.bin, p.captures]) {
    if (UNSAFE_IN_QUOTES.test(dir)) {
      throw new RangeError(`the Ficus folder path ${JSON.stringify(dir)} has a character that cannot be put safely in a Terminal command.`);
    }
  }

  installCleaner(p, scriptsDir);
  fs.mkdirSync(p.captures, { recursive: true });

  const capture = captureName(now);
  const command = [
    `"${path.join(p.bin, 'ficus-clean.sh')}" record -o "${path.join(p.captures, capture)}" -t ${seconds}`,
    ...domains.map((d) => `-D ${d}`),
  ].join(' ');

  const instructions = [
    'Open Terminal (Applications > Utilities > Terminal, or press Command-Space and type Terminal).',
    'Paste the command and press Return.',
    'When Terminal asks for a password, type your Mac password. The Mac asks for it (for sudo), not the agent, and nothing shows as you type.',
    'If it stops at once saying eslogger stopped before recording anything, give Terminal Full Disk Access in System Settings > Privacy & Security > Full Disk Access, then run the command again.',
    `Keep using the Mac normally until it stops by itself after ${duration(seconds)}.`,
    'Tell the agent when Terminal shows the summary.',
  ];
  return { command, capture, instructions };
}
