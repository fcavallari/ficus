import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

// lab/lab-net.py joins the gateway VM and the sample VM with a private socket-pair cable (`tart run --net-fd`).
// The tests run it against a stub `tart` (a Python script) that logs what it was given and what came over the cable.
const LAUNCHER = path.resolve(__dirname, '..', 'lab', 'lab-net.py');

const STUB = `#!/usr/bin/env python3
import json, os, signal, socket, sys, time
log = os.environ["STUB_LOG"]
def write(rec):
    with open(log, "a") as f:
        f.write(json.dumps(rec) + "\\n")
args = sys.argv[1:]
if args[0] == "stop":
    write({"op": "stop", "name": args[1]})
    sys.exit(0)
name = args[-1]
fd = next(int(a.split("=", 1)[1]) for a in args if a.startswith("--net-fd="))
s = socket.socket(fileno=fd)
rec = {"op": "run", "name": name, "pid": os.getpid(), "args": args, "fd": fd,
       "sndbuf": s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
       "rcvbuf": s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)}
if name == os.environ.get("STUB_EXIT_NAME"):
    write(rec)
    sys.exit(3)
if name.startswith("gw"):
    s.send(b"hello-from-gateway")
else:
    s.settimeout(5)
    rec["got"] = s.recv(2048).decode()
write(rec)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
while True:
    time.sleep(0.1)
`;

let dir: string;
let tart: string;
let logFile: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-net-'));
  tart = path.join(dir, 'tart');
  logFile = path.join(dir, 'log.jsonl');
  fs.writeFileSync(tart, STUB, { mode: 0o755 });
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

interface Rec { op: string; name: string; pid?: number; args?: string[]; fd?: number; sndbuf?: number; rcvbuf?: number; got?: string }
const records = (): Rec[] => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l) as Rec) : []);
const runs = () => records().filter(r => r.op === 'run');
const stops = () => records().filter(r => r.op === 'stop').map(r => r.name).sort();
const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const env = (extra: Record<string, string> = {}) => ({ PATH: process.env.PATH ?? '', LAB_TART: tart, STUB_LOG: logFile, ...extra });

/** Starts the launcher and resolves with it once it has printed READY. */
function start(args: string[], extra: Record<string, string> = {}) {
  const child = spawn('python3', [LAUNCHER, ...args], { env: env(extra), stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', d => { out += String(d); });
  child.stderr.on('data', d => { err += String(d); });
  const exited = new Promise<number | null>(res => child.on('exit', code => res(code)));
  const ready = new Promise<void>((res, rej) => {
    const t = setInterval(() => { if (out.includes('READY')) { clearInterval(t); res(); } }, 50);
    void exited.then(() => { clearInterval(t); rej(new Error(`exited before READY: ${err}`)); });
  });
  ready.catch(() => undefined); // a test that never awaits `ready` must not leave an unhandled rejection behind
  return { child, exited, ready, output: () => out, errors: () => err };
}
const until = async (cond: () => boolean, ms = 8000) => {
  const end = Date.now() + ms;
  while (!cond() && Date.now() < end) await new Promise(r => setTimeout(r, 50));
};

describe('lab/lab-net.py', () => {
  test('parses under python3', () => {
    // Compile in memory: py_compile would leave a __pycache__ folder next to the launcher.
    const code = 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")';
    expect(spawnSync('python3', ['-I', '-B', '-c', code, LAUNCHER]).status).toBe(0);
  });

  test('starts both VMs on different cable ends, with the buffers raised, and prints READY', async () => {
    const l = start(['--gateway', 'gw-1', '--guest', 'g-1']);
    await l.ready;
    await until(() => runs().length === 2 && runs().every(r => r.name === 'gw-1' || r.got !== undefined));
    const [gw, guest] = [runs().find(r => r.name === 'gw-1')!, runs().find(r => r.name === 'g-1')!];
    expect(gw.fd).not.toBe(guest.fd);
    expect(gw.args).toContain('run');
    for (const r of [gw, guest]) {
      expect(r.sndbuf!).toBeGreaterThanOrEqual(1 << 20);
      expect(r.rcvbuf!).toBeGreaterThanOrEqual(1 << 20);
    }
    l.child.kill('SIGTERM');
    await l.exited;
  });

  test('a datagram sent on the gateway end arrives on the guest end', async () => {
    const l = start(['--gateway', 'gw-1', '--guest', 'g-1']);
    await l.ready;
    await until(() => runs().some(r => r.name === 'g-1'));
    expect(runs().find(r => r.name === 'g-1')!.got).toBe('hello-from-gateway');
    l.child.kill('SIGTERM');
    await l.exited;
  });

  test('neither VM gets a shared folder, a clipboard or USB', async () => {
    const l = start(['--gateway', 'gw-1', '--guest', 'g-1']);
    await l.ready;
    await until(() => runs().length === 2);
    for (const r of runs()) {
      expect(r.args!.some(a => a.startsWith('--dir')), r.name).toBe(false);
      expect(r.args, r.name).toContain('--no-clipboard');
      expect(r.args, r.name).toContain('--no-usb-accessories');
    }
    l.child.kill('SIGTERM');
    await l.exited;
  });

  test('the shared-folder option is gone', () => {
    expect(spawnSync('python3', [LAUNCHER, '--gateway', 'gw-1', '--guest', 'g-1', '--gateway-out', '/tmp'], { env: env() }).status).toBe(2);
  });

  test('--guest-window runs the guest with a window; otherwise both are headless', async () => {
    const headless = start(['--gateway', 'gw-1', '--guest', 'g-1']);
    await headless.ready;
    await until(() => runs().length === 2);
    expect(runs().every(r => r.args!.includes('--no-graphics'))).toBe(true);
    headless.child.kill('SIGTERM');
    await headless.exited;
    fs.rmSync(logFile);
    const windowed = start(['--gateway', 'gw-2', '--guest', 'g-2', '--guest-window']);
    await windowed.ready;
    await until(() => runs().length === 2);
    expect(runs().find(r => r.name === 'g-2')!.args).not.toContain('--no-graphics');
    expect(runs().find(r => r.name === 'gw-2')!.args).toContain('--no-graphics');
    windowed.child.kill('SIGTERM');
    await windowed.exited;
  });

  test('SIGTERM stops both VMs, exits 0 and leaves no child running', async () => {
    const l = start(['--gateway', 'gw-1', '--guest', 'g-1']);
    await l.ready;
    await until(() => runs().length === 2);
    const pids = runs().map(r => r.pid!);
    l.child.kill('SIGTERM');
    expect(await l.exited).toBe(0);
    expect(stops()).toEqual(['g-1', 'gw-1']);
    await until(() => pids.every(p => !alive(p)));
    expect(pids.map(alive)).toEqual([false, false]);
  });

  test('when one VM exits, the launcher stops the other and exits non-zero', async () => {
    const l = start(['--gateway', 'gw-1', '--guest', 'g-1'], { STUB_EXIT_NAME: 'g-1' });
    const code = await l.exited;
    expect(code).not.toBe(0);
    expect(stops()).toEqual(['g-1', 'gw-1']);
    const gw = runs().find(r => r.name === 'gw-1');
    if (gw) await until(() => !alive(gw.pid!));
    if (gw) expect(alive(gw.pid!)).toBe(false);
  });

  test('a missing --guest exits 2', () => {
    expect(spawnSync('python3', [LAUNCHER, '--gateway', 'gw-1'], { env: env() }).status).toBe(2);
  });
});
