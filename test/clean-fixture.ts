// Builders for hand-made eslogger captures (schema 11), for the cleaner's tests. Every builder after esProc returns one
// JSONL line; esProc returns the process object that the others embed. Every event takes an explicit `seq`, which
// becomes its global_seq_num, so a test can leave gaps. A `seq` argument is either the number or `{seq}`.

export interface ProcOpts {
  pid: number;
  pidversion?: number;
  path: string;
  uid?: number;
  euid?: number;
  signingId?: string | null;
  teamId?: string | null;
  platform?: boolean;
  ppid?: number;
}

type Json = Record<string, unknown>;
type SeqArg = number | { seq: number };
const seqOf = (s: SeqArg): number => (typeof s === 'number' ? s : s.seq);

const T0 = Date.parse('2026-03-14T10:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString().replace('Z', '000Z');

const token = (pid: number, pidversion: number, uid: number, euid = uid): Json => ({
  auid: uid, ruid: uid, rgid: 20, egid: 20, euid, asid: 100000 + pid, pid, pidversion,
});

/** An eslogger process object: audit token `pid:pidversion` (pidversion defaults to pid + 1000), parent launchd. */
export function esProc(o: ProcOpts): Json {
  const pidversion = o.pidversion ?? o.pid + 1000;
  const uid = o.uid ?? 501;
  const ppid = o.ppid ?? 1;
  return {
    tty: null,
    start_time: '2026-03-14T09:00:00.000000Z',
    session_id: 1,
    is_es_client: false,
    ppid,
    is_platform_binary: o.platform ?? false,
    original_ppid: ppid,
    team_id: o.teamId ?? null,
    cdhash: '6F8527C5F41B804E4C90BF31A969ACF8C4694EE6',
    parent_audit_token: token(ppid, ppid + 1000, 0),
    cs_validation_category: o.platform ? 1 : 6,
    executable: { path_truncated: false, path: o.path },
    signing_id: o.signingId ?? null,
    group_id: o.pid,
    codesigning_flags: o.platform ? 637631233 : 570491649,
    audit_token: token(o.pid, pidversion, uid, o.euid ?? uid),
    responsible_audit_token: token(o.pid, pidversion, uid, o.euid ?? uid),
  };
}

function line(proc: Json, name: string, eventType: number, body: Json, seq: number): string {
  return JSON.stringify({
    action: { result: { result_type: 0, result: { auth: 0 } } },
    version: 11,
    action_type: 1,
    event_type: eventType,
    thread: { thread_id: 4000 + seq },
    process: proc,
    schema_version: 1,
    seq_num: seq,
    event: { [name]: body },
    time: iso(T0 + seq),
    global_seq_num: seq,
    mach_time: 2_400_000_000_000 + seq * 40_000,
  });
}

const file = (path: string): Json => ({ path_truncated: false, path });
const DEFAULT_ENV = ['HOME=/Users/alice', 'LANG=C.UTF-8', 'LOGNAME=alice', 'PATH=/usr/bin:/bin', 'SHELL=/bin/zsh', 'USER=alice'];
const TTY_FDS = [{ fd: 0, fdtype: 1 }, { fd: 1, fdtype: 1 }, { fd: 2, fdtype: 1 }];
const PIPE_FDS = [{ fd: 0, fdtype: 6, pipe: { pipe_id: 100231 } }, { fd: 1, fdtype: 1 }, { fd: 2, fdtype: 1 }];

export interface ExecOpts {
  args: string[];
  cwd: string;
  seq: number;
  env?: string[];
  stdinPipe?: boolean;
  script?: string;
}

/** `proc` execs `target`: the event carries the process before the exec, `target` is the image after it. */
export function esExec(proc: Json, target: Json, o: ExecOpts): string {
  return line(proc, 'exec', 9, {
    image_cpusubtype: 2,
    script: o.script ? file(o.script) : null,
    cwd: file(o.cwd),
    target,
    entitlements: {},
    dyld_exec_path: (target['executable'] as { path: string }).path,
    fds: o.stdinPipe ? PIPE_FDS : TTY_FDS,
    env: o.env ?? DEFAULT_ENV,
    args: o.args,
    image_cputype: 16777228,
    last_fd: 2,
  }, o.seq);
}

export const esFork = (proc: Json, child: Json, seq: SeqArg): string =>
  line(proc, 'fork', 11, { child }, seqOf(seq));

/** A created file: `{path}` for one that exists, `{dir, filename}` for a new one eslogger reports by folder and name. */
export function esCreate(proc: Json, dest: { path: string } | { dir: string; filename: string }, seq: SeqArg): string {
  const destination = 'path' in dest
    ? { existing_file: file(dest.path) }
    : { new_path: { dir: file(dest.dir), filename: dest.filename, mode: 33188 } };
  return line(proc, 'create', 13, { destination, destination_type: 'path' in dest ? 0 : 1, acl: null }, seqOf(seq));
}

export const esRename = (proc: Json, from: string, to: string, seq: SeqArg): string =>
  line(proc, 'rename', 25, { destination: { existing_file: file(to) }, destination_type: 0, source: file(from) }, seqOf(seq));

export interface BtmOpts { itemUrl: string; executablePath: string; appUrl?: string; itemType: number }

/** A background task management event: `proc` is the emitter (backgroundtaskmanagementd). */
export function esBtm(proc: Json, o: BtmOpts, seq: SeqArg): string {
  return line(proc, 'btm_launch_item_add', 124, {
    app_token: null,
    executable_path: o.executablePath,
    instigator_token: token(560, 1390, 0),
    app: null,
    instigator: null,
    item: { uid: 501, item_url: o.itemUrl, app_url: o.appUrl ?? null, legacy: true, item_type: o.itemType, managed: false },
  }, seqOf(seq));
}

export const esExit = (proc: Json, seq: SeqArg): string => line(proc, 'exit', 15, { stat: 0 }, seqOf(seq));

/** A hard link `target_dir/target_filename` to `source`: eslogger names the new link by folder and bare name. */
export const esLink = (proc: Json, source: string, targetDir: string, name: string, seq: SeqArg): string =>
  line(proc, 'link', 19, { source: file(source), target_dir: file(targetDir), target_filename: name }, seqOf(seq));

/** A clone (APFS copy) of `source` as `target_dir/target_name`. */
export const esClone = (proc: Json, source: string, targetDir: string, name: string, seq: SeqArg): string =>
  line(proc, 'clone', 61, { source: file(source), target_dir: file(targetDir), target_name: name }, seqOf(seq));
