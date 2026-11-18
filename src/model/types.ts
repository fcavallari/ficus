export type TokenKey = string;            // `${pid}:${pidversion}`
export type ProcId = string;              // first TokenKey of the exec chain, or `ghost:${pid}`
/** Real and effective user and group ids of an audit_token. */
export interface Ids { ruid: number; euid: number; rgid: number; egid: number }
export interface ProcInfo {               // normalized es process object
  token: TokenKey; pid: number; path: string | null;
  signingId: string | null; teamId: string | null;
  isPlatform: boolean; csFlags: number;
  ppid: number | null; originalPpid: number | null;
  parentToken: TokenKey | null; responsibleToken: TokenKey | null;
  startTime: string | null;
  ids: Ids | null;                          // null when the audit_token lacks any of the four
}
export type EventKind = 'fork' | 'exec' | 'exit' | 'create' | 'rename' | 'unlink'
  | 'write' | 'setextattr' | 'btm_add' | 'btm_remove' | 'other';
export interface BtmInfo { plistPath: string | null; executablePath: string | null; appPath: string | null;
  itemType: number | null;                                  // es_btm_item_type_t: 0 user item, 1 app, 2 login item, 3 agent, 4 daemon
  instigator: ProcInfo | null; instigatorToken: TokenKey | null;   // the XPC caller that asked for the item
  app: ProcInfo | null; appToken: TokenKey | null }                // the app process that registered it
export interface NormEvent {
  seq: number; time: string; kind: EventKind; rawType: string; version: number;
  /** A Mac Monitor record's mach_time: it orders the trace, since Mac Monitor's sequence numbers are per ES client. */
  machTime?: number;
  /** The record carried no numeric global_seq_num, so `seq` is a placeholder 0 and takes no part in gap counting. */
  seqMissing?: true;
  proc: ProcInfo;
  child?: ProcInfo;                                         // fork
  target?: ProcInfo; args?: string[]; cwd?: string | null;  // exec
  env?: string[]; stdinIsPipe?: boolean | null; script?: string | null;
  path?: string; toPath?: string; xattr?: string;           // file ops
  btm?: BtmInfo;
}
export interface Image {
  token: TokenKey; path: string | null; signingId: string | null; teamId: string | null;
  isPlatform: boolean; csFlags: number;
  args: string[] | null; cwd: string | null; env: string[] | null;   // null when not from an exec event
  stdinIsPipe: boolean | null; script: string | null;
  time: string | null; seq: number;   // for an inherited image: the fork event's time and seq
  inherited: boolean;   // true for the copy a fork child starts with; rules skip these
}
export interface FileOp { kind: 'create' | 'rename' | 'unlink' | 'write' | 'setextattr';
  path: string; toPath?: string; xattr?: string; time: string; seq: number }
export interface Process {
  id: ProcId; pid: number; ghost: boolean; images: Image[];
  forkParent: ProcId | null;
  originalPpid: number | null; ppid: number | null;
  parentToken: TokenKey | null; responsibleToken: TokenKey | null;   // raw, latest seen
  originalParent: ProcId | null; currentParent: ProcId | null; responsible: ProcId | null; // resolved by resolveRelations
  startTime: string | null; exitTime: string | null; firstSeq: number; fileOps: FileOp[];
  /** Sequence number of the exit event, when one was captured. */
  exitSeq?: number;
  /**
   * Per image the process ran, the first event whose audit_token had euid != ruid or egid != rgid (setuid/setgid), with
   * those ids. `imgIndex` is the image running when that token was seen (for the emitter of an exec, the one before it).
   */
  credMismatches?: (Ids & { seq: number; time: string; imgIndex: number })[];
}
export interface PersistenceItem { id: string; kind: 'add' | 'remove'; plistPath: string | null;
  executablePath: string | null; appPath: string | null; time: string; seq: number;
  itemType: number | null;                                  // see BtmInfo.itemType
  emitter: ProcId;                                          // the process that emitted the event (smd, backgroundtaskmanagementd)
  instigatorToken: TokenKey | null; appToken: TokenKey | null;   // raw
  instigator: ProcId | null; app: ProcId | null;            // resolved in resolveRelations
  creator: ProcId | null }                                  // the plist's writer, resolved in resolveRelations
/** `lines` and `badLines` count records, not lines, when `layout` is 'objects' (a pretty-printed export). */
export interface CaptureStats { lines: number; events: number; badLines: number; layout?: 'objects';
  otherEvents: Record<string, number>; versions: number[];
  /** Modelled events by eslogger event type (`exec`, `btm_launch_item_add`…), so a missing type can be told apart from an empty one. */
  kinds?: Record<string, number>;
  /**
   * Numbers missing from the global_seq_num sequence, and how many separate holes they form: Endpoint Security numbers
   * every event it delivers, so a hole is an event dropped (the recorder fell behind) or removed afterwards. Set for an
   * eslogger capture, 0 when it is complete; absent for a Mac Monitor trace, whose numbers restart per ES client.
   */
  seqGaps?: number; seqGapRuns?: number;
  firstSeq: number | null; firstTime: string | null; lastTime: string | null }
export interface CaptureModel { processes: Map<ProcId, Process>; tokenIndex: Map<TokenKey, ProcId>;
  persistence: PersistenceItem[]; stats: CaptureStats }
