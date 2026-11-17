# Ficus MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stdio MCP server that lets an agent hand out the cleaned-recording command, read Ficus's redacted report on the result, and export the report (or the full session) for Security Ops.

**Architecture:** `src/mcp/` holds plain modules (paths and the cleaned-capture guard, the record command, a `Workspace` that loads one capture and builds `ficus-report`s from it, the export writer) and a thin `server.ts` that registers five tools with the MCP SDK. A second Vite build bundles it into `dist-mcp/ficus-mcp.mjs`; a pack step wraps that and the cleaner into `dist-mcp/ficus.mcpb`.

**Tech Stack:** TypeScript, Node 24 (tests) / Claude Desktop's bundled Node (runtime), `@modelcontextprotocol/sdk` ^1.32, `zod` ^4, Vite 8 (SSR build), Vitest 5, `@anthropic-ai/mcpb` ^2 (dev, packing).

**Spec:** `docs/superpowers/specs/2026-11-17-mcp-server-design.md` (read it first; this plan does not repeat its reasoning).

## Global Constraints

- Nothing under `src/model`, `src/rules`, `src/report`, `src/ingest`, `src/session` or `src/ui` changes. The server only imports them.
- Every tool output the agent sees comes from a report built with `redactArgs: true`, except `ficus_row` with `reveal: true`.
- No tool returns environment variables or opens the key file (existence checks only).
- No network, no child processes anywhere in `src/mcp/`: no `fetch`, `node:http`, `node:https`, `node:net`, `node:dgram`, `node:child_process`.
- Writes only under `ficusPaths().home` and the new export folder under `ficusPaths().exportRoot`.
- `dist/` must keep holding only `index.html`; server output goes to `dist-mcp/` (git-ignored).
- Ficus folder: `~/Library/Application Support/Ficus/` with `keys/` (the cleaner's), `captures/`, `bin/`. Overrides: `FICUS_HOME`, `FICUS_EXPORT_DIR` (default `~/Desktop`).
- Record command: `seconds` default 600, allowed 60 to 1800. Output name `capture-YYYY-MM-DD-HHMMSS.cleaned.jsonl` (local time).
- Cleaned-capture guard: plain file name, directly in `captures/`, `keys/<name>.key.tsv` exists, not modified in the last 10 000 ms.
- `ficus_analyze` page size: 40 rows.
- Made-up session name: `self-check YYYY-MM-DD HH:MM` (local time), random UUID id, stable per capture for the life of the server.
- Export folder: `<exportRoot>/Ficus report YYYY-MM-DD HHMMSS/`; files `agent-verdict.md`, `README.txt`, `reportFileName(session,'md')`, `reportFileName(session,'json')`; full adds the capture (same name) and `saveFileName(session)`. Never a `.key.tsv`.
- Tool names: `ficus_record_command`, `ficus_list_captures`, `ficus_analyze`, `ficus_row`, `ficus_export`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Agent-supplied domains in the record command.** The person pastes the command into Terminal and it runs `sudo`. A domain like `x.com; rm -rf ~` or `$(id)` must be refused, not quoted. Test in Task 2.
2. **A capture that loads with no events or is not eslogger at all** (e.g. a cleaned file that is empty because the recording failed: the cleaner writes the file and key before the first event). The tool must return an error result naming the problem and the server must keep answering. Test in Task 3 and Task 5.
3. **The agent switching captures mid-conversation.** `ficus_row` for capture B after `ficus_analyze` on A must load B, and reveals on A must not appear in B's `agent-verdict.md`. Test in Task 3 and Task 4.
4. **Two exports in the same second** must not overwrite each other: the second folder gets ` 2` appended. Test in Task 4.
5. **An unknown or stale row key** (from another capture, or made up) must return an error that says to call `ficus_analyze` for keys, not throw out of the server. Test in Task 5.

---

### Task 1: Ficus paths and the cleaned-capture guard

**Files:**
- Create: `src/mcp/home.ts`
- Test: `test/mcp-home.test.ts`

**Interfaces:**
- Produces:
  - `interface FicusPaths { home: string; captures: string; keys: string; bin: string; exportRoot: string }`
  - `function ficusPaths(env?: NodeJS.ProcessEnv): FicusPaths` (default `process.env`)
  - `class CaptureRefused extends Error`
  - `const STILL_WRITING_MS = 10_000`
  - `function cleanedCapturePath(p: FicusPaths, name: string, now?: number): string` (absolute path, or throws `CaptureRefused`)
  - `interface CaptureEntry { name: string; size: number; modified: string; hasKey: boolean; stillWriting: boolean }`
  - `function listCaptures(p: FicusPaths, now?: number): CaptureEntry[]` (newest first; `[]` when `captures/` is missing)

- [ ] **Step 1: Write the failing tests** in `test/mcp-home.test.ts`, each with a fresh `fs.mkdtempSync` folder as `FICUS_HOME`:

```ts
test('ficusPaths defaults and overrides', () => {
  const p = ficusPaths({ HOME: '/Users/x' } as NodeJS.ProcessEnv);
  expect(p.home).toBe('/Users/x/Library/Application Support/Ficus');
  expect(p.captures).toBe('/Users/x/Library/Application Support/Ficus/captures');
  expect(p.keys).toBe('/Users/x/Library/Application Support/Ficus/keys');
  expect(p.bin).toBe('/Users/x/Library/Application Support/Ficus/bin');
  expect(p.exportRoot).toBe('/Users/x/Desktop');
  expect(ficusPaths({ HOME: '/Users/x', FICUS_HOME: '/t/f', FICUS_EXPORT_DIR: '/t/d' } as NodeJS.ProcessEnv))
    .toMatchObject({ home: '/t/f', captures: '/t/f/captures', exportRoot: '/t/d' });
});
test('a capture with its key, written over 10 s ago, is accepted', /* write captures/a.cleaned.jsonl and keys/a.cleaned.jsonl.key.tsv; now = mtime + 10_001 → returns path.join(captures, name) */);
test.each(['../a.jsonl', 'sub/a.jsonl', '.', '..', '', '/etc/passwd'])('name %j is refused', /* expect(() => cleanedCapturePath(p, n)).toThrow(CaptureRefused) */);
test('a capture without its key is refused, and the message says to record with ficus_record_command', /* toThrow(/ficus_record_command/) */);
test('a capture modified less than 10 s ago is refused as still recording', /* now = mtime + 9_999 → toThrow(/still being recorded/) */);
test('a missing capture is refused', ...);
test('listCaptures: newest first, key and still-writing flags, ignores folders and key files', ...);
test('listCaptures on a missing captures folder is empty', ...);
```

- [ ] **Step 2: Run** `npx vitest run test/mcp-home.test.ts`. Expected: FAIL, cannot resolve `../src/mcp/home`.

- [ ] **Step 3: Implement `src/mcp/home.ts`.** `home` = `FICUS_HOME` or `${HOME}/Library/Application Support/Ficus`; `exportRoot` = `FICUS_EXPORT_DIR` or `${HOME}/Desktop`. Refusal messages, verbatim intent: no key → "…was not made by the Ficus cleaner (no key for it). Ask the person to record a new capture with the command from ficus_record_command. To clean a capture they already have, see the README section 'Cleaning a capture before it leaves the Mac'." Still writing → "…is still being recorded; wait until Terminal shows the summary." `listCaptures` lists only regular files not ending in `.key.tsv`.

- [ ] **Step 4: Run** `npx vitest run test/mcp-home.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit** `git add src/mcp/home.ts test/mcp-home.test.ts && git commit -m "feat(mcp): Ficus folder paths and the cleaned-capture guard"`

---

### Task 2: The record command

**Files:**
- Create: `src/mcp/record.ts`
- Test: `test/mcp-record.test.ts`

**Interfaces:**
- Consumes: `FicusPaths`, `ficusPaths` (Task 1).
- Produces:
  - `interface RecordCommand { command: string; capture: string; instructions: string[] }`
  - `function recordCommand(p: FicusPaths, scriptsDir: string, opts: { seconds?: number; domains?: string[] }, now?: Date): RecordCommand` (throws `RangeError` on bad input)
  - `const CLEANER_FILES = ['ficus-clean.sh', 'ficus-clean.jq'] as const`

- [ ] **Step 1: Write the failing tests** (temporary `FICUS_HOME`; `scriptsDir` = the repo's `scripts/`; `now = new Date(2026, 10, 17, 10, 30, 12)`):

```ts
test('the command records to captures/ with absolute quoted paths', () => {
  const r = recordCommand(p, SCRIPTS, { domains: ['example.com'] }, NOW);
  expect(r.capture).toBe('capture-2026-11-17-103012.cleaned.jsonl');
  expect(r.command).toBe(`"${p.bin}/ficus-clean.sh" record -o "${p.captures}/${r.capture}" -t 600 -D example.com`);
  expect(r.command).not.toContain('~');
});
test('the cleaner is copied to bin/, executable, and replaced when it differs', /* both CLEANER_FILES byte-equal to scripts/; .sh mode & 0o111; overwrite bin copy with junk, call again, equal again */);
test('captures/ is created', ...);
test.each([59, 1801, 1.5, NaN])('seconds %s is refused', s => expect(() => recordCommand(p, SCRIPTS, { seconds: s }, NOW)).toThrow(RangeError));
test.each(['x.com; rm -rf ~', '$(id)', '`id`', 'a b.com', '"x.com"', '-D', '', 'x'.repeat(254)])(
  'domain %j is refused', d => expect(() => recordCommand(p, SCRIPTS, { domains: [d] }, NOW)).toThrow(RangeError));
test('several domains each get -D', /* ['a.example', 'b-c.example.org'] → '… -t 600 -D a.example -D b-c.example.org' */);
test('instructions mention Terminal, the Mac password, Full Disk Access and waiting for the summary', ...);
```

- [ ] **Step 2: Run** `npx vitest run test/mcp-record.test.ts`. Expected: FAIL, module missing.

- [ ] **Step 3: Implement `src/mcp/record.ts`.** Domains must match `/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i`; seconds must be an integer from 60 to 1800. Copy `CLEANER_FILES` from `scriptsDir` to `p.bin` when missing or byte-different, `.sh` with mode `0o755`. Instructions (one string per step): open Terminal; paste the command; when Terminal asks for a password, type your Mac password (the Mac asks, not the agent); if it stops at once saying eslogger stopped before recording anything, give Terminal Full Disk Access in System Settings > Privacy & Security > Full Disk Access, then run it again; keep using the Mac normally until it stops after N minutes; tell the agent when Terminal shows the summary.

- [ ] **Step 4: Run** `npx vitest run test/mcp-record.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit** `git commit -m "feat(mcp): the record command, with the cleaner copied to a stable path"`

---

### Task 3: Workspace: load one capture, build reports, the analyze view, rows and reveals

**Files:**
- Create: `src/mcp/workspace.ts`
- Test: `test/mcp-workspace.test.ts`

**Interfaces:**
- Consumes: `FicusPaths`, `cleanedCapturePath`, `CaptureRefused` (Task 1); `loadCapture` (`src/ingest/load.ts`); `buildReport`, `Report`, `ReportRow` (`src/report/report.ts`); `CaptureRec`, `Session` (`src/session/store.ts`).
- Produces:
  - `const PAGE_SIZE = 40`
  - `interface AnalyzeRow { n: number; key: string; kind: ReportRow['kind']; name: string; severity: Severity | null; inFlaggedChain: boolean; reconBurst: boolean; path: string | null; signature: Signature | null; findings: { ruleId: string; severity: Severity; title: string; mitre: string[]; evidence: string; trait: boolean }[]; launchItems: { typeName: string; plistPath: string | null; executablePath: string | null }[] }`
  - `interface AnalyzeView { capture: { name: string; firstTime: string | null; lastTime: string | null; events: number; processes: number; schemaVersions: number[]; coverage: { id: string; level: 'warn' | 'info'; title: string; checks: string[] }[]; coverageDetail: Record<string, string> }; summary: { rows: number; bySeverity: Record<Severity, number>; contextOnly: Record<string, number> }; rows: AnalyzeRow[]; offset: number; truncated: { remaining: number; bySeverity: Record<Severity, number> } | null; rules: Record<string, string> }`
  - `class Workspace { constructor(paths: FicusPaths, now?: () => Date); load(name: string): Promise<LoadedCapture>; session(name: string): Pick<Session, 'id' | 'name'>; captureRec(name: string): Promise<CaptureRec>; report(name: string, redact: boolean): Promise<Report>; analyze(name: string, offset?: number, pageSize?: number): Promise<AnalyzeView>; row(name: string, key: string, reveal?: boolean): Promise<ReportRow>; revealed(name: string): string[] }`
  - `class UnknownRow extends Error`

- [ ] **Step 1: Write the failing tests.** A helper `stage(name)` copies `test/fixtures/synthetic-lab.jsonl` into a temp `captures/` with a stub key and an mtime 60 s in the past.

```ts
test('analyze matches the app: 17 rows, same order and severities as loadCapture', async () => {
  const v = await ws.analyze('lab.cleaned.jsonl');
  const cap = await loadCapture(new Blob([fs.readFileSync(fixture('synthetic-lab.jsonl'))]));
  expect(v.summary.rows).toBe(17);
  expect(v.rows.map(r => r.severity)).toEqual(/* buildReport(... redactArgs: true) rows sorted by n, mapped to severity */);
  expect(v.capture.events).toBe(111);
  expect(v.truncated).toBeNull();
});
test('nothing the agent sees by default holds the dscl password', async () => {
  const text = JSON.stringify(await ws.analyze(N)) + JSON.stringify(await Promise.all((await ws.analyze(N)).rows.map(r => ws.row(N, r.key))));
  expect(text).not.toContain('labpass-not-real');
});
test('reveal shows that one row unredacted and is remembered', async () => {
  const dscl = (await ws.analyze(N)).rows.find(r => r.name === 'dscl')!;
  expect(JSON.stringify(await ws.row(N, dscl.key, true))).toContain('labpass-not-real');
  expect(ws.revealed(N)).toEqual([dscl.key]);
  const other = (await ws.analyze(N)).rows.find(r => r.key !== dscl.key)!;
  expect(JSON.stringify(await ws.row(N, other.key))).not.toContain('labpass-not-real');
});
test('paging: pageSize 5 from offset 15 returns 2 rows; offset 0 says 12 remain with their severities', ...);
test('rules holds each explanation once, keyed by rule id', ...);
test('an unknown row key throws UnknownRow', ...);
test('the session is stable per capture and named self-check YYYY-MM-DD HH:MM', ...);
test('switching captures reloads, and reveals stay with their capture', /* stage a.cleaned.jsonl and b.cleaned.jsonl; reveal on a; row on b; revealed(b) == [] */);  // Review Focus 3
test('an empty cleaned capture is refused with the loader message', /* stage an empty file with key → rejects /No eslogger or Mac Monitor events/ */); // Review Focus 2
test('a refused capture rejects with CaptureRefused', ...);
```

- [ ] **Step 2: Run** `npx vitest run test/mcp-workspace.test.ts`. Expected: FAIL, module missing.

- [ ] **Step 3: Implement `src/mcp/workspace.ts`.** `load` resolves through `cleanedCapturePath`, reads with `fs.openAsBlob`, calls `loadCapture`, sets `fileName` to `name`, and keeps only the last capture loaded (same name → cached). `captureRec` mirrors `src/ui/session-context.tsx:313` (`flagged: cap.analysis.queue.length`), `sessionId` = `session(name).id`. `report(name, redact)` calls `buildReport({ session, capRecs: [rec], loaded: new Map([[fp, cap]]), verdicts: [], routineKeys: new Set() }, { redactArgs: redact, generated: now().toISOString() })`. `analyze` projects `report(name, true)`'s single capture: rows sorted by `n`; `path` and `signature` from the row's last image; `coverageDetail` maps note id → `detail`; `rules` maps each rule id in the page's findings → `explanation`. `row(name, key, reveal)` finds `key` in `report(name, reveal).captures[0].rows`, records the key in that capture's reveal list when `reveal` is true, and throws `UnknownRow` when absent.

- [ ] **Step 4: Run** `npx vitest run test/mcp-workspace.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit** `git commit -m "feat(mcp): a workspace that serves the redacted report, rows and consented reveals"`

---

### Task 4: The export folder

**Files:**
- Create: `src/mcp/export.ts`
- Test: `test/mcp-export.test.ts`

**Interfaces:**
- Consumes: `Workspace` (Task 3); `FicusPaths`, `cleanedCapturePath` (Task 1); `reportMarkdown` (`src/report/markdown.ts`); `reportFileName` (`src/report/report.ts`); `saveFileName`, `parseExport`, `SessionExport` (`src/session/export.ts`).
- Produces:
  - `interface ExportResult { folder: string; files: string[] }` (`files`: names, sorted)
  - `function writeExport(ws: Workspace, p: FicusPaths, name: string, opts: { mode: 'report' | 'full'; verdict: string; redact?: boolean }, now?: Date): Promise<ExportResult>`

- [ ] **Step 1: Write the failing tests.**

```ts
test('report mode: verdict, README and the two report files, no capture, no key', async () => {
  const r = await writeExport(ws, p, N, { mode: 'report', verdict: '# ALL GOOD' }, NOW);
  expect(path.basename(r.folder)).toBe('Ficus report 2026-11-17 103012');
  const s = ws.session(N);
  expect(r.files).toEqual(['README.txt', 'agent-verdict.md', reportFileName(s, 'json'), reportFileName(s, 'md')].sort());
});
test('full mode adds the capture and a session file that parseExport accepts', async () => {
  const r = await writeExport(ws, p, N, { mode: 'full', verdict: 'v' }, NOW);
  expect(r.files).toContain(N);
  expect(r.files).toContain(saveFileName(ws.session(N)));
  const data = parseExport(fs.readFileSync(path.join(r.folder, saveFileName(ws.session(N))), 'utf8'));
  expect(data.captures).toHaveLength(1);
  expect(data.verdicts).toEqual([]);
  expect(r.files.some(f => f.endsWith('.key.tsv'))).toBe(false);
});
test('the report files are unredacted by default and redacted with redact: true', /* .json contains 'labpass-not-real' by default; not with redact */);
test('the JSON report equals ws.report(N, false) apart from generated', ...);
test('agent-verdict.md holds the verdict, then the revealed rows or "none"', ...);
test('a second export in the same second goes to "… 2"', ...);   // Review Focus 4
test('reveals on another capture are not listed', ...);           // Review Focus 3
test('README.txt says the key stays on the Mac and the capture is pseudonymized', ...);
```

- [ ] **Step 2: Run** `npx vitest run test/mcp-export.test.ts`. Expected: FAIL, module missing.

- [ ] **Step 3: Implement `src/mcp/export.ts`.** Make the folder with `fs.mkdirSync(..., { recursive: false })`, retrying ` 2`, ` 3`… on `EEXIST`. Session file object: `{ format: 'ficus-session', version: 1, session: { ...ws.session(N), created, updated }, captures: [await ws.captureRec(N)], verdicts: [], routine: [], details: {} }`. `agent-verdict.md`: the verdict as given, a blank line, `## Shown to the agent with consent`, then one line per revealed key with the row's name, or `none`. The capture is copied with `fs.copyFileSync` from `cleanedCapturePath`.

- [ ] **Step 4: Run** `npx vitest run test/mcp-export.test.ts`. Expected: PASS.

- [ ] **Step 5: Commit** `git commit -m "feat(mcp): export the report or the full session to a Desktop folder"`

---

### Task 5: MCP server and tool registration

**Files:**
- Modify: `package.json` (add dependencies `@modelcontextprotocol/sdk@^1.32.2`, `zod@^4.6.7`)
- Create: `src/mcp/server.ts`
- Test: `test/mcp-server.test.ts`

**Interfaces:**
- Consumes: Tasks 1 to 4.
- Produces: `function createServer(opts: { paths: FicusPaths; scriptsDir: string; now?: () => Date }): McpServer`

- [ ] **Step 1: Install** `npm install @modelcontextprotocol/sdk@^1.32.2 zod@^4.6.7`. Expected: both in `dependencies`.

- [ ] **Step 2: Write the failing tests.** Connect a `Client` to `createServer(...)` through `InMemoryTransport.createLinkedPair()`; `call(name, args)` returns `JSON.parse(result.content[0].text)` or the error text.

```ts
test('lists exactly the five tools', async () => {
  expect((await client.listTools()).tools.map(t => t.name).sort()).toEqual(
    ['ficus_analyze', 'ficus_export', 'ficus_list_captures', 'ficus_record_command', 'ficus_row']);
});
test('ficus_row describes reveal as needing the person\'s yes in chat', /* inputSchema.properties.reveal.description matches /ask the person/i */);
test('ficus_export describes asking which mode first', ...);
test('record → list → analyze → row → export works end to end on the staged fixture', ...);
test('a refused capture is an error result, and the server still answers', /* isError true, text matches /ficus_record_command/, then listTools still works */); // Review Focus 2
test('an unknown row key is an error result that points to ficus_analyze', ...);   // Review Focus 5
test('a bad domain is an error result', ...);
test('no tool result in the end-to-end run contains labpass-not-real unless reveal was set', ...);
```

- [ ] **Step 3: Run** `npx vitest run test/mcp-server.test.ts`. Expected: FAIL, module missing.

- [ ] **Step 4: Implement `src/mcp/server.ts`** with `McpServer` and `registerTool`, input schemas in zod matching the spec's Tools section. Each handler returns `{ content: [{ type: 'text', text: JSON.stringify(result) }] }`; `CaptureRefused`, `UnknownRow`, `RangeError` and loader errors become `{ isError: true, content: [{ type: 'text', text: message }] }`. `UnknownRow`'s text: "No row <key> in <capture>. Call ficus_analyze for the row keys." Descriptions carry the rules the agent must follow: `ficus_record_command` says it never runs anything and the person runs it; `ficus_row.reveal` says ask the person in chat first, naming the program, and set it only after a yes; `ficus_export` says ask the person which mode first and tell them to read the report before sending; `ficus_analyze` says evidence is redacted and the rule title is the finding.

- [ ] **Step 5: Run** `npx vitest run test/mcp-server.test.ts`. Expected: PASS. Then `npx tsc --noEmit`. Expected: no errors.

- [ ] **Step 6: Commit** `git commit -m "feat(mcp): register the five Ficus tools with the MCP SDK"`

---

### Task 6: Build the server bundle and guard it

**Files:**
- Create: `src/mcp/main.ts`, `vite.mcp.config.ts`
- Modify: `package.json` (scripts), `.gitignore` (`dist-mcp/`)
- Test: `test/mcp-build.test.ts`

**Interfaces:**
- Consumes: `createServer` (Task 5), `ficusPaths` (Task 1).
- Produces: `dist-mcp/ficus-mcp.mjs`; npm scripts `build:mcp` and `pretest` = `vite build && npm run build:mcp`.

- [ ] **Step 1: Write the failing test** `test/mcp-build.test.ts`:

```ts
const BUNDLE = 'dist-mcp/ficus-mcp.mjs';
test('the bundle opens no network and starts no process', () => {
  const js = fs.readFileSync(BUNDLE, 'utf8');
  for (const s of ['fetch(', 'node:http', 'node:https', 'node:net', 'node:dgram', 'node:child_process',
    "'http'", "'https'", "'net'", "'dgram'", "'child_process'", '"http"', '"https"', '"net"', '"dgram"', '"child_process"'])
    expect(js, s).not.toContain(s);
});
test('dist/ still holds only index.html', () => expect(fs.readdirSync('dist')).toEqual(['index.html']));
test('the bundle answers over stdio', async () => {
  // StdioClientTransport({ command: process.execPath, args: [BUNDLE], env: { FICUS_HOME: tmp, FICUS_EXPORT_DIR: tmp2, HOME: tmp } })
  // listTools → five names
});
```

Note: the stdio test's *client* spawns the bundle; the grep is over the bundle only, so the SDK's client-side `child_process` is not in it. If the SDK's server-side code turns out to reference `fetch(` or a forbidden module (it should not for stdio), stop and report: do not loosen the test.

- [ ] **Step 2: Run** `npx vitest run test/mcp-build.test.ts`. Expected: FAIL, no `dist-mcp/ficus-mcp.mjs`.

- [ ] **Step 3: Implement.** `src/mcp/main.ts`: `createServer({ paths: ficusPaths(), scriptsDir: fileURLToPath(new URL('../scripts/', import.meta.url)) })` connected to `StdioServerTransport`. (In the repo the bundle sits in `dist-mcp/`, so `../scripts/` is the repo's; Task 7's bundle keeps the same layout.) `vite.mcp.config.ts`: `build.ssr: 'src/mcp/main.ts'`, `outDir: 'dist-mcp'`, `emptyOutDir: true`, `target: 'node20'`, output `entryFileNames: 'ficus-mcp.mjs'`, `ssr.noExternal: true` (bundle the SDK and zod). Scripts: `"build:mcp": "vite build -c vite.mcp.config.ts"`, `"pretest": "vite build && npm run build:mcp"`.

- [ ] **Step 4: Run** `npm test`. Expected: the whole suite passes, including `build.test.ts` and `mcp-build.test.ts`.

- [ ] **Step 5: Commit** `git commit -m "build(mcp): bundle the server to dist-mcp/ficus-mcp.mjs and test that it stays offline"`

---

### Task 7: Claude Desktop extension and README

**Files:**
- Create: `mcp/manifest.json`, `scripts/pack-mcp.mjs`
- Modify: `package.json` (devDependency `@anthropic-ai/mcpb@^2.1.2`, script `pack:mcp`), `README.md`
- Test: `test/mcp-pack.test.ts`

**Interfaces:**
- Consumes: `dist-mcp/ficus-mcp.mjs` (Task 6), `scripts/ficus-clean.sh`, `scripts/ficus-clean.jq`.
- Produces: `dist-mcp/ficus.mcpb`; staging layout `dist-mcp/bundle/{manifest.json, server/ficus-mcp.mjs, scripts/ficus-clean.sh, scripts/ficus-clean.jq}`.

- [ ] **Step 1: Write the failing test** `test/mcp-pack.test.ts` (runs `scripts/pack-mcp.mjs` once in `beforeAll` with `--stage-only`, which builds `dist-mcp/bundle/` without zipping):

```ts
test('the manifest names the server entry and the five tools', () => {
  const m = JSON.parse(fs.readFileSync('mcp/manifest.json', 'utf8'));
  expect(m.server.entry_point).toBe('server/ficus-mcp.mjs');
  expect(m.tools.map((t: { name: string }) => t.name).sort()).toEqual([/* the five names */]);
});
test('the staged bundle has the server and both cleaner files, byte-equal', ...);
test('the staged server finds the cleaner at ../scripts/', /* fs.existsSync(path.join('dist-mcp/bundle/server', '../scripts/ficus-clean.sh')) */);
```

- [ ] **Step 2: Run** `npx vitest run test/mcp-pack.test.ts`. Expected: FAIL.

- [ ] **Step 3: Implement.** Create `mcp/manifest.json` with `npx @anthropic-ai/mcpb init` and keep: `name` `ficus`, `display_name` `Ficus`, `server.type` `node`, `server.entry_point` `server/ficus-mcp.mjs`, `server.mcp_config` `{ "command": "node", "args": ["${__dirname}/server/ficus-mcp.mjs"] }`, `compatibility.platforms` `["darwin"]`, and the five tools with one-line descriptions. `scripts/pack-mcp.mjs` copies the files into `dist-mcp/bundle/`, then (unless `--stage-only`) runs the mcpb packer to write `dist-mcp/ficus.mcpb`. Script: `"pack:mcp": "npm run build:mcp && node scripts/pack-mcp.mjs"`.

- [ ] **Step 4: Run** `npx vitest run test/mcp-pack.test.ts`, then `npm run pack:mcp`. Expected: PASS, and `dist-mcp/ficus.mcpb` exists.

- [ ] **Step 5: Write the README section** "Using Ficus from an AI agent (MCP)", after "Report for security": what the server is for (the "what ran" evidence beside a snapshot check), installing (`npm run pack:mcp`, then open `dist-mcp/ficus.mcpb` in Claude Desktop; or `npm run build:mcp` and add `node <repo>/dist-mcp/ficus-mcp.mjs` as a stdio server in other hosts), the five tools in one line each, the safety rules (no sudo from the agent; only captures it recorded; command lines redacted unless the person says yes; never the key), the export modes, and the suggested lines for the "Am I Pwned?" prompt from the spec's "The prompt side". `test/readme.test.ts` already checks the README; run it.

- [ ] **Step 6: Run** `npm test`. Expected: all pass.

- [ ] **Step 7: Commit** `git commit -m "feat(mcp): pack a Claude Desktop extension, and document the MCP server"`
