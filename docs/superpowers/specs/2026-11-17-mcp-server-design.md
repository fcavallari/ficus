# Ficus MCP server: give an AI agent the "what ran" evidence

*Revised 2026-11-17 after the Report for security (`src/report/`, PR #17) and the rename to Ficus (PR #18) landed. The decisions are unchanged; the export and the redaction now reuse the report module instead of defining their own.*

## Intent

People at the company run a periodic "Am I Pwned?" check: they paste a standard prompt into Claude (or another agent), the agent inspects the Mac read-only, and it answers with a one-line verdict and a short findings table. Anything worrying goes to Security Ops. The companion `mac-triage.sh` gives the agent a snapshot: what is installed, listening and set to start right now.

A snapshot cannot show what *ran*: a `curl | bash`, a fake password dialog, a launch agent written by a shell and then removed. Ficus can, from an `eslogger` recording. This server lets the agent ask for a recording, read Ficus's findings on it, and package the result for Security Ops, so the verdict rests on behaviour as well as state.

The person running the check is usually not a security specialist. The agent explains; Ficus supplies the evidence. Security Ops receives either the report or the full session, at the person's choice.

## Goals

- An MCP server (stdio) that any MCP-capable agent can use: Claude Desktop, Claude Code, Cursor and others.
- It reuses Ficus's model, rules and report (`src/model`, `src/rules`, `src/report`), so the agent and Security Ops see exactly the findings and the report the web app produces for the same capture.
- The agent can: get the exact command to record a cleaned capture, list the captures it can read, analyze one, look at one flagged row in detail, and export for Security Ops.
- Export has two modes the person chooses between:
  - **report**: the agent's verdict plus the Ficus report (`.ficus-report.md` and `.ficus-report.json`, the same files the app's Report for security writes).
  - **full**: the report, plus the cleaned capture and a session file Ficus imports, so Security Ops can open the same tree in the app.
- A regular user can install it on Claude Desktop without installing Node or anything else.

## Non-goals

- Replacing `mac-triage.sh` or the "Am I Pwned?" prompt. The server is one more source the prompt calls; the snapshot checks stay in the script.
- Talking to the Ficus web app. The page keeps `connect-src 'none'` and stays sealed; the server writes files the page imports, nothing more.
- Reading verdicts from a browser session. Verdicts in IndexedDB stay in the browser. The server's report has no verdicts: nobody has triaged; the agent's view goes in its own file.
- Changing the `ficus-report` or `ficus-session` formats.
- Sending anything anywhere. Export writes files on the Mac; the person attaches them to their message to Security Ops.
- A remote (HTTP) transport. It would make the server a network listener on the investigated Mac.
- Cleaning a raw capture the person already has (see Telling a cleaned capture apart).
- Windows or Linux. `eslogger` is macOS only.

## Anti-goals (a failure even if it works)

- The agent ever running `sudo`, or the server asking for a password. This is ground rule 3 of the prompt ("No sudo from you").
- Raw capture content reaching the agent: uncleaned paths, names, environment variables, or anything from the key file. Whatever a tool returns is sent to the AI vendor; only cleaned data may be in it.
- Command lines reaching the agent without the person's yes. A recording of every command run is close to shell history, which the prompt puts off limits, and the cleaner can miss a password passed by position.
- The key file leaving the Mac, in either export mode.
- Findings that differ from what the web app shows for the same capture: the same rows, rule ids, severities and queue status.
- The server making any network connection or starting any process.
- Tool output so large it buries the verdict. The prompt says "Keep it short".

## Constraints

- Engine and report code are shared with the browser build. Nothing under `src/model`, `src/rules`, `src/report` or the parts of `src/ui` they import (`triage-model.ts`) may start depending on Node, and the server must not fork them.
- The cleaner deliberately puts no "cleaned" mark inside a capture (an extra line would count as unreadable in the viewer; see the capture-cleaner design). The server has to tell a cleaned capture apart some other way.
- `ficus-clean.sh record` needs a terminal: it asks for the person's password once (`sudo -v`), and the terminal needs Full Disk Access. An MCP server started by an agent host has neither.
- Claude Desktop extensions (`.mcpb`) run on the Node that Claude Desktop bundles. Other hosts need Node installed (the repo's tests use Node 24).
- `test/build.test.ts` requires `dist/` to hold only `index.html`, so the server's build output goes elsewhere.

## Approaches

1. **TypeScript MCP server in this repo** (picked). A new entry point imports the shared code and is bundled into one JavaScript file by Vite, like the app. Same rules and report everywhere, one place to change them. Shipped as a Claude Desktop extension and as a plain `node` script. Cost: the MCP SDK becomes the first dependency outside the browser app, and there is a second build target.
2. **A command-line report, no MCP.** `ficus report capture.cleaned.jsonl` prints findings; the prompt tells the agent or the person to run it. Smallest, works even in a chat with no shell, but no export step, no follow-up questions about one row without re-running, and not what was asked. The picked design keeps its logic in plain functions, so this command can be added later at little cost.
3. **A Python MCP server.** Rejected: the rules and the report would be rewritten and the copies would drift.

## Design

### Where things live

- Code: `src/mcp/`.
  - `home.ts`: the Ficus folder layout, the cleaned-capture check, file-name validation.
  - `view.ts`: plain functions from a loaded capture to what each tool returns, and the export writer. No MCP SDK types, so a CLI can reuse them.
  - `server.ts`: tool registration with the MCP SDK; `main.ts`: stdio entry point.
- Build: a second Vite build in library/SSR mode producing `dist-mcp/ficus-mcp.mjs`, a single ES module for Node with `@modelcontextprotocol/sdk` and `zod` bundled in. `npm run build:mcp`. `dist-mcp/` is git-ignored.
- Extension: `mcp/manifest.json` plus a pack step producing `dist-mcp/ficus.mcpb`, which also carries `scripts/ficus-clean.sh` and `scripts/ficus-clean.jq`.
- Ficus's own folder on the Mac: `~/Library/Application Support/Ficus/`. The cleaner already keeps keys in `keys/`. The server adds `captures/` (where recordings go) and `bin/` (a copy of the cleaner, so the command it hands out has a stable path rather than one inside the extension's install folder). For tests, `FICUS_HOME` overrides the folder (my call; the cleaner has `FICUS_CLEAN_KEY_DIR` for the same reason).

### Telling a cleaned capture apart

The server reads a capture only if all hold:

1. The `capture` argument is a plain file name: no `/`, not `.` or `..`.
2. The file is directly inside `captures/`.
3. The cleaner's key for it exists: `keys/<file name>.key.tsv` (the cleaner's default key path for an output file).
4. It was not modified in the last 10 seconds. Its key exists from the first second of recording, so the key check alone would let a half-written file through.

Anything else is refused with a message telling the agent to have the person make a new recording with the command from `ficus_record_command`. There is no override parameter: an agent cannot argue its way past it. This is a guard against mistakes (an agent handed a raw `capture.jsonl`), not proof against someone faking a key.

The server never opens the key file, beyond checking that it exists.

Cleaning a raw capture the person already has is out of scope (my call): the command would need the raw file's path, which passes the account's real name and folder names through the agent, and someone with a raw capture is past the self-check stage. The refusal message points to the README's cleaning section for that case.

### The report behind every tool

The server loads a capture with the same code path as the app (`loadCapture` from `src/ingest/load.ts`, given the file as a Blob from `fs.openAsBlob`), then builds a report with `buildReport` from `src/report/report.ts`:

- `session`: a session made up for this run: a random id and the name `self-check <local date-time>`.
- `capRecs`: one `CaptureRec` for the loaded capture (fingerprint, file name, size, events, processes, flagged rows).
- `verdicts`: none. `routineKeys`: none.
- `opts.redactArgs`: `true` for anything returned to the agent; see below.

The loaded capture is kept in memory, one at a time, so follow-up calls do not re-parse. There is no size cap, as in the app (my call; the record command's 30-minute maximum keeps its own captures around 375 MB, under the 516 MB the README measured loading).

### Command lines (decided: redact by default, reveal one row on consent)

Every tool output comes from a report built with `redactArgs: true`. The report module already guarantees that a redacted report holds no argument after `argv[0]` anywhere: command lines, evidence text (it strips the arguments out of the evidence and keeps the rest), ancestry, launch items, paths that came from arguments. Program paths, process names, working directories, file-event paths and launch-item paths stay, as they are evidence, and they are cleaned paths.

- `ficus_row` takes `reveal: true` to return that one row from a report built with `redactArgs: false`: its cleaned command lines and full evidence. The parameter's description tells the agent to ask the person in chat first, naming the program, and to call with `reveal` only after a yes. The server cannot verify that yes; the transcript is the record, as in the prompt's audit rule.
- The server remembers which rows were revealed during this run. The export's `agent-verdict.md` lists them under "Shown to the agent with consent", so a Security Ops reviewer can check the transcript against it.
- No tool returns environment variables, ever. (The report never includes them.)

### Tools

All tool output is JSON text.

**`ficus_record_command`** `{ seconds?: number (default 600, 60 to 1800), domains?: string[] }`
Copies the cleaner to `bin/` if missing or different, makes `captures/` if missing, picks an output name `capture-<local date-time to the second>.cleaned.jsonl` (so two commands handed out in the same minute do not collide on the cleaner's "key already exists" check), and returns:
- `command`: the exact line to paste in Terminal, with absolute paths (a `~` inside quotes would not expand): `"<home>/Library/Application Support/Ficus/bin/ficus-clean.sh" record -o "<home>/Library/Application Support/Ficus/captures/capture-2026-11-17-103012.cleaned.jsonl" -t 600 -D example.com`. The home path holds the account name and reaches the agent; the agent's host already knows it.
- `capture`: the file name to pass to the other tools afterwards.
- `instructions`: plain steps the agent relays: open Terminal, paste, type your Mac password when Terminal asks (it is the Mac asking, not the agent), keep using the Mac normally until it stops, Terminal needs Full Disk Access (and where to grant it), say when it has finished.

It never runs the command. 30 minutes maximum (my call): at about 85 events a second and 2.5 KB an event (the cleaner design's and README's figures), that is about 375 MB, a slow but workable first load inside Claude Desktop; an hour would be about 750 MB for little extra evidence.

**`ficus_list_captures`** `{}`
Captures in `captures/`, newest first: file name, size, modified time, whether its key exists, and whether it is still being written (modified in the last 10 seconds).

**`ficus_analyze`** `{ capture: string, offset?: number }`
A compact view of the redacted report, built for an agent writing a verdict:
- `capture`: time span, events, processes, schema versions, and the report's `coverage` notes (title and checks; `detail` once per note id).
- `summary`: the report's `summary.bySeverity` and `rows`, and its `contextOnly` counts per rule.
- `rows`: in the report's order (`n`), at most 40 from `offset` (default 0); `truncated` says how many remain, by severity. Each row: `n`, `key`, `kind`, `name`, `severity`, `inFlaggedChain`, `reconBurst`, the latest image's path and `signature`, its findings (`ruleId`, `severity`, `title`, `mitre`, `evidence` as redacted, `trait`), and its launch items' paths and type.
- `rules`: each rule id that appears, with its `explanation` once, rather than once per finding.

**`ficus_row`** `{ capture: string, key: string, reveal?: boolean }`
One report row in full (`ReportRow`: images, ancestry, responsible process, children count, file operations, launch items), redacted unless `reveal` (see Command lines).

**`ficus_export`** `{ capture: string, mode: "report" | "full", verdict: string, redact?: boolean }`
`verdict` is the agent's report in Markdown (the prompt's output format). Writes a new folder `~/Desktop/Ficus report <local date-time>/` and returns its path and file list (never file contents):
- Both modes:
  - `agent-verdict.md`: the agent's verdict as given, then "Shown to the agent with consent" (the revealed rows, or "none").
  - `<session>.<hash>.ficus-report.md` and `.json`: `reportMarkdown` and the JSON of `buildReport` for this capture, file names from `reportFileName`. Built with `redactArgs: redact`, default `false` (my call): the files go to Security Ops, not to the agent, and they need the cleaned command lines; the person can ask for the redacted version, as in the app.
  - `README.txt`: what each file is, that the capture is pseudonymized not anonymous, that the key stays on the Mac, and to read the report before sending.
- `full` adds the cleaned capture (copied, same file name) and `<session>.<hash>.ficus-session.json` (file name from `saveFileName`): a `ficus-session` v1 export of the made-up session with this capture's record, no verdicts, no routine marks, no details. It must pass `parseExport`. Security Ops imports it on Ficus's home page and drops the capture in.
- Never the key file, in either mode.

The tool's description tells the agent to ask the person which mode before calling it, and to tell them to read the report before sending.

### The prompt side

The "Am I Pwned?" prompt is maintained outside this repo. The README gets a section with the install steps and suggested lines for the prompt: if the Ficus tools are available, record for 10 minutes while the person works normally, analyze, include Ficus's findings in the findings table with their rule id as evidence, ask before revealing any command line, and offer the export at the end. Updating the shared prompt itself is the owner's step.

### Safety in the server itself

- No network and no child processes. A build test reads `dist-mcp/ficus-mcp.mjs` and fails on `fetch(`, `node:http`, `node:https`, `node:net`, `node:dgram`, `node:child_process` (and their unprefixed forms), as `build.test.ts` does for the page.
- File writes only under the Ficus folder and the new export folder on the Desktop.

## What's left to the builder

- How the second Vite build is configured, and how `.mcpb` packing runs (the official `@anthropic-ai/mcpb` packer or a small script).
- The manifest's metadata, icon and the Node version it declares.
- Exact field names of the `ficus_analyze` view, within the shape above.
- Tests: tool handlers through the SDK's in-memory transport, against `test/fixtures/synthetic-lab.jsonl` placed in a temporary `FICUS_HOME` with a stub key. They must cover: the refusal cases (no key, `/` or `..` in the name, still being written); that no `ficus_analyze` or unrevealed `ficus_row` output contains the fixture's `dscl -authonly` password `labpass-not-real`; that `reveal: true` shows it for that row only; the reveal list in `agent-verdict.md`; both export modes' file lists, no key file in either; the full export's session file passing `parseExport`; the bundle grep.
