# Using Ficus from an AI agent (MCP)

A snapshot check of a Mac (what is installed, listening and set to start now) cannot show what *ran*: a `curl | bash`, a fake password dialog, a launch agent written by a shell and then removed. An `eslogger` recording can, and Ficus reads it. The MCP server lets an AI agent, such as the one behind a periodic "Am I Pwned?" check, ask for a recording, read Ficus's findings on it, and package the result for Security Ops. It uses the same rules and report as the app, so the agent and the security team see the same findings for the same capture. It is a stdio server and runs only on the Mac, with no network access and no child processes; the page itself is unchanged.

## Installing

For Claude Desktop, which brings its own Node:

```bash
npm install
npm run pack:mcp     # writes dist-mcp/ficus.mcpb
```

Then open `dist-mcp/ficus.mcpb` in Claude Desktop and install it. The extension carries the cleaner (`scripts/ficus-clean.sh` and `.jq`). `npm test` rebuilds `dist-mcp/` and empties it first, so it removes `ficus.mcpb`: run `npm run pack:mcp` again afterwards.

For another host (Claude Code, Cursor and others), run `npm run build:mcp` and add `node <repo>/dist-mcp/ficus-mcp.mjs` as a stdio server in the host's settings. That needs Node 20 or later, and the `scripts/` folder must stay beside `dist-mcp/`, because the server looks for the cleaner at `../scripts/` from the bundle.

Ficus keeps its files in `~/Library/Application Support/Ficus/`: `captures/` for recordings, `keys/` for the cleaner's keys, and `bin/` for a copy of the cleaner, so the command handed out has a stable path. The server reads two environment variables when it starts. `FICUS_HOME` sets another Ficus folder: `captures/`, `keys/` and `bin/` all move there, and the recording command it hands out then starts with `FICUS_CLEAN_KEY_DIR="<FICUS_HOME>/keys"` so the cleaner writes its key where the server looks for it (without `FICUS_HOME` the command is unchanged). The list of rows shown with consent is kept in memory, so it covers only what happened since the server started. `FICUS_EXPORT_DIR` sets another place for exports instead of `~/Desktop`; the first write to the Desktop can make macOS ask for permission, and if it is refused the tool says so.

## The tools

- `ficus_record_command`: returns the one line to paste into Terminal to record a cleaned capture (`seconds`, 60 to 1800, default 600; optional `domains`), with the steps to relay. It never runs the command. `domains` is for the person's *own* company domains: the cleaner replaces every host under them with a placeholder (`host1.internal.invalid`), so a domain the agent wants to find in the capture must never be passed, or it would be hidden. The recording needs macOS 15 or later, and a recording that is stopped early or fails needs a new command, since the same command refuses to run again once its key exists.
- `ficus_list_captures`: lists the cleaned captures, newest first, with their size, time, whether the key exists and whether the file is still being written.
- `ficus_analyze`: a compact view of one capture's redacted report: time span, counts, coverage notes, a summary by severity, and the flagged rows, 40 at a time (`offset` for the next page), with each rule's explanation once.
- `ficus_row`: one row in full (images, ancestry, responsible process, file operations, launch items). Redacted unless `reveal` is true.
- `ficus_export`: writes a verdict and the report to a new folder on the Desktop (see below) and returns its path and file list, never the contents. The agent is told to offer the redacted version (`redact: true`) first.

The descriptions of `ficus_analyze`, `ficus_row` and `ficus_export` also tell the agent not to open the capture or export files itself, since reading them directly would bypass the record of what it was shown.

## What the server will not do

- It never runs `sudo` and never asks for a password. The person pastes the recording command into Terminal, and it is Terminal that asks for the Mac password. Terminal needs Full Disk Access.
- It reads only captures that the cleaner recorded into `captures/`: a plain file name, directly in that folder, with its key beside it, and not modified in the last 10 seconds. A raw capture is refused, and there is no override. To clean a capture you already have, see [Cleaning a capture before it leaves the Mac](cleaning-captures.md).
- Everything the agent sees is redacted: every argument after the program name is replaced, in command lines, in the evidence text, in ancestry and in launch items. Program paths, process names and file paths stay, since they are the evidence. `ficus_row` with `reveal: true` returns one row with its cleaned command lines. Its description tells the agent to ask the person first, naming the program. The server cannot check the answer, so the chat is the record, and each reveal is listed in the export.
- It never returns environment variables, and it never opens the key file, only checks that it exists.
- It writes only under the Ficus folder and the export folder.

## Exporting for Security Ops

`ficus_export` asks the agent to put the choice to the person, then writes `Ficus report <date> <time>/` on the Desktop. Both modes hold:

- `agent-verdict.md`: first the rows shown to the agent with consent (or "none recorded since the Ficus server started"), written by the server, then the agent's verdict.
- `<session>.<hash>.ficus-report.md` and `.json`: the same report as Report for security in the app. It has the cleaned command lines unless the person asked for `redact`, since the files go to the security team and not to the agent.
- `README.txt`: what each file is, that the capture is pseudonymized and not anonymous, and to read the report before sending.

The **full** mode adds the cleaned capture and a `<session>.<hash>.ficus-session.json`, so Security Ops can import the session on Ficus's home page, drop the capture in and see the same tree. The key never leaves the Mac in either mode. The person reads the report and attaches the folder to their own message.

## Lines for the "Am I Pwned?" prompt

The prompt is kept outside this repository. These lines can be added to it; they apply only when the Ficus tools are present:

```text
If the Ficus tools are available, use them for what ran, not just what is installed:
- Offer a 10-minute recording with ficus_record_command. Tell the person to keep working normally.
- When they say it is done, run ficus_analyze and add Ficus's findings to the findings table, with the rule id as the evidence.
- Ask the person before revealing any command line. Name the program. Use ficus_row with reveal only after a yes.
- Do not open the capture or export files yourself; use the Ficus tools.
- At the end, offer ficus_export, offer the redacted version first, and ask which mode they want, report or full.
```
