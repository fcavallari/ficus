# Ficus

A macOS process tree viewer for `eslogger` captures that follows every root, not just the parent PID.

Drop a capture onto the page. Ficus rebuilds the process tree, flags suspicious processes with plain-language, MITRE-tagged findings, and gives you a queue to mark each one suspicious or benign. It also loads traces exported from Mac Monitor 3.0 or later.

> **Authorized use only.** Record only Macs you own or are authorized to investigate. A raw capture holds account names, paths, command lines, environment variables and sometimes secrets. [Clean it](docs/cleaning-captures.md) before it leaves the Mac, and never send the cleaner's key file with it.

## Quickstart

Requirements:

- To record: macOS 13 or later (`eslogger` ships with it), `sudo` rights, and Full Disk Access for the terminal. The cleaner needs macOS 15 or later.
- To build: Node and npm. CI builds with Node 24.

**1. Open Ficus.** Use the hosted copy at **https://fcavallari.github.io/ficus/**, or build it yourself:

```bash
npm ci
npm run build   # writes dist/index.html, one self-contained file
npm run serve   # http://localhost:4173
```

For a sensitive capture, prefer the local build: you then run the code you checked out. The hosted copy keeps its sessions under an origin that every GitHub Pages project of that account shares ([details](docs/sessions-and-storage.md)).

**2. Get a capture.** A safe sample that shows every rule, with an answer key beside it:

```bash
scripts/ficus-lab.sh synthetic   # writes scratch/ficus-lab-synthetic.jsonl
```

Or record the Mac you are investigating, and stop with Ctrl-C:

```bash
sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

**3. Drop the `.jsonl` file into a session** and work through the Triage queue.

## How it works

Ficus is passive and offline: it only reads a capture file, and the page ships with a Content-Security-Policy of `connect-src 'none'`, so it cannot send a capture anywhere. A worker streams the file and builds a process model with three kinds of parent (original, current, responsible). The rules are data, each with a severity, an explanation and MITRE ATT&CK IDs. Verdicts are kept per session in the browser's IndexedDB.

## Documentation

| Topic | Page |
|---|---|
| Recording a capture, Mac Monitor traces | [Capturing](docs/capturing.md), [Mac Monitor traces](docs/mac-monitor.md) |
| Cleaning a capture before sharing it | [Cleaning a capture](docs/cleaning-captures.md) |
| Triage, Tree, Timeline, sessions, reports | [Using Ficus](docs/using-ficus.md), [What the queue means](docs/triage-queue.md) |
| Rules and indicators | [Rules](docs/rules.md) |
| Hosted copy, `file://`, storage, browser differences | [Running Ficus, sessions and storage](docs/sessions-and-storage.md) |
| Using Ficus from an AI agent | [MCP server](docs/mcp.md) |
| A capture to learn on | [Learning lab](docs/learning-lab.md) |
| How it is built, how fast it is, how to test it | [Architecture](docs/architecture.md), [Performance](docs/performance.md), [Development and tests](docs/development.md) |

Ficus is named after the gameleira, a Brazilian fig whose aerial roots become new trunks. [Why “Ficus”?](docs/name.md)

## License

MIT, see [LICENSE](LICENSE).
