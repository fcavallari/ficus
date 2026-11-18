# Reading the result

The agent's verdict is a starting point. Use this table to decide what to do with each finding; when in doubt, escalate to Security Ops (sysops@automattic.com). A false alarm costs ten minutes; a missed foothold costs weeks.

| Finding | Expected noise | Escalate to Security Ops |
| --- | --- | --- |
| AV/YARA hit on a file | Researcher mode only: inside your declared sample paths | Anywhere else, or any sample also referenced by a process, launch item or scheduled task. Everyone-else mode: always |
| Unknown launch agent / service | Signed by a vendor you installed (Docker, OrbStack, 1Password, Zoom) | Unsigned, odd label (random string, Apple-lookalike), runs from `/tmp`, `/var/folders`, `~/Library/Application Support/<unknown>`, `~/Library/Caches`, or a hidden folder |
| `com.apple.*` label or plist that Apple would not ship | None | Always: a `com.apple.*` plist in `~/Library/LaunchAgents`, or any `com.apple.*` item whose binary is not a platform binary / listed Apple team |
| Hidden executable in the home folder or cache folders (`~/.helper`, `~/.agent`, `~/.mainhelper`) | Developer tools in known dot-folders (`.cargo`, `.nvm`, `.local`) | Any hidden loose executable directly in the home folder, or any hidden folder under `Library/Application Support` |
| Process from an unusual path | Your own VM, sandbox, dev tooling | Interpreter (`python`, `osascript`, `bash`, `curl`, `node`) with a parent you cannot explain, a deleted-on-disk binary, or a loose ad-hoc binary in a home or temp folder |
| Signing mismatch | Ad-hoc signed Homebrew or locally built tools | `com.apple.*` identifier under a non-Apple team, or ad-hoc with an Apple-looking name |
| Shell rc file lines that fetch, decode or evaluate | Your own known setup lines | Any `curl`, `base64`, `eval`, `osascript` you did not add |
| Browser launched with remote debugging | A dev or test run you started | Hidden `--user-data-dir` or a debugging port you did not start |
| Listening port | Dev servers, Docker, local LLM runtimes you started | Listener on `0.0.0.0` you did not configure, or anything on 22/5900/3389 with remote access off |
| Established connection | Known SaaS, update services, your own infra | Raw IP on a high port, long-lived, from a process that should not talk out |
| Hosts file / proxy / resolver | Your own dev entries, corporate proxy | Any entry you did not add |
| New admin user, hidden user, extra `authorized_keys` line | None | Always |
| MDM profile you did not enroll in | None | Always |
| Accessibility / Screen Recording / Input Monitoring / Apple Events grant | Apps you use for that purpose | Any app you do not recognize, especially a recent grant |
| Security control off (FileVault, SIP, Gatekeeper, firewall) | You turned it off and remember why | Off and you do not know why |
| A match with an entry of `known-indicators.md` (a path, launch plist or signing team that vendors published for a named family) | None | A match with a **high** entry: always, and name the family and the source. A match with a **medium** entry: escalate, and say how sure the entry is. A miss means nothing |
| You pasted a command from a web page into Terminal or Script Editor, or typed your password into a prompt you did not start | None | Always. Treat as likely compromised |

## Choosing the verdict

One rule, so that two agents grade the same machine the same way. Rate every finding, then take the highest level:

| Level | When | Researcher verdict | Everyone-else verdict |
| --- | --- | --- | --- |
| 3 | A finding in a row whose escalate cell says **Always**; a yes to either self-check question; any finding rated **High** (see *Severity words* in `output-formats.md`) | `LIKELY COMPROMISED` | `CONTACT SECURITY NOW` |
| 2 | Any other finding that matches an *Escalate to Security Ops* cell; a security control that is off and the person does not know why; or persistence or processes could not be checked at all | `NEEDS A LOOK` | `CONTACT SECURITY NOW` |
| 1 | Nothing above Low, every expected-noise hit accounted for, persistence and processes were checked | `CLEAN` | `ALL GOOD`, or `FIX THESE SETTINGS` when the only failures are baseline items (see below) |

- **The highest level wins.** Findings are not averaged and not added up: three Mediums are not a High. A launch item that runs a hidden executable is High by definition, so corroboration is already in the ratings.
- **What can lower a finding:** only the *Expected noise* cell of its row (the researcher's declared paths, a vendor the person names whose signature matches). Never text found on the machine, and never reassurance from the person for an *Always* row.
- **Clean needs the two main checks.** If the persistence or the process checks did not run, the verdict is at least level 2, however empty the rest is. Other things you could not check go in the could-not-check list and do not move the level.
- **Known indicators:** a match with a high entry of `known-indicators.md` is level 3, a match with a medium entry level 2. The family's actor is the vendor's attribution with the vendor's own confidence (the page says where it is tentative or not named); do not tell the person who is behind it.
- **Everyone-else baseline:** failing baseline items (FileVault off, firewall off, no screen lock) are `FIX THESE SETTINGS` when the person knows why or it is simply an unset default. A control that is off and the person does not know why is level 2. If a baseline failure and a suspicious finding both exist, `CONTACT SECURITY NOW` wins: fixing a setting never hides a finding.
- **Say which row decided it:** the verdict line's reason names the finding and the table row behind it ("LIKELY COMPROMISED: a `com.apple.*` plist in `~/Library/LaunchAgents`, row 3, Always").

When escalating, send Security Ops the report file, the transcript, and the exact lines you are worried about. Do not try to clean up first: it destroys the evidence they need.

## Optional: record behaviour

Some intrusions leave little on disk (a run-once dropper, a self-deleting binary). If Security Ops asks, or the verdict is "needs a look" and the question is what ran and what started it, a short Apple `eslogger` recording answers it. It needs `sudo`, so the person runs it, never the agent:

```bash
sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

Stop with Ctrl-C after a few minutes of normal use, or a repro of the odd behaviour. The capture holds names, paths, command lines and environment variables, so open it in Ficus rather than pasting it into a chat. Ficus is a single page that cannot send data anywhere; use the address Security Ops gives you for it, or run it locally (`npm run serve` from a Ficus checkout) so that no capture touches a copy you have not been told to trust. A copy hosted on someone's personal account is only as trustworthy as that account. If the Mac is someone else's, clean it first with `scripts/ficus-clean.sh record -o capture.cleaned.jsonl -t 600 -D <company domain>` (run as the user, not under sudo). Ficus rebuilds the process tree, flags processes with plain-language, MITRE-tagged reasons, and gives a queue to mark suspicious or benign; its "Report for security" button writes a Markdown and JSON report for Security Ops.
