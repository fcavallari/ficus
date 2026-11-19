# Ficus malware lab

Runs macOS malware in a throwaway Tart VM on a fake internet and records `eslogger` for it. Design:
`docs/superpowers/specs/2026-11-18-malware-lab-vm-design.md`. Plan: `docs/superpowers/plans/2026-11-18-malware-lab-vm.md`.
Authorized use only: your own lab, your own Mac. Never extract or run samples on the host.

## What exists now

| File | What it does |
|---|---|
| `guest-setup.sh` | Run once inside the golden guest: Rosetta, UTC, no sleep, no Spotlight indexing, no auto-updates, fake bait, `/etc/lab-golden-image`. |
| `gateway-setup.sh` | Run once inside the Debian gateway (on Tart's normal NAT, it needs apt): makes it `10.66.0.1/24` with DHCP, DNS for every name, INetSim, redirects and a packet capture. |
| `lab-net.py` | Starts a gateway VM and a sample VM joined by a private socket-pair cable (`tart run --net-fd`). The host is not on that network. |
| `check-isolation.sh` | Proves the sample VM reaches only the gateway. Run before any sample. |
| `lib.sh`, `events.txt` | Shared shell functions (data folder, slugs, sample URL, run ids, name checks) and the list of eslogger events to record. |
| `fetch-sample.sh` | Downloads one sample zip from objective-see/malware into `$FICUS_LAB_DATA/samples/` and adds a row (family, zip, sha256, recipe, window) to `manifest.tsv`. Never extracts it. |
| `lab-run.sh` | The one-command run: clone both VMs, cable, isolation check, eslogger streaming to the host, unzip in the guest, launch by recipe, wait, collect post-state and pcap, delete the clones. Writes `runs/<name>/<run-id>/`. |
| `guest-collect.sh` | Runs in the guest after a run: BTM items, launch agent and daemon folders, crontabs, process list. |
| `guest-benign.sh` | Runs in the guest for `lab-run.sh --baseline benign`: ordinary activity (recon, developer tools, files, zip and tar, a curl download, a preference, an SSH key, an empty package install, an app, launchctl, Python). Nothing in it is an attack. |
| `summarize-core.ts`, `summarize-cli.ts`, `expected/` | Runs Ficus's own model and rules over a capture, lists the findings, and compares them with the behaviors public reports describe (`expected/<Family>.tsv`) into a `gap.md`: hit, miss, gap, review. See `expected/README.md`. |

## The images

- `lab-gold`: the golden macOS guest (macOS 26, user `admin`). Configured, shut down, never booted again. `lab-gold-backup` is a spare copy.
- `lab-gw`: the gateway (Debian 13 from `ghcr.io/cirruslabs/debian:latest`, user `admin`). Same rule.
- Every run clones both (`tart clone lab-gold run-X`, `tart clone lab-gw gw-X`) and deletes the clones afterwards. Tart has no snapshot command; a stopped VM is the snapshot.
- To change an image: clone it, boot and edit the clone, shut it down *gracefully* (see below), then swap names with `tart rename`.

## Things learned the hard way (2026-11-19)

- **Shut the gateway down gracefully.** `tart stop` straight after running `gateway-setup.sh` left the new config files at 0 bytes (unflushed). Use `tart exec lab-gw sudo systemctl poweroff` and wait for `tart list` to say `stopped`.
- **`tart exec` starts commands with a minimal PATH** (no `/sbin`). Use full paths or set `PATH=/usr/bin:/bin:/usr/sbin:/sbin`.
- **The gateway must not redirect DHCP.** UDP 67-68 is exempted before the catch-all that sends everything else to INetSim's dummy service.
- **INetSim 1.3.2's DNS service is broken on Debian 13** (it calls `Net::DNS::Nameserver->main_loop`, which no longer exists). dnsmasq answers DNS: `address=/#/10.66.0.1`.
- **A virtiofs shared folder was not writable from the Linux guest**, so there are no shared folders. The harness reads `/var/lib/lab/gateway.pcap` out of the gateway with `tart exec`.
- **Boot times:** a macOS clone is SSH- and agent-ready in about 12 s; the gateway is ready in about 3 s once its network config is static.
- **Capture volume:** `write` plus unmodified `close` were 90% of a 77,000-event, 156 MB capture of 14 seconds of a booting guest. The harness drops `write` and keeps only `close` events with `modified` true.
- **Full Disk Access for `eslogger`:** `sudo eslogger` worked both over SSH and through `tart exec` on the golden image.

## Trying the network by hand

```bash
tart clone lab-gold g1 && tart clone lab-gw w1
python3 lab/lab-net.py --gateway w1 --guest g1 &      # prints READY
lab/check-isolation.sh g1                            # expect: isolation ok
tart exec w1 /bin/sh -c 'sudo cat /var/lib/lab/gateway.pcap' > gateway.pcap
kill %1; tart delete g1; tart delete w1
```

## A run, by hand

```bash
lab/fetch-sample.sh AtomicStealer          # a live sample: only the ones you mean to run
lab/lab-run.sh --manual AtomicStealer      # window open, you launch it by hand, Enter to finish
lab/lab-run.sh --window 600 AtomicStealer  # or the manifest's recipe, unattended
lab/lab-run.sh --baseline idle             # the guest alone for 10 minutes: the noise floor
lab/lab-run.sh --baseline benign           # ordinary activity for 2 minutes: what is noise on clean behavior
```

Run both baselines after every change to a rule (or to the golden image) and compare their findings with the last ones.

Set the recipe in `lab/manifest.tsv` (`exec:<path>`, `app:<name.app>`, `pkg:<file>`, `dmg:<file>`, `manual`) once you know what works.

```bash
npm run build:lab                           # once: writes dist-lab/lab-summarize.mjs
node dist-lab/lab-summarize.mjs "$FICUS_LAB_DATA/runs/atomicstealer/<run-id>" lab/expected/AtomicStealer.tsv
```

For a manual run, or any run whose capture holds more than the sample, add `--under <part of the sample's program path>` (for example
`--under VisualStudioHelper`): the capture also holds your own `tart exec` commands and macOS's own activity (a crash reporter running
`system_profiler`, background services), and counting those as the sample's behavior gives false hits.

That prints the findings and writes `gap.md` in the run folder. The facts about the capture go to stderr, including **dropped events**
(found from each event type's own sequence numbers; `close` is not counted, since the harness filters it on purpose) and which
Ficus checks cannot fire on this schema version.

## Verified on real VMs (2026-11-19, with a harmless stand-in script, not a sample)

A zip holding a script that writes a fake launch agent, fetches a file from the fake internet, sets a file date and strips a quarantine flag. One `lab-run.sh` run: status `ok`, about 70 seconds start to finish, no VM left behind. The capture holds the start and end markers, every action of the script, and none of the unmodified `close` events; `post-state/launchagents.txt` shows the plist; `gateway.pcap` shows the DNS lookup and the HTTP request. Ficus loads the capture (4,153 events, 0 bad lines) and flags: `persistence-item`, `odd-location-exec`, `download`, `timestomp` (low), `orphaned` (low), `quarantine-strip` (high).

## More things learned the hard way

- **`nohup run.sh` searches PATH** and finds nothing: the launch must be `./run.sh`. The stub tests could not see this; the real run did.
- **The macOS 26.6.2 guest writes eslogger schema 10.** Ficus's stdin checks (`shell-from-pipe`, the socket part of `reverse-shell`) need schema 11, so they cannot fire on captures from this guest. A golden image on macOS 27 (this Mac's version) is needed to exercise them.
- **The start marker goes in after the unzip**, so the harness's own `unzip` is not part of the sample's stretch of the capture. eslogger is stopped before the post-state is collected, for the same reason.
- **A booting guest is noisy** (Siri, Shortcuts, XProtect and similar helpers start in the first minute). The idle baseline (plan, Task 8) measures it.
- **eslogger's JSON keys are not in a fixed order**, so a text filter for `"modified":false` missed most close events; the harness filters with `jq`.
- **Ficus's global sequence-gap count is useless on a lab capture**: the harness removes unmodified `close` events, which leaves tens of thousands of holes (30,514 in the stand-in run). The summarizer counts drops per event type instead, which are gapless in a complete capture (0 in that run).
- **Ficus has no rule for `xp_malware_detected`, `tcc_modify` or `gatekeeper_user_override`**, although its guide lists them as events to record. XProtect detections are high-value evidence; a candidate rule for Task 10.
- **macOS `unzip` opened the first real objective-see zip (KoiStealer)**, so those are the older ZipCrypto encryption. MalwareBazaar's zips are AES (compression type 99), which macOS `unzip` cannot open.
- **A `manual` recipe means a window and a wait**, and the run folder then holds your own commands. Inspect a sample first with read-only commands (`file`, `codesign -dvv`, `strings`, `otool -L`) through `tart exec`, never on the host.
- **`tart exec` commands that need a permission trigger a prompt in the guest**: a `screencapture` through the guest agent raised a Screen Recording prompt. Harmless (the clone is thrown away), but it shows in screenshots.

## Baselines (2026-11-19)

`baselines.md` records what Ficus flags on an idle guest (2 low context findings, nothing queued, nothing high) and on ordinary
activity (20 findings, none high: recon, `download`, `archive-staging` and similar). The 10-minute idle run was also the first long
`tart exec` stream: it held, 22,904 events and 49 MB, no dropped events. Re-run both baselines after any rule change.

## Pilot results

Per family: what the run did, and Ficus's comparison with the public report (`--under` = limited to the sample's own process tree).

### KoiStealer (2026-11-19, objective-see/malware `KoiStealer.zip`, 2.8 MB, `manual` recipe)

- **Opening it:** macOS `unzip -P infect3d` opened the zip in the guest (the older encryption). One universal Mach-O, `KoiStealer/VisualStudioHelper`, ad-hoc signed, identifier `update_agent-…`; the readme points to the Unit 42 article "RustDoor and Koi Stealer for macOS…" (2025-02-26).
- **It is not the article's build.** Its sha256 (`adde2970…`) is none of the article's three Koi hashes, and the article names `VisualStudioHelper` only for RustDoor. Its strings show things the article does not state for Koi: a `com.apple.update_agent` launch agent, cron and `.zshrc` persistence, Chrome injection, `launch-agent`/`inject-rc`/`dialog` options, `dscl authonly` password checking.
- **What it did here:** launched with no arguments (`./VisualStudioHelper`), it loops: it runs `VisualStudioHelper --dialog` (the fake password dialog helper), which **aborts every time with `SIGABRT`** ("abort() called"; macOS shows "Problem Report for VisualStudioHelper"), then `dscl . authonly admin` with an empty answer. 528 turns in about three minutes, about 20 MB of capture a minute. It never got a password, so it never reached the stealing or the upload: no network contact beyond macOS's own Apple lookups. Why the helper aborts in this guest is not known.
- **Ficus, under the sample:** `odd-location-exec` (high), `dscl-authonly` (high), `adhoc` (low), `orphaned` (low). Against the article: hit 0, miss 4, gap 4, review 2. The 4 misses (`fake-prompt`, `recon`, `credential-store-copy`, `osascript-script`) are behaviors the sample did not get to in this run, not rule faults. The 2 review rows are real: `odd-location-exec` is right, and `dscl-authonly` is the stealer's password check, which the article does not describe.
- **Gaps with no rule:** `tccutil reset AppleEvents`, muting the volume around the upload, the encrypted HTTP upload (eslogger cannot see it), and the Visual Studio update disguise.
- **A false hit, caught:** a comparison over every finding in the capture first reported 1 hit (`recon`). That came from my own `ps` commands and from macOS's crash reporter running `system_profiler` after each abort, not from the sample. `--under` removes it.

Not built yet: more pilot runs and the rule fixes. See the plan, Tasks 9 and 10.
