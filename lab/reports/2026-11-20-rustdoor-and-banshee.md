# Two more MalwareBazaar samples in the Ficus malware lab: RustDoor and Banshee

Runs `bazaar-rustdoor-baa676b6-20261120T030900Z-77380` and `bazaar-banshee-dea72cdd-20261120T031442Z-86784`, 2026-11-20 (UTC; the evening of 2026-11-19 on the Mac).
The first runs started without a person at the VM: the manifest recipe is `exec:<file>`, not `manual`. Written from the run folders' evidence, with the public
reports read only as secondary summaries (see the expected files' caveats). Both runs used the main guest image `lab-gold` (macOS 26.6.2, `eslogger` schema 10),
a 300-second window, a fresh clone each, and the same fake internet and isolation check as before.

## Summary

- **RustDoor** (an x86_64 backdoor tagged APT and DPRK, running under Rosetta): about 130 ms after launch it **cloned the whole home folder into a hidden `~/.docks/`** (203 files, in
  about a second), including the bait SSH key, `~/.aws/credentials` and `Documents/recovery phrase.txt`. It then stayed running to the end of the window, looking up
  `juchesoviet48.com` about every 15 seconds (21 lookups) and sending signal 0 (an existence check) 340 times. It wrote no persistence. **Ficus flagged only where it ran from and that it
  was unsigned**; the bulk copy, the credential files and the beacon raised nothing.
- **Banshee** (an arm64 Rust stealer, signature `AmosStealer`): it re-ran itself with `run_controller`, ran `killall Terminal`, asked `system_profiler SPHardwareDataType | grep 'Model Identifier'`, `sw_vers`,
  `sysctl machdep.cpu.brand_string` and `sysctl hw.memsize`, created an empty UUID-named folder in `/tmp` and **exited within 0.35 seconds**. That is the virtual-machine check Elastic
  describes for Banshee, and the sample evidently refused to run here. No theft, no network contact. Ficus flagged its recon commands.
- **Compared with the reports:** RustDoor 0 hits, 3 misses, 2 gaps, 2 for review; Banshee 1 hit, 3 misses, 1 gap, 2 for review. The misses are things the samples did not do in these runs, not rule faults.
- **The new rules caused no false findings.** I ran the summarizer on a local merge of the open and merged rule changes (queue grouping #34, `mass-rename` #35, `file-upload` #36) over both runs and over the idle and benign baselines, Koi, HeartBreaker and AMOS: `mass-rename` fires only on HeartBreaker, `file-upload` only on AMOS, and neither sample here uploaded anything. (The queue sizes quoted in this report are from main without #34, which groups repeats: neither run has any, so they would not change.)

## The samples

| | RustDoor | Banshee |
|---|---|---|
| Source | MalwareBazaar, tags `RustDoor`, `apt`, `DPRK`; first seen 2024-09-17 | MalwareBazaar, signature `AmosStealer`, tags `Banshee`, `Rust`; first seen 2025-12-15 |
| File | `localfile.x64`, x86_64 Mach-O, 3,022,328 bytes, **unsigned** | `crypto-win`, arm64 Mach-O, 576,192 bytes, ad-hoc signed (`mac_os_stealer-0063b5638896729d`) |
| sha256 | `baa676b671e771bf04b245e648f49516b338e1f49cbd9b4d237cc36d57ab858d` | `dea72cdd7c9dfc49f0a19581086c8e6e99b000dc33f461ece8b9f37c1bd7068d` |
| Zip | `Bazaar-RustDoor-baa676b6.zip`, 1,433,942 bytes, AES, password `infected` | `Bazaar-Banshee-dea72cdd.zip`, 245,555 bytes |
| Recorded | 19,952,166 bytes, 8,955 events, 240 processes, 0 dropped | 16,352,519 bytes, 7,340 events, 235 processes, 0 dropped |

Neither zip was extracted on the host (only listed). Both were unzipped in the guest with `7zz`, and launched by the manifest's `exec:` recipe (`chmod +x`, then in the background).

## What RustDoor did (observed)

| Time (UTC, 2026-11-20) | What |
|---|---|
| 03:09:26.255 | the sample runs from `~/Downloads/sample/`; it forks 4 times in 20 ms (three of the forks exit within 10 ms) |
| 03:09:26.276 | `/usr/bin/log stream --predicate 'eventMessage contains "com.apple.restartInitiated" or eventMessage contains "com.apple.shutdownInitiated"' --info`: it waits for a restart or shutdown message |
| 03:09:26.385 to 03:09:27 | 129 `clone` events and 203 `create` events: files from `~/.ssh`, `~/.aws`, `~/Documents`, `~/Public`, `~/Downloads`, `~/.rbenv`, `~/.npm/_cacache` and `~/actions-runner` cloned into `~/.docks/<same layout>` |
| throughout | 340 `signal` events, all signal 0 (an existence check), aimed at system daemons such as `distnoted`, `cfprefsd`, `trustd` |
| 03:09:27 to 03:14:27 | DNS lookups of `juchesoviet48.com`, 21 of them about 15 seconds apart; the lab's gateway answered each with itself (the gateway's clock reads 17:09 where the run folder's reads 03:09; both are the same minute); port 443 traffic to the gateway runs through the whole capture, but the guest's own Apple lookups use it too, so it is not attributed |
| at the end | still running (pid 716, now under `launchd`); no launch agent, no crontab, no new login item |

No process was started besides the `log stream` and the forks; no archive was built and nothing was uploaded. The clone is APFS `clonefile`, so it costs no disk space and leaves no `cp`, `ditto` or `zip` to read.

## What Banshee did (observed)

| Time (UTC) | What |
|---|---|
| 03:15:03.716 | `./<sha256>.macho`, then the same file again with arguments `run_controller 5Hi/` (a re-exec into a controller mode) |
| 03:15:03.720 | `killall Terminal` |
| 03:15:03.721 | `sh -c "system_profiler SPHardwareDataType \| grep 'Model Identifier'"` (the VM check) |
| 03:15:04.044 to .057 | `sw_vers -productVersion`, `sysctl -n machdep.cpu.brand_string`, `sysctl -n hw.memsize` |
| 03:15:04.060 | creates `/private/tmp/<uuid>/` (empty), and exits |

Nothing is running after that and nothing else happened in the window. I did not read the guest's model identifier in this run; Virtualization.framework guests normally report a `VirtualMac…` identifier, which a build looking for "Virtual" would find.

## What Ficus found

RustDoor, under the sample: `odd-location-exec` (high), `dropped-then-executed` (high, written by the lab's `7zz` 0 s earlier), `unsigned` (med), `orphaned` twice (low). Queue: 2 items.

Banshee, under the sample: `odd-location-exec` (high, 2), `dropped-then-executed` (high, 2), `adhoc` (low, 2), `orphaned` (low), and `recon` (low) for `system_profiler` (twice), `sw_vers`, `sysctl` (twice). Queue: 7 items. The recon commands are four different tools within a second under one shell, so they form a recon burst. `killall Terminal` raised nothing.

`odd-location-exec` and `dropped-then-executed` are the lab's own placement and unzip (see the lab README), not the samples' behavior.

## Comparison with the reports

| | Row | Rule | Result |
|---|---|---|---|
| RustDoor | collects Desktop, Documents and notes into a ZIP | `archive-staging` | Miss: it cloned them instead |
| RustDoor | uploads the archive | `file-upload` | Miss: nothing was sent |
| RustDoor | a spoofed administrator password dialog | `fake-prompt` | Miss: none shown |
| RustDoor | registers with its C2 over HTTP | none | Gap: DNS and TLS to `juchesoviet48.com` are in the pcap, invisible to `eslogger` |
| RustDoor | persists with cron or the Dock | none | Gap: no rule for cron; none happened in this window |
| Banshee | VM check with `system_profiler … Model Identifier` | `recon` | Hit |
| Banshee | fake password prompt, staged ZIP, HTTP POST | `fake-prompt`, `archive-staging`, `file-upload` | Miss: it quit at the VM check |
| Banshee | avoids Russian-language systems | none | Gap: an API call, nothing to see |

## What the evidence suggests for Ficus

These are candidates, not changes made here.

1. **Model `clone` and `copyfile` events as file creates.** RustDoor copied a whole home folder with `clonefile` and Ficus counted it as "other events: clone ×129". The creates it produced are already modeled; the missing piece is that the staging looks ordinary: a hidden folder of copies made by an unsigned program. A rule for **a process creating many files in a hidden folder it made itself** (or a bulk copy of a home folder) would have caught this; it should be tried against the baselines first.
2. **Recognize SSH keys and cloud credentials as credential stores** (`~/.ssh/id_*`, `~/.aws/credentials`, `~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`). `credential-store-copy` only knows browsers, keychains, Notes and one wallet file, so it never looked at what RustDoor copied.
3. **`killall Terminal`** by a program running from Downloads, seconds after launch, is worth a low finding: closing the window the user launched the sample from. One sample is not enough to say how often benign software does it.
4. **A beacon in the pcap.** The gateway capture shows `juchesoviet48.com` looked up every ~15 s for five minutes. That is outside `eslogger`, but the lab could print the periodic names of a run in its summary. This is a lab feature, not a rule.
5. **VM checks.** Banshee's command is a recon command Ficus already sees; the useful lab change is the opposite one: a run that ends in under a second with a VM-check command is worth saying so in the summary, so it is not mistaken for a sample that did nothing.

## Limits

- **One run each, five minutes.** RustDoor's command channel never answered (the gateway serves INetSim's default pages), so its later behavior (collection, ZIP, upload, persistence) was not triggered. A different fake server response might have changed that; that would be a separate experiment.
- **Banshee refused to run in a Virtualization.framework guest.** The guest's model identifier cannot be changed from inside; a run that gets past the check needs either a different guest or a patched sample, and neither is done here.
- **Secondary sources.** The expected rows come from news summaries of Bitdefender's RustDoor report and from Elastic and Check Point on Banshee; I did not open Bitdefender's report. This RustDoor build is seven months newer than the report and tagged DPRK.
- **The beacon attribution is by elimination:** `juchesoviet48.com` is the only non-Apple, non-lab name in the pcap, it started 1 s after launch and repeated until the end; I did not see the connection's payload (TLS).

## Evidence

- `$FICUS_LAB_DATA/runs/bazaar-rustdoor-baa676b6/bazaar-rustdoor-baa676b6-20261120T030900Z-77380/` and `.../bazaar-banshee-dea72cdd/bazaar-banshee-dea72cdd-20261120T031442Z-86784/`: `capture.jsonl`, `gateway.pcap`, `post-state/`, `meta.json`, `gap.md`.
- `lab/expected/Bazaar-RustDoor-baa676b6.tsv`, `lab/expected/Bazaar-Banshee-dea72cdd.tsv`.
- Sources: Bitdefender Labs, "New macOS Backdoor Written in Rust Shows Possible Link with Windows Ransomware Group" (2024-02), read through [Dark Reading](https://darkreading.com/threat-intelligence/macos-targeted-by-new-backdoor-linked-to-alphv-ransomware), [SecurityWeek](https://www.securityweek.com/new-macos-backdoor-linked-to-prominent-ransomware-groups/) and [The Hacker News](https://thehackernews.com/2024/02/alert-new-stealthy-rustdoor-backdoor.html); Elastic Security Labs, [Beyond the wail: deconstructing the BANSHEE infostealer](https://www.elastic.co/security-labs/beyond-the-wail); Check Point Research, [Banshee macOS stealer](https://research.checkpoint.com/2025/banshee-macos-stealer/); Hivepro advisory TA2024316.
