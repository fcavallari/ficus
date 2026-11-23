# HeartBreaker in the Ficus malware lab

Run `heartbreaker-20261119T221354Z-43444`, 2026-11-19. One sample, one run of about four minutes, with a person closing the ransom window partway.
Written from the run folder's evidence. Statements that come from reading the binary or its source, not from watching it run, are marked **static**.

## Summary

- **What ran.** `HeartBreaker.zip` from objective-see/malware: macOS ransomware written in Rust, in the lab's throwaway macOS 26.6.2 guest on a fake internet with `eslogger` recording. This binary is the article's own sample (the sha256 matches the VirusTotal ID in Patrick Wardle's write-up).
- **What happened.** It did what the article says, almost to the letter. In 1.3 seconds it encrypted every file under `~/Downloads` (15 files, each renamed to `<name>.heartbreaker` and exactly 28 bytes bigger), dropped a ransom note `README.txt` on the Desktop, wrote the launch agent `~/Library/LaunchAgents/com.network.startup.plist`, and showed a red "HEARTBREAKER WARNING!" window. After the window was closed it ran the classic `curl … https://sh.rustup.rs | sh -s -- -y …` to install Rust, wrote a temporary Cargo project for its next generation, and stopped after checking for `cargo`, which the guest does not have.
- **What Ficus saw.** The launch agent (`persistence-item`, high) and the `curl | sh` (`shell-from-pipe`, medium), plus findings about running from Downloads. **It raised nothing for the encryption itself**: 15 files truncated, rewritten and renamed in 1.3 seconds is the one thing this sample is for, and no rule described it. **Done since:** the `mass-rename` rule (10 or more files renamed in place to one new extension within 10 seconds) fires on this capture, and not on the idle and benign baselines or the other two pilot runs.
- **Compared with the article:** 1 hit, 0 misses, 4 gaps, 2 for review. All four gaps are real missing rules; the two review rows are `odd-location-exec`, partly a product of where the lab unzips samples.

## The sample

| | |
|---|---|
| Source | `https://github.com/objective-see/malware`, `HeartBreaker.zip`, added 2026-10-18 (commit `16c4f3bf`) |
| Zip | 3,202,517 bytes, sha256 `30eb363fa4764c1c53b865c26a8fc110f4287d4502c430db39ff2a3b1bdac60e`, password `infect3d` |
| Contents | `HeartBreaker/heartbreaker`, `HeartBreaker/metacore-master.zip` (18,538 bytes, the Rust source of a related crate), `HeartBreaker/readme.txt` |
| readme | "HEARTBREAKER", with the write-up `https://objective-see.org/blog/blog_0x8A.html` |
| Binary | 7,531,952 bytes, thin arm64 Mach-O, sha256 `6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18` |
| Signing | ad-hoc, linker-signed, identifier `heartbreaker-e2c97a640967e3f6`, no team ID |
| Links against | libSystem, OpenGL, CoreServices, AppKit, CoreGraphics, Foundation, CoreFoundation, CoreVideo, Carbon (a Rust GUI) |

**The article:** "Heartbreaker: Metamorphic ransomware comes for macOS", Patrick Wardle, 2026-10-18. It reports the sample was uploaded to VirusTotal in May 2025 and was undetected by every engine at the time of writing. It states no network activity and no MITRE ATT&CK IDs.

## How it was run

- **Guest:** the lean image (recorded as `lab-gold`; since renamed `lab-gold-lean`, see `lab/README.md`), macOS 26.6.2 (25G83), `eslogger` schema 10. It has no Rust, which is why the sample took its install path. Fresh clone, deleted afterwards.
- **Network:** a private cable to a gateway VM answering every name and address with INetSim. The isolation check passed before the sample was copied in.
- **Recording:** `eslogger` through `tart exec`, 24,932,698 bytes, 11,317 events, 387 processes, 0 dropped events, 0 bad lines.
- **Recipe:** `manual`. The zip was unzipped in the guest (`~/Downloads/sample`); I read the sample's metadata and strings read-only; I put eleven harmless decoy files (text, JPEG-sized random data, empty Office files) in `~/Downloads/decoys` so there was something to encrypt; I launched `./heartbreaker` with no arguments; and a person closed the ransom window in the VM.
- **No Rust in the guest.** The sample therefore took its "install Rust" path, which the article describes only in outline.

| Time (UTC, 2026-11-19) | Event |
|---|---|
| 22:13:54 | Run starts |
| 22:14:19.9 | Start marker (after the unzip) |
| 22:14:26 to 22:15:09 | Read-only inspection in the guest |
| 22:15:51.5 | `./heartbreaker` launched (through `nohup`, in the background) |
| 22:15:51.56 to 22:15:52.85 | Encryption: 15 files renamed to `.heartbreaker`; ransom note and launch agent written |
| 22:15:53 to 22:17:30 | Ransom window on screen; no activity |
| 22:17:30.4 | Window closed; `uname -m`, then the `curl … https://sh.rustup.rs | sh -s -- -y --default-toolchain stable-aarch64-apple-darwin` |
| 22:17:32.6 | Last event from the sample |
| 22:18:02.9 | End marker; run finished 22:18:04, clones deleted |

## What the sample did (observed)

- **Encryption.** Its own log shows `Encrypting file:` for 15 files; the capture shows 15 renames to `<name>.heartbreaker`. Decoys went from, for example, 64 to 92 bytes and 40,000 to 40,028 bytes: the article's layout of a 12-byte nonce, the ciphertext and a 16-byte tag. It also encrypted `.localized` and **its own folder**: the sample binary, `metacore-master.zip` and `readme.txt` (the lab unzips into `~/Downloads/sample`, which is inside the target folder). The whole pass took about 1.3 seconds.
- **Ransom note.** `~/Desktop/README.txt` (301 bytes): a demand for 0.003 BTC to one address and 0.001 BTC to another, then a contact over Session. The window shows the same addresses. Addresses and ID are in the sample's own note and are recorded here only as indicators: `1LACmsR1mU6WLKzALMqkLxRjDSNVqoCpzj`, `bc1qsq2p02m6mtdac7llu798wusrtc9p4mcnu5e9eg`, Session ID `424234njewjnnjnj812a50659065edc8wewqnjdjwnj44343nj4neee344564nj6n3535`.
- **Persistence.** `~/Library/LaunchAgents/com.network.startup.plist`, label `com.myapp.startup` (the article points out that the label and the file name disagree), `RunAtLoad`, running the sample's own path. That path no longer exists: the sample encrypted its own binary, renaming it `heartbreaker.heartbreaker`. macOS showed "heartbreaker can run in the background" and the capture has the matching `btm_launch_item_add`. The agent was not loaded and a login was not tested.
- **The window.** A red "HEARTBREAKER WARNING!" window with the ransom text and a disabled "Decrypt Files" button, as the article says.
- **Rust install.** After the window closed: `uname -m`, then `sh -c curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable-aarch64-apple-darwin`. The gateway capture shows one DNS lookup for `sh.rustup.rs`. The fake internet answered, and the sample logged "Rust installation completed successfully", though no `~/.cargo` exists: it appears to trust the exit status.
- **Metamorphism, as far as it got.** The sample wrote a temporary Cargo project under `/var/folders/…/T/mU87JOX2MhUUFr/` (`Cargo.toml`, `build.rs`, `src/main.rs`, `modified_source.rs`, 13,427 bytes with 20 function definitions; the article says 15 junk functions are added, which I did not check separately). The generated `Cargo.toml` lists `aes-gcm`, `dirs`, `eframe`, `epaint`, `litcrypt`, `mimicore` (a git dependency) and `walkdir`. It then logged "Checking for Cargo…" and stopped, keeping the folder. **The build and the swap of its own binary were not reached**, because the guest never got Rust.
- **No other network contact** of its own that I could attribute: no C2 and no upload (the article states none). The post-state shows no crontab entry for root or the user.

## What Ficus found

Findings about the sample's process tree (`--under heartbreaker`):

| Rule | Severity | About |
|---|---|---|
| `odd-location-exec` | high | the binary running from `~/Downloads`, ad-hoc signed |
| `odd-location-exec` | high | the same process again, as `heartbreaker.heartbreaker` (see below) |
| `persistence-item` | high | `com.network.startup.plist`, run from the Downloads folder |
| `unsigned` | med | `heartbreaker.heartbreaker` has no code signature |
| `shell-from-pipe` | med | `sh -s -- -y --default-toolchain stable-aarch64-apple-darwin` with stdin from a pipe |
| `adhoc` | low | the binary is ad-hoc signed |
| `orphaned` | low | its parent shell exited; it sits under launchd |
| `recon` | low | `uname -m` |

The whole capture has 13 distinct findings (17 counting repeats) and a triage queue of **3 items**. A quirk worth knowing: after the sample renamed (encrypted) its own running binary, Ficus saw the process as a second program, `heartbreaker.heartbreaker`, with no signature, so the same process gets `odd-location-exec`, `unsigned` and `orphaned` under that name.

## Comparison with the article

Expected behaviors are in `lab/expected/HeartBreaker.tsv`, written from the article before the capture was read.

| Result | Behavior (article) | Rule |
|---|---|---|
| Hit | LaunchAgent plist `com.network.startup.plist`, `RunAtLoad`, runs its own binary | `persistence-item` |
| Gap | Encrypts every file under `~/Downloads` (AES-256-GCM, truncate, rewrite, rename to `.heartbreaker`) | no rule |
| Gap | Ransom note `README.txt` on the Desktop | no rule |
| Gap | Installs Rust when cargo is missing (observed as `curl … | sh`) | no rule for the purpose; `shell-from-pipe` flags the pattern |
| Gap | Builds a modified copy of itself with cargo and swaps its own executable (not reached here) | no rule |
| Review | `odd-location-exec` ×2 (high): not in the article | |

The article does not mention running from Downloads, so those rows come out as "review". Here they are partly the lab's doing: the sample was unzipped to `~/Downloads/sample`. Real victims often do run things from Downloads, but the row will appear in every pilot run and says little.

## What the evidence suggests for Ficus

1. **A ransomware rule is the clear gap.** One process truncated, rewrote and renamed 15 files in about 1.3 seconds, all adding the same new extension (`.heartbreaker`). `eslogger` recorded 15 renames, 49 modified closes and the creates. Ficus recommends `create rename unlink` and the lab also records `close` and `truncate`; a rule would read a burst of renames by one non-Apple process that add the same new extension, or many truncate-and-rename pairs, in a few seconds. It has to be tested against the benign baseline (`lab/baselines.md`, which has zip, tar and file moves) before it ships.
2. **A ransom note is a weak signal alone, but strong after item 1:** a new `README.txt` or similar on the Desktop right after a rename burst.
3. **A process that renames its own running executable** is rare and worth a finding (here it was the encryption reaching its own binary). It would also remove the duplicate "second program" noise.
4. **`curl … | sh` to install a toolchain** is already caught (`shell-from-pipe`, medium); it is the same pattern as a malicious one-liner, and the only thing separating the two is the destination.
5. **Ficus's docs say its stdin checks need schema 11.** This guest reports schema 10, but its `exec` events carry `fds` and the check fired. The documented requirement may be stricter than the real one; worth a look in `docs/capturing.md` and the capture header's coverage note.

## Limits

- One run of about four minutes. The metamorphic stage stopped early because the guest has no Rust; the build and the replacement of the binary were not seen.
- The window needed a person to close it; the run's timing around it depends on when that happened.
- The sample ran from `~/Downloads/sample` and encrypted that folder too. A different location would change which files it touches and which findings appear.
- The login-time launch of the agent was not tested.
- The sample's metamorphic step depends on a git dependency (`mimicore`) whose repository is gone, so on a real internet it would fail at the build in any case; this run did not reach that point because the guest had no Rust.
- The capture holds my own commands and the system's activity; `--under` separates them by ancestry.
- The guest is a fresh macOS 26.6.2 image on Apple silicon; nothing here covers other versions.

## Next

1. Re-run on a guest image that has Rust (Homebrew rust 1.100.0 was added to the lab's dev image on 2026-11-19) to see the sample's `cargo build` attempt. **Expect the build to fail, and not only because of the lab's fake internet:** the generated `Cargo.toml` takes `mimicore` from `https://github.com/saaaarwar/mimicore`, and that repository no longer exists (GitHub answers 404 for it; the related `saaaarwar/metacore` exists, last pushed 2025-05-22). The build and the binary swap would fail the same way on a real Mac today. Getting them to run would mean patching a local library in with a cargo `[patch]` section, which changes the sample's behavior and is an experiment, not a baseline.
2. Try the rule idea in item 1 against the benign baseline and this capture.
3. Run the next sample.

## Evidence

Kept outside the repository, in `~/WORK/investigation/MacOSThreats/ficus-lab-data/runs/heartbreaker/heartbreaker-20261119T221354Z-43444/` (the sample is live malware; never open the zip on the host).

| File | Size | sha256 |
|---|---|---|
| `capture.jsonl` | 24,932,698 bytes | `d6027836056b83a80a313e677f28d12385f936fac6ef1f002ca6b5c1ff87948c` |
| `gateway.pcap` | 3,538,321 bytes | `3d17883a2c2c8296e42c4fb81c5fe96e4d4bbc66923401e6002126ffc539bdfd` |
| `meta.json` | | `304b24ad78ff222a17ed32d5252e2d5b51fdda2e602b1051245272040309e7fa` |

Also in that folder: `post-state/` (BTM items, launch folders, crontabs, process list), `findings.tsv`, `findings-sample.tsv`, `gap.md`, `summary.txt`, `isolation.log`, `launcher.log`.
