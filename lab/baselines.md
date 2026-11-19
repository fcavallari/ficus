# Baselines

What Ficus flags when nothing malicious happens, so a real sample's findings can be read against it. Re-run both after any change to
a rule or to the golden image (`lab/lab-run.sh --baseline idle`, `--baseline benign`, then `lab-summarize.mjs`) and compare. A new
**high** row here is a false positive to fix before the rule ships.

Recorded 2026-11-19. Guest: `lab-gold`, macOS 26.6.2 (build 25G83), eslogger schema 10. Ficus at commit `3044d6a` (rules as of main
`9e74480`). Both runs: status ok, 0 dropped events, 0 bad lines, eslogger never exited early.

## Idle: the guest alone for 10 minutes

22,904 events, 452 processes, 49 MB (about 5 MB a minute, most of it in the first minute after boot). Findings: 2, both low and
context-only (not queued).

| rule | severity | what |
|---|---|---|
| `uid-mismatch` | low | `loginwindow` runs with euid 501, ruid 0 |
| `uid-mismatch` | low | `sudo` runs with euid 0, ruid 501 (the harness's own `sudo eslogger`) |

The noise floor is two Apple processes behaving as designed. Nothing is queued and nothing is high.

## Benign: ordinary activity for 2 minutes

`lab/guest-benign.sh` (12 steps, all worked), then the rest of a 120-second window. 6,124 events, 267 processes, 13.5 MB.
Findings: 20, none high; 13 queued, 7 context-only.

| rule | severity | count | what |
|---|---|---|---|
| `recon` | low | 12 | `sw_vers`, `uname`, `whoami`, `id`, `hostname`, `sysctl`, `launchctl` and similar (context only unless in a flagged chain) |
| `uid-mismatch` | low | 4 | `loginwindow` and `sudo` as in the idle run, plus `installer` (run through sudo, euid 0) and `WindowServer` (euid 88) |
| `orphaned` | low | 2 | two `bash` processes left under launchd after their parent `bash` exited; the parents are shells the benign script's own steps started (the recon step's is one). Not investigated further |
| `download` | med | 1 | `curl -s -m 10 -o ~/lab-benign/page.html http://example.com/` |
| `archive-staging` | med | 1 | `zip -q d.zip d.txt` in the home folder |

The two medium findings are the expected cost of a rule that matches a tool's use (any `curl -o`, any `zip`): in a real sample's
run they are context, not evidence on their own. The empty package install (`installer`), the SSH key, the preference write, the app
launch, `launchctl list` and the Python one-liner raised nothing.

## What these baselines do not cover

- **Schema 10 only.** Ficus's stdin checks (`shell-from-pipe`, the socket part of `reverse-shell`) cannot fire on this guest, so
  they are untested here. A macOS 27 golden image would exercise them; run both baselines on it too.
- **No network noise** beyond a curl to the fake internet. eslogger sees no network events.
- **A fresh guest.** No user session history, no logged-in apps, no developer toolchain beyond Cirrus Labs's base image. A real Mac is
  noisier; this is a floor, not a forecast.
