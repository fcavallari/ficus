# Learning lab

`scripts/ficus-lab.sh` writes a capture for learning what Ficus flags, with an answer key beside it.

```bash
scripts/ficus-lab.sh synthetic     # hand-built, every rule, no noise; safe on any machine
scripts/ficus-lab.sh live          # harmless attack steps on this Mac, recorded by sudo eslogger
```

- **synthetic** builds the capture by hand (an invented user `learner`, invented pids, fixed times) in plain bash. It tells the story of a fake installer that drops a stealer agent, and around it shows every rule at least once, plus the queue's `in chain`, `recon burst`, context-only findings and a launch item with no process. The output is the same on every run; a test checks it against the rule engine.
- **live** runs harmless versions of the same steps as you while `sudo eslogger` records for about a minute, so the steps sit among the real background noise of a Mac. Only `eslogger` runs under sudo, and the terminal needs Full Disk Access. It shows a dialog (type anything, or wait), writes a launch agent (`com.ficus.lab`, runs `exit 0`) and removes it at the end; macOS will likely show a "Background Items Added" notification. Everything else happens in a temporary folder under `/tmp` that is removed at the end, also on Ctrl-C. Nothing real is touched: the keychain lookup asks for an item that does not exist, the password check names an account that does not exist, and `csrutil disable` is refused outside Recovery. A few rules cannot be set off this way (an unsigned binary, a setuid-root copy, the settings changes an admin could actually make); the answer key lists them. The capture holds every process's environment and your user name, so review it before sharing it.
- Both write `scratch/ficus-lab-<mode>.jsonl` and `scratch/ficus-lab-<mode>.answers.tsv` (`-o FILE` to choose; `synthetic --stdout` prints the capture, `--answers` prints only the key). The key has one row per expected finding: `step`, `rule`, `severity`, `queue` (`queued`, `in-chain`, `burst`, `context` or `item`), a `marker` to find the process by (a piece of its command line, or a launch item's plist), and a note on what the step imitates. In a live capture, find `ficus-lab.sh` in the Tree first: every step runs under it.
