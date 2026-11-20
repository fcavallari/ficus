# Capturing

Run this on the Mac you are investigating, stop it with Ctrl-C, then drop `capture.jsonl` into a session:

```bash
sudo eslogger fork exec exit create rename unlink setextattr btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

- `exec` and `fork` build the tree; `exit` gives process lifetimes.
- `create` and `rename` show what a process wrote (a launch agent plist, a download, an archive). `setextattr` records extended-attribute writes on files (shown under “What it did” in the detail pane). No rule uses them yet; a future rule could check whether a downloaded file got its quarantine flag.
- `btm_*` captures persistence registrations (login items, launch agents and daemons).
- `clone` and `copyfile` are optional and low-volume (about 1 to 2 percent of the events in the lab's captures). Add them (`sudo eslogger clone copyfile …`) when you suspect a program copied files, for example a stealer that clones a home folder with APFS `clonefile`: they show as copies in the detail pane, and the credential-store and launch-plist rules count the copy's source and destination.
- `write` is left out on purpose because it is very noisy; the tool still handles it if it is present.
- `close` is left out for the same reason. When either is present, a `write` or a `close` marked modified on a launch plist shows a plist overwritten in place, which has no `create` event; without them the header says so.
- Needs `eslogger` schema version 11 for the checks that read a process's stdin, such as `shell-from-pipe`. Older captures load, and the header says which checks may not apply.

See also: [Cleaning a capture before it leaves the Mac](cleaning-captures.md), [Learning lab](learning-lab.md) and [Mac Monitor traces](mac-monitor.md).
