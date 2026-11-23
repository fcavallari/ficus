# Capturing

Run this on the Mac you are investigating, stop it with Ctrl-C, then drop `capture.jsonl` into a session:

```bash
sudo eslogger fork exec exit create rename unlink setextattr clone copyfile btm_launch_item_add btm_launch_item_remove > capture.jsonl
```

- `exec` and `fork` build the tree; `exit` gives process lifetimes.
- `create` and `rename` show what a process wrote (a launch agent plist, a download, an archive). `setextattr` records extended-attribute writes on files (shown under “What it did” in the detail pane). No rule uses them yet; a future rule could check whether a downloaded file got its quarantine flag.
- `btm_*` captures persistence registrations (login items, launch agents and daemons).
- `clone` and `copyfile` record files copied: an APFS clone (what `cp` and Finder use) or a copyfile call. They are low-volume (about 1 to 2 percent of the events in the lab's captures) and show a stealer that copies your folders, such as RustDoor cloning a home folder with `clonefile`. They appear as copies in the detail pane, and the credential-store and launch-plist rules count a copy's source and destination. A capture without them still loads.
- `write` is left out on purpose because it is very noisy; the tool still handles it if it is present.
- `close` is left out for the same reason. When either is present, a `write` or a `close` marked modified on a launch plist shows a plist overwritten in place, which has no `create` event; without them the header says so.
- Needs `eslogger` schema version 11 for the checks that read a process's stdin, such as `shell-from-pipe`. Older captures load, and the header says which checks may not apply.

See also: [Cleaning a capture before it leaves the Mac](cleaning-captures.md), [Learning lab](learning-lab.md) and [Mac Monitor traces](mac-monitor.md).
