# Mac Monitor traces

A trace exported from [Mac Monitor](https://github.com/redcanaryco/mac-monitor) 3.0 or later (Export telemetry, or `macmonitor stream ... > trace.jsonl`) loads like an `eslogger` capture: Mac Monitor writes `eslogger`'s JSON with its own enrichments beside it, and Ficus reads the `eslogger` keys and ignores the rest. Both the JSONL export and the pretty JSON export load, and so does a JSON array of events. A file whose first line is only `{`, or which starts with `[`, is read object by object; anything else is read line by line.

- Subscribe to at least `fork`, `exec` and `exit`, and to `create`, `rename` and `btm_launch_item_add` for the persistence rules.
- Mac Monitor's mute set, filters and dropped events leave gaps: a process whose `fork` or `exec` was muted shows up without its parent, as it would in an `eslogger` capture that missed it.
- Mac Monitor numbers the messages of each of its Endpoint Security clients separately, so its sequence numbers do not give one order across a trace. Ficus orders a Mac Monitor trace by `mach_time` instead.
- Mac Monitor's enrichments (its indicators, script contents, `launched_by_parent`) are not shown yet.
- Exports from before 3.0 may not follow `eslogger`'s layout. Open them in Mac Monitor 3 (File > Open Trace...) and export them again.
