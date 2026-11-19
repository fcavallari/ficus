# Expected behaviors

One file per sample family, `lab/expected/<Family>.tsv`: what public reports say the sample does, and which Ficus rule should
catch each behavior. `node dist-lab/lab-summarize.mjs <run folder> lab/expected/<Family>.tsv` runs Ficus over the capture, compares
the findings with this file, and writes `gap.md` in the run folder.

Tab-separated, with this header line first (`#` comment lines and blank lines are allowed anywhere):

```
behavior<TAB>mitre<TAB>rule<TAB>source
```

| Column | What goes in it |
|---|---|
| `behavior` | One thing the sample does, in plain words: "Registers a launch agent that runs from ~/Library". |
| `mitre` | The ATT&CK technique ID, e.g. `T1543.001`. |
| `rule` | The Ficus rule id that should catch it (the `id` column of `docs/rules.md`), or `-` when no rule exists yet. A rule id that does not exist is an error, so a typo is not read as a miss. |
| `source` | Where the report says so: a URL, or a book chapter. |

What the report (`gap.md`) shows:

- **Hit**: the rule fired for the capture (queued or context-only).
- **Miss**: the rule exists and did not fire. Look at the capture: either the rule needs fixing, or the sample did not do it in this run (it may have refused to run in a VM, or its server was not there).
- **Gap**: a behavior with no rule yet (`-`). These are the candidates for new rules.
- **Review**: a high finding that no row of this file names. A false positive, or a behavior nobody wrote down.

Write only what a report states. Do not add a behavior because the capture showed it: that would make the comparison pass by
construction. `LabCheck.tsv` is the worked example, for the harmless stand-in script used to test the lab.
