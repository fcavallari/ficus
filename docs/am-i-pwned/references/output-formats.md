# Output formats

Keep it short. The person will ask for detail if they want it.

## Researcher mode

1. **Verdict in one line:** `CLEAN` / `NEEDS A LOOK` / `LIKELY COMPROMISED`, with a one-sentence reason naming the decisive row. Pick it with *Choosing the verdict* in `reading-the-result.md`.
2. **Findings table:** severity, what, evidence (path or command output), why it matters, what to do. Expected-noise hits go in a separate short list, not in the table.
3. **Things you could not check, and why.**
4. If `NEEDS A LOOK` or worse: the exact next three commands or actions, and whether to disconnect from the network first.

## Everyone-else mode

Plain language; explain terms in a few words. No severity judgement left to the person: say clearly what to do.

1. **Verdict in one line:** `ALL GOOD` / `FIX THESE SETTINGS` / `CONTACT SECURITY NOW`, with a one-sentence reason naming the decisive row. Pick it with *Choosing the verdict* in `reading-the-result.md`.
2. **Baseline table:** each company baseline item (see `field-guide-baseline.md`), pass / fail / could not check, and the one-line fix if it fails.
3. **Findings table:** what, evidence, why it matters in plain words, what to do. Mark anything the person should NOT touch themselves.
4. **Things you could not check, and why.**
5. **Self-check questions** (yes/no) for the Field Guide items a device check cannot see; the table of these is in `field-guide-baseline.md`.
6. If `CONTACT SECURITY NOW`: tell the person to disconnect from Wi-Fi, leave the machine on, not log into anything else from it, and email sysops@automattic.com from a phone or another device. Do not walk them through cleanup. If a self-check answer was yes, add that whatever they typed or ran should be treated as stolen, that they should not change passwords from this machine, and that Security Ops will tell them which accounts to secure and how, from another device.

## Severity words

- **High**: things almost no ordinary software does (a fake password prompt, a `com.apple.*` launch agent in a user folder, a hidden executable that runs from a launch item, a pasted command that downloads and runs code).
- **Medium**: worth a look with context (an unsigned item from an odd path, an unexplained listener).
- **Low / context**: weak signals that matter only in company (ad-hoc signed developer tools, a single `whoami`). Mention them in one line, not in the table, unless they sit next to a higher finding.

A finding is a lead, not a verdict. Say what you saw and why it might matter; let the evidence, not tone, carry it.
