# Cleaning a capture before it leaves the Mac

A raw capture holds the account's names, file and folder names, hosts, command lines, environment variables and sometimes secrets. If the Mac belongs to someone else, such as an executive, the capture should not leave it as it is. `scripts/ficus-clean.sh` replaces the identifying values with placeholders and keeps what the rules and the investigator need. It needs only what macOS 15 and later has (bash and `/usr/bin/jq`). The findings stay the same, with one exception noted below for standard input: a test runs the rule engine on a capture and on its cleaned copy and compares them.

Two commands. `record` runs `sudo eslogger` and cleans the stream as it comes, so the raw capture is never written to disk. Run it as yourself, not under `sudo`: the script refuses to run as root and asks for your password once, for its own `sudo`. `clean` cleans a capture you already have.

```bash
scripts/ficus-clean.sh record -o capture.cleaned.jsonl -t 600 -D example.com
scripts/ficus-clean.sh clean -i capture.jsonl -o capture.cleaned.jsonl -D example.com
```

- `-o FILE` is the cleaned capture (`-` for standard output; the default is `capture.cleaned.jsonl` in the current folder).
- `-D DOMAIN` is the company's own domain. Hosts under it are treated as internal. Repeat it for more domains.
- `-S SEEDFILE` lists more values to clean, one per line: a kind, a tab, then the value. The kinds are `user`, `realname`, `name`, `volume`, `host`, `email`, `seed` and `data`.
- `-k KEYFILE` is where the real values are kept (see "The key" below). An existing key is loaded first and added to, so several captures of one Mac share placeholders (`user1` is the same person in each). Without `-k` the key is named after the output file, and it must not exist yet: running again with the same `-o` fails until you pass `-k` or choose another `-o`. With `-o -` the default key is `stdout.key.tsv`. The key can never be the output or the input file, however the path is written.
- `-t SECONDS` (`record` only) stops the recording after that long. Ctrl-C (or `Ctrl-\`) stops it too.

`clean -i` reads a JSONL capture, a pretty-printed export or a JSON array, and always writes JSONL. `-i -` reads standard input. From standard input (and in `record`) there is no prescan of the programs the capture runs, so a file created before its program runs keeps a placeholder name there. A finding that joins a file write to a later run (`dropped-then-executed`) can then be missing from the cleaned copy: use `clean -i FILE` when the findings must match. It never changes or deletes the raw file. Delete that yourself when you are happy with the result.

**What is replaced.**

- Account short names (`user1`), full names (`Person 1`), and the names of files, folders and volumes under home folders, `/Users/Shared`, `/Volumes` and the temporary folders (`name1`, `vol1`; a leading dot and a short extension stay). The path segments of a URL are cleaned the same way, and so is the path of a git remote written `git@host:org/repo.git`. User info in a URL is removed. The same name gets the same placeholder in every path, argument and text, `curl -d @file` and `-F name=@file` included (the `@` stays).
- Email addresses (`person1@example.invalid`), and internal hosts (`host1.internal.invalid`): private and link-local addresses, `.local`, `.internal`, `.corp`, `.lan` and `.home.arpa` names, hosts under a `-D` domain, and this Mac's own host names. Public hosts are kept as evidence.
- Recognised credentials become `<redacted>` and are never written to the key: passwords after `dscl -authonly`, `security -w`, `curl -u` and `Authorization` or `Cookie` headers, options named like a password, token, secret or API key with one dash or two (`--password`, `--db-password`, `-password`, `-adminPassword`, `-apiKey`; not `-password -`, which reads it from standard input), the user info of `//user:password@host/share` (as `mount_smbfs` takes it), secret-looking `NAME=value` entries, and AWS, GitHub, Slack, `sk-` and JWT shapes. Environment values are `<redacted>` too, except a few such as `PATH`, `HOME` and `DYLD_*`.
- Data the cleaner cannot judge becomes `data1`, `data2` and so on, with the real value in the key: `curl -d` request bodies, the values of `curl -H` and `wget --header` headers (the header's name stays: `X-Deal: data2`), URL query values (`?id=data1`) and long encoded runs (32 or more characters of base64 or hex). So you can still recover a payload by looking it up on the Mac.
- This Mac's accounts (uid 500 and up), their full names, its computer, local host and host names, serial number and hardware UUID are read as seeds and cleaned wherever they appear, unless `FICUS_CLEAN_NO_LOCAL_SEEDS=1` is set. Cleaning a capture from another Mac warns that names outside paths are only caught with `-S`.

**What is kept.** The rules decide by program name, so the file name of every program and script that ran stays (`python3`, `curl`, a dropper's name), and so do the standard home folders (`Desktop`, `Documents`, `Downloads`, `Library`), the structure folders under `~/Library`, tooling folders such as `node_modules`, `.app` and other bundle names, `com.apple.*` and other bundle IDs, and system paths like `/usr` and `/System`. Words the rules look for, such as `display dialog`, `Chrome Safe Storage`, `launchctl load` and `-authonly`, stay too. In those places a name is kept even when it is the same word as an account name. The summary lists any account name that is short or a common word.

**The key.** The key file holds the real values: names, request bodies, payloads, anything that became `dataN`. It is as sensitive as the raw capture. By default it is `~/Library/Application Support/Ficus/keys/<name of the output>.key.tsv`, readable by you only, and deliberately not next to the capture, so copying the capture's folder does not take it along. Keep it on the Mac. Do not send it with the capture. If you delete it, the cleaning cannot be undone, which is a choice you can make once the investigation is over. Keys made before the project was renamed Ficus are in `~/Library/Application Support/Gameleira/keys/`; pass one with `-k` to reuse it.

**What a cleaned capture can still hold.** The cleaner replaces what it can recognise. These stay as they were, apart from account names, seeds and names already mapped elsewhere in the capture:

- Free text: commit messages, search terms and globs (`mdfind`, `find -name '*Falcon*'`, `grep -r 'Project Falcon'`), dialog and spoken text. Run from a home or another cleaned folder, a whole argument with a space in it becomes a name; elsewhere it stays.
- Other people's logins and names: `sudo -u jane`, `ssh jane@host`, a colleague's name in text. Only this Mac's accounts and full names, and `-S` seeds, are known.
- Public hosts, SaaS tenant hosts among them (`acme.sharepoint.com`, `acme.slack.com`), unless they are under a `-D` domain.
- Names in system and app places: under `/opt`, `/Library/Application Support/<vendor>/…` and other app folders, bundle IDs and launchd labels (`com.acme.falcon.plist`), and environment variable names (`ACME_FALCON_BUCKET`).
- A script's positional arguments (`map_drives.sh / jdoe smb_user SmbPass123`).
- Passwords passed by position or by a one-letter option to tools the cleaner has no table for, such as `networksetup -setairportnetwork en0 Net Passw0rd`, `htpasswd -b file user Passw0rd`, `pwpolicy -p`, `defaults write … Password …` and `launchctl setenv NAME value`, a password piped to `sudo -S` (`echo Passw0rd | sudo -S …`), `wget --post-data` bodies, and the subject and body of a `mailto:` link.

A cleaned capture is pseudonymized, not anonymous. A hand-picked name or a public host can still point to one person or one company, and a value the cleaner does not recognise stays as it was. Read the cleaned file before it goes anywhere.

**Things to know about `record`.**

- It needs ordinary admin `sudo` rights. It runs one `sudo -n /bin/bash -c '<wrapper>'` that starts `eslogger` and stops it through a private pipe. So a sudoers rule that allows only `eslogger` will refuse it, and an endpoint tool may flag a root inline shell. Stopping never asks for a password, and a closed terminal or a killed script also stops `eslogger`. Like `eslogger` itself it needs Full Disk Access for the terminal.
- It asks for your password once (`sudo -v`) and then needs `sudo -n` to work without asking, right after. On a Mac whose sudoers ask every time (`Defaults timestamp_timeout=0`), it cannot start: `sudo -n` refuses (sudo prints its own reason), and the script ends with `ficus-clean: eslogger stopped before recording anything (see above; does the terminal have Full Disk Access?)` and exit status 1, leaving no capture or key behind. `sudo -v && sudo -n true && echo ok` tells you beforehand: it prints `ok` when `record` can start.
- Ctrl-C may take up to about 5 seconds to stop `eslogger`. If `eslogger` ended on SIGTERM, a cut last line can be counted under `unreadable lines dropped` in the summary.
- The config and seed files, which hold the names being hidden, are deleted from `$TMPDIR` as soon as they are read, before the first event; while recording, `$TMPDIR/ficus-clean.*` holds only pipes and empty files. If the script is force-killed (`kill -9`), those are left behind (nothing in them); delete `$TMPDIR/ficus-clean.*` afterwards.
- At the end a summary is printed on standard error: events in and out, lines dropped as unreadable, events Endpoint Security dropped (gaps in `global_seq_num`), placeholders per kind, credentials replaced, and where the capture and the key are.
