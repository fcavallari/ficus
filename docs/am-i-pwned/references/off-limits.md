# What the agent will not touch

The rule behind it: if reading a thing could put a secret in the transcript, do not read it; report that it exists and let the person look. A reviewer should be able to audit a transcript against this table.

| Category | Off limits | Allowed instead |
| --- | --- | --- |
| SSH | Key files, `authorized_keys` contents, `known_hosts` | Existence, key count, modification time |
| Credential stores | Keychain files, Windows Credential Manager, GNOME Keyring, password-manager data | Nothing. Do not open them, copy them or list their items |
| Cloud and dev CLIs | `~/.aws`, `~/.config/gh`, `~/.kube`, `~/.npmrc`, `~/.docker/config.json`, `~/.gitconfig` credential helpers' stores | Existence and mtime only. `git config --global --get core.hooksPath` is fine; it is a path, not a secret |
| Scheduled jobs | `crontab -l` contents (a line can carry a token), `at` job files | Line count, and the keyword with its line number (`crontab -l \| grep -n -o -E 'curl\|wget\|base64\|eval\|osascript\|/tmp/'`) |
| Shell | History files, environment variables (`env`, `printenv`, `ps eww`), `.env` files | rc files: print only the matching keyword and line number (`grep -n -o`), never the line |
| Process arguments | Full command lines can hold tokens and passwords | Use `ps -axo pid,ppid,user,etime,comm`. Print arguments only for one named suspect, after redacting anything token-like, and only the flags you need (for example `--remote-debugging-port`) |
| Browser | Cookies, Login Data, session storage, bookmarks, history | Extension IDs and names; native-messaging manifest file names |
| Downloads | File contents, source URLs | Downloading app and timestamp |
| Documents and notes | Contents of any user document, note or spreadsheet. Never grep them for passwords | Nothing |
| Privilege | Running `sudo`, or asking for a password in chat | Give the exact command; the person runs it and shares the output |

Reading the TCC database (`TCC.db`) is allowed: it lists which apps hold which permissions, and holds no secrets. It needs Terminal to have Full Disk Access; if it does not, say you could not check.

If a transcript shows an item from the *Off limits* column being read, the check has failed: tell the person to rotate whatever was exposed.
