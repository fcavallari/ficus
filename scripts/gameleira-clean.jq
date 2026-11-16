# gameleira-clean.jq: the program scripts/gameleira-clean.sh runs as `jq -n -R -c --unbuffered --slurpfile cfg CONFIG`.
#
# It reads the capture as raw lines, keeps what it has learned across lines in a state value and writes each cleaned
# event to stdout as one line of JSON. It also talks to the script on stderr, one line per message, in two kinds:
#
#   K<TAB>kind<TAB>placeholder<TAB>real as a JSON string      a placeholder was just created; the script appends it to
#                                                              the key file at once, so a cut-short capture keeps its key
#   S<TAB>stats as JSON                                        once, at the very end
#
# Fail closed: a line that does not parse as a JSON object, or an event the cleaner cannot clean, is dropped and counted
# (apart: unreadable, uncleaned). Nothing of it is written anywhere.
#
# $cfg[0] is {seeds: [{kind, value}], domains: [string], key: [{kind, placeholder, real}], keep: [string]}, or
# {prescan: true} for the first pass of `clean -i FILE`, which only lists the programs the capture runs (as a JSON
# array on stdout) so the script can put them in `keep` before the cleaning pass.
#
# The cleaner's state: {map: {<kind>: {<real>: <placeholder>}}, next: {<kind>: int}, keep: {<name>: true},
# words: {<real>: <placeholder>}, multi: {<first word>: {<word count>: true}}, nwords: int, stats: {...}, lastSeq: number|null,
# new: [...]}.
# `map` says which placeholder a real value already has, `next` the number the next placeholder of a kind gets, `keep`
# the names that stay as they are, `words` and `multi` the mapped names free text is searched for (replace_mapped) and
# `nwords` how many there are (jq counts an object's keys one by one, so `length` would cost as much as the object),
# `rel` the cwd while shell code run from a cleaned place is being cleaned (its relative names are names in that folder),
# `sec` whether that code runs security,
# `lastSeq` the highest global_seq_num seen, `new` the key entries the event being cleaned has created. `new` is emptied
# for each event, never deleted and added back: jq does not reuse a deleted key's slot, so that would grow the state
# with every event.

# The first run of digits in a placeholder is its number: user3, Person 3, .name3, name3.pdf, host3.internal.invalid.
def placeholder_number: ([scan("[0-9]+")] | .[0] // "0") | tonumber;

# Events Endpoint Security dropped show as holes in global_seq_num, which is consecutive in a complete capture.
def track_seq($e):
  ($e.global_seq_num | if type == "number" then . else null end) as $n
  | if $n == null then .
    else (if .lastSeq != null and $n > .lastSeq + 1 then .stats.seqGaps += ($n - .lastSeq - 1) else . end)
      | .lastSeq = ([.lastSeq, $n] | map(select(. != null)) | max)
    end;

# ---- placeholders -----------------------------------------------------------------------------------------------
# Every function below that can make a placeholder takes the state as input and gives back the new state with its
# result ({ph, state} or {v, s}): jq has no mutable state, so the state is threaded through every replacement of an
# event, and a name met twice in one event gets one placeholder. New key entries collect in the state's `new` list
# until clean_event hands them to `step`.

# Extensions a name placeholder keeps, compared lower-case: common file types, so `name42.pdf` still says what kind
# of file it was. Anything else after a dot (Jane.Smith, notes.jdoe) is part of the name and is replaced with it.
def FILE_EXTENSIONS: {
  "pdf": true, "doc": true, "docx": true, "dot": true, "dotx": true, "xls": true, "xlsx": true, "xlsm": true,
  "ppt": true, "pptx": true, "pages": true, "numbers": true, "key": true, "txt": true, "rtf": true, "rtfd": true,
  "md": true, "csv": true, "tsv": true, "odt": true, "ods": true, "odp": true, "epub": true, "vsdx": true,
  "jpg": true, "jpeg": true, "png": true, "gif": true, "heic": true, "heif": true, "tif": true, "tiff": true,
  "bmp": true, "svg": true, "webp": true, "ico": true, "icns": true, "psd": true, "raw": true, "dng": true,
  "mp3": true, "m4a": true, "aac": true, "wav": true, "aiff": true, "flac": true, "mp4": true, "m4v": true,
  "mov": true, "avi": true, "mkv": true, "webm": true,
  "zip": true, "tar": true, "gz": true, "tgz": true, "bz2": true, "xz": true, "7z": true, "rar": true, "zst": true,
  "dmg": true, "iso": true, "img": true, "pkg": true, "mpkg": true, "sparseimage": true, "sparsebundle": true,
  "sh": true, "zsh": true, "bash": true, "command": true, "py": true, "rb": true, "pl": true, "js": true, "mjs": true,
  "cjs": true, "ts": true, "php": true, "swift": true, "c": true, "h": true, "cpp": true, "m": true, "go": true,
  "rs": true, "java": true, "kt": true, "scpt": true, "applescript": true, "ps1": true, "bat": true, "jar": true,
  "dylib": true, "so": true, "o": true, "a": true, "bin": true, "exe": true, "html": true, "htm": true, "css": true,
  "plist": true, "json": true, "xml": true, "yaml": true, "yml": true, "toml": true, "ini": true, "conf": true,
  "cfg": true, "db": true, "sqlite": true, "sqlite3": true, "log": true, "tmp": true, "bak": true, "old": true,
  "dat": true, "b64": true, "pem": true, "crt": true, "cer": true, "p12": true, "rsp": true, "lock": true,
  "eml": true, "emlx": true, "mbox": true, "msg": true, "vcf": true, "ics": true
};

# The extension a name placeholder keeps: on the list, and never an account name or seed. Input: the state.
def kept_extension($real):
  ([$real | ltrimstr(".") | capture("^.+\\.(?<e>[A-Za-z0-9]{1,11})$") | .e] | .[0]) as $e
  | if $e == null or FILE_EXTENSIONS[$e | ascii_downcase] != true then ""
    elif ([(.map.user // {}), (.map.seed // {}) | keys[] | ascii_downcase] | index($e | ascii_downcase)) != null then ""
    else "." + $e end;

# What a kind's placeholder number n looks like. A name keeps a leading dot and $ext: .name3, name42.pdf.
def placeholder_form($kind; $real; $n; $ext):
  if $kind == "name" then (if $real | startswith(".") then "." else "" end) + "name\($n)" + $ext
  elif $kind == "user" then "user\($n)"
  elif $kind == "realname" then "Person \($n)"
  elif $kind == "volume" then "vol\($n)"
  elif $kind == "host" then "host\($n).internal.invalid"
  elif $kind == "email" then "person\($n)@example.invalid"
  elif $kind == "seed" then "seed\($n)"
  else "data\($n)" end;

# ---- names that are kept ----------------------------------------------------------------------------------------
# Compared lower-case, so `DerivedData` and `downloads` match too: the standard home folders, the structure folders of
# ~/Library, the tooling folders of src/rules/locations.ts (TOOLING_DIRS), the inside of a bundle, and system folder
# names, so that a home folder called `bin` or `usr` keeps a recognisable shape.
def KEEP: {
  "desktop": true, "documents": true, "downloads": true, "library": true, "movies": true, "music": true,
  "pictures": true, "public": true, "applications": true, ".trash": true,
  "launchagents": true, "launchdaemons": true, "caches": true, "preferences": true, "application support": true,
  "containers": true, "group containers": true, "logs": true, "saved application state": true, "webkit": true,
  "cookies": true, "httpstorages": true, "data": true,
  ".git": true, ".venv": true, "venv": true, ".tox": true, ".direnv": true, ".husky": true, "node_modules": true,
  ".pnpm-store": true, ".build": true, ".terraform": true, ".next": true, ".cargo": true, ".gradle": true, ".m2": true,
  ".cache": true, ".npm": true, ".yarn": true, "target": true, "deriveddata": true,
  "contents": true, "macos": true, "resources": true, "frameworks": true, "helpers": true, "plugins": true,
  "xpcservices": true, "loginitems": true, "versions": true, "current": true, "_codesignature": true,
  "info.plist": true,
  "system": true, "usr": true, "bin": true, "sbin": true, "lib": true, "libexec": true, "include": true,
  "share": true, "local": true, "etc": true, "var": true, "tmp": true, "opt": true, "private": true, "dev": true,
  "cores": true, "db": true, "users": true, "volumes": true, "shared": true, "shims": true,
  "temporaryitems": true, ".localized": true, ".ds_store": true
};

# ---- words the rules look for -------------------------------------------------------------------------------
# PROTECTED: words that are never treated as names outside a path, even when a folder has that name, because a rule
# looks for them in arguments or text. Compared lower-case (the rules match with /i). Built from src/rules/rules.ts
# and src/rules/args.ts: the programs rules decide by (SHELLS, INTERPRETER, RECON_TOOLS and each rule's basename test),
# launchctl subcommands, the security subcommands and trust results, csrutil and networksetup words, osascript's
# dialog words, dscl's authonly, the quarantine attribute, openssl's digests, and the keychain service, browser
# account and wallet names (SAFE_STORAGE, BROWSER_ACCOUNT, WALLET). When a rule starts looking for a new word, add it
# here; the test 'words the rules look for stay outside paths' in test/clean-script.test.ts checks a sample, and
# takes RECON_TOOLS and SHELLS from rules.ts itself. KEEP's names and the programs that ran (state.keep) count too.
def PROTECTED: {
  "sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "csh": true, "tcsh": true, "osascript": true,
  "node": true, "php": true, "curl": true, "wget": true, "security": true, "dscl": true, "launchctl": true,
  "xattr": true, "base64": true, "openssl": true, "spctl": true, "csrutil": true, "networksetup": true, "scutil": true,
  "airport": true, "ps": true, "whoami": true, "id": true, "system_profiler": true, "sw_vers": true, "sysctl": true,
  "ioreg": true, "uname": true, "hostname": true, "ditto": true, "zip": true, "tar": true, "xpcproxy": true,
  "launchd": true, "load": true, "unload": true, "bootstrap": true, "bootout": true, "submit": true, "enable": true,
  "disable": true, "kickstart": true, "gui": true, "user": true, "system": true,
  "find-generic-password": true, "find-internet-password": true, "dump-keychain": true, "unlock-keychain": true,
  "export": true, "add-trusted-cert": true, "authorizationdb": true, "write": true, "read": true, "deny": true,
  "unspecified": true, "trustroot": true, "trustasroot": true, "clear": true, "add": true, "remove": true,
  "authenticated-root": true, "status": true, "on": true, "off": true, "empty": true, "display": true, "dialog": true,
  "displaydialog": true, "hidden": true, "answer": true, "hiddenanswer": true, "javascript": true, "applescript": true,
  "authonly": true, "-authonly": true, "quarantine": true, "com.apple.quarantine": true, "dgst": true, "md4": true,
  "md5": true, "sha1": true, "sha224": true, "sha256": true, "sha384": true, "sha512": true, "rmd160": true,
  "ripemd160": true, "safe": true, "storage": true, "google": true, "chrome": true, "chromium": true, "brave": true,
  "microsoft": true, "edge": true, "opera": true, "vivaldi": true, "arc": true, "browser": true, "exodus": true,
  "electrum": true, "metamask": true, "ledger": true, "live": true, "atomic": true, "wallet": true, "coinomi": true,
  # Subcommands of everyday tools (git, brew, npm, pip, docker, kubectl, launchctl, systemctl-style), so a home folder
  # called commit or install does not rewrite `git commit` or `brew install` in arguments and text.
  "git": true, "brew": true, "npm": true, "pip": true, "pip3": true, "docker": true, "kubectl": true, "make": true,
  "commit": true, "push": true, "pull": true, "clone": true, "fetch": true, "checkout": true, "switch": true,
  "merge": true, "rebase": true, "branch": true, "tag": true, "diff": true, "log": true, "show": true, "reset": true,
  "stash": true, "init": true, "list": true, "install": true, "uninstall": true, "upgrade": true, "update": true,
  "start": true, "stop": true, "restart": true, "run": true, "build": true, "config": true, "exec": true,
  "logs": true, "apply": true, "get": true, "delete": true, "create": true, "describe": true, "test": true,
  "publish": true, "info": true, "search": true, "rm": true, "kill": true, "print": true, "help": true, "version": true
};

# What separates words in free text, and the text as alternating words and separators (joined, the text again).
def WORD_SEP: "\\s/\"'`|;&<>(){}\\[\\]=:,$\\\\";
def WORD_TOKENS: "[^" + WORD_SEP + "]+|[" + WORD_SEP + "]+";

# A word the rules look for, a standard folder name, or a versioned interpreter (python3.11, perl5.30).
def protected_word($w):
  ($w | ascii_downcase) as $l
  | PROTECTED[$l] == true or KEEP[$l] == true or ($l | test("^(?:python|perl|ruby|php|node)[0-9.]*$"));
# A name all of whose words are protected: Chrome Safe Storage, Ledger Live.
def protected_name($n):
  [$n | scan("[^" + WORD_SEP + "]+")] as $w | ($w | length) > 0 and all($w[]; protected_word(.));

# What the keychain rule matches in a `security` argument as a phrase, whatever else is around it: a service ending in
# Safe Storage (SAFE_STORAGE), a wallet name (WALLET), a browser account (BROWSER_ACCOUNT). Such an argument of
# security is never a relative name, and in it a mapped name is replaced only when it has no keychain word
# (state.single, KEYCHAIN_WORDS), so the phrase survives (jdoe Safe Storage becomes user1 Safe Storage). For any other
# program it is a name like others.
def KEYCHAIN_PHRASES:
  "(?i)safe storage$|\\b(?:exodus|electrum|metamask|ledger live|atomic wallet|coinomi)\\b"
  + "|^(?:google )?(?:chrome|chromium|brave|microsoft edge|edge|opera|vivaldi|arc)(?: browser)?$";
def keychain_value($prog; $a): $prog == "security" and ($a | test(KEYCHAIN_PHRASES));
# The words of KEYCHAIN_PHRASES. In a keychain argument a mapped name is replaced only when it has none of them, so
# Board Minutes Safe Storage becomes name5 Safe Storage, but a folder called Gameleira Lab Safe Storage does not take
# the service of that name.
def KEYCHAIN_WORDS: {
  "safe": true, "storage": true, "exodus": true, "electrum": true, "metamask": true, "ledger": true, "live": true,
  "atomic": true, "wallet": true, "coinomi": true, "google": true, "chrome": true, "chromium": true, "brave": true,
  "microsoft": true, "edge": true, "opera": true, "vivaldi": true, "arc": true, "browser": true
};
def keychain_free($n): all($n | scan("[^" + WORD_SEP + "]+"); KEYCHAIN_WORDS[ascii_downcase] != true);

# A new placeholder's real value, made findable in free text (General string cleaning, step 4): names of 4 or more
# characters that are not protected, of the kinds that are names (not hosts, emails or data, which have their own
# steps). For a name of several words (Q3 Financials, M&A Plan: words and separators as WORD_TOKENS splits them),
# `multi` notes under its first word how many it has, so replace_mapped can join that many from the text and look the
# result up in `words`: one lookup per distinct count, however many names share the first word (Screenshot …).
# Input: the state.
def index_word($kind; $real; $ph):
  if ({"user": true, "realname": true, "name": true, "volume": true, "seed": true}[$kind] | not)
     or ($real | length) < 4 or .words[$real] != null or protected_name($real) then .
  else .words[$real] = $ph | .nwords += 1
    | [$real | scan(WORD_TOKENS)] as $t
    | if ($t | length) > 1 then .multi[$t[0]][$t | length | tostring] = true else . end
  end;

# The placeholder `real` already has, or a new one numbered on from `next` (which a loaded key has moved on).
def placeholder($kind; $real):
  .map[$kind][$real] as $have
  | if $have != null then {ph: $have, state: .}
    else (.next[$kind] // 1) as $n
      | placeholder_form($kind; $real; $n; (if $kind == "name" then kept_extension($real) else "" end)) as $ph
      | {ph: $ph, state: (.map[$kind][$real] = $ph | .next[$kind] = $n + 1 | index_word($kind; $real; $ph)
                          | .new += [{kind: $kind, placeholder: $ph, real: $real}])}
    end;

# The state a run starts with: the loaded key's values keep their placeholders, and numbering goes on after them.
def initial_state($cfg):
  { map: (reduce $cfg.key[] as $k ({}; .[$k.kind][$k.real] = $k.placeholder)),
    next: (reduce $cfg.key[] as $k ({}; .[$k.kind] = ([.[$k.kind] // 1, ($k.placeholder | placeholder_number) + 1] | max))),
    keep: (reduce $cfg.keep[] as $n ({}; .[$n] = true)),
    words: {}, multi: {}, nwords: 0, single: false, code: false, rel: null, sec: false,
    stats: { eventsIn: 0, eventsOut: 0, unreadable: 0, uncleaned: 0, seqGaps: 0, redacted: 0, placeholders: {} },
    lastSeq: null, new: [] }
  | reduce $cfg.key[] as $k (.; index_word($k.kind; $k.real; $k.placeholder));

# The structure folders of ~/Library whose first name below is an app's, a vendor's or a bundle ID (Ruling A):
# ~/Library/Application Support/Microsoft is kept, what Microsoft keeps below it is not.
def LIBRARY_STRUCTURE: {
  "application support": true, "caches": true, "containers": true, "group containers": true, "preferences": true,
  "logs": true, "saved application state": true, "httpstorages": true, "webkit": true, "cookies": true,
  "launchagents": true
};

# A bundle (Foo.app, X.framework …) or Go's build folder: kept wherever it is.
def bundle_name: test("(?i:\\.(?:app|framework|bundle|plugin|kext|xpc|appex))$|^(?i:go-build)");
# A reverse-DNS bundle ID (com.apple.launchd.x, with or without .plist), recognised only at the top of a temporary
# folder: it has a common first label and no document extension, so it.budget.cuts.xlsx is a person's file.
def bundle_id:
  test("^(?:group\\.)?(?:com|org|net|io|edu|gov|dev|app)(?:\\.[A-Za-z0-9_-]+){2,}$")
  and (([capture("\\.(?<e>[A-Za-z0-9]+)$").e][0] // "" | ascii_downcase) as $e | $e == "plist" or FILE_EXTENSIONS[$e] != true);

# True when a name in a cleaned place stays as it is: a program that ran (state.keep), a standard name, a bundle, or
# (with $ids, at the top of a temporary folder) a bundle ID. Input: the state.
def kept_name($n; $ids):
  .keep[$n] == true or KEEP[$n | ascii_downcase] == true or ($n | bundle_name) or ($ids and ($n | bundle_id));

# Account names in a name, whole or as dot- or dash-separated parts: jdoe -> user1, com.jdoe.agent.plist ->
# com.user1.agent.plist. Only names that already have a placeholder are replaced, so the state does not change.
# Input: the state.
def replace_accounts($n):
  (.map.user // {}) as $u
  | if $u == {} then $n
    else ($n | ascii_downcase) as $low
      | ($u | with_entries(.key |= ascii_downcase)) as $lu
      | if $lu[$low] != null then $lu[$low]
        elif ($n | test("[.-]")) and any($lu | keys[]; . as $k | $low | contains($k)) then
          [$n | scan("[^.-]+|[.-]")] | map($lu[ascii_downcase] // .) | join("")
        else $n end
    end;

# The file names of the programs and scripts an event runs: the last component of every process's executable.path,
# exec's script.path and dyld_exec_path, a launch item's executable_path, and argv[0]. Input: the event. $ps: the
# paths of the event's strings that hold a / (clean_event has them already; every program path holds one).
def exec_name_path($p):
  $p[-2:] == ["executable", "path"] or $p[-2:] == ["script", "path"] or $p[-1] == "dyld_exec_path" or $p[-1] == "executable_path";
def exec_names($ps):
  . as $e
  | [ ($ps[] | select(exec_name_path(.)) as $p | $e | getpath($p)), .event.exec.args[0]?, .event.btm_launch_item_add.executable_path?
      | strings | sub("/+$"; "") | split("/") | last | select(. != null and . != "") ];

# ---- paths ------------------------------------------------------------------------------------------------------
# %-escapes in a file:// URL, undone (as UTF-8), so a name matches the same name in a plain path.
def hex_byte: ascii_downcase | explode | map(if . >= 97 then . - 87 else . - 48 end) | .[0] * 16 + .[1];
def utf8_text:
  reduce .[] as $b ({cps: [], cur: 0, need: 0};
    if .need > 0 and $b >= 128 and $b < 192 then
      .cur = .cur * 64 + $b - 128 | .need -= 1 | if .need == 0 then .cps += [.cur] else . end
    elif $b < 128 then .cps += [$b] | .need = 0
    elif $b >= 248 or $b < 192 then .cps += [65533] | .need = 0
    elif $b >= 240 then .cur = $b - 240 | .need = 3
    elif $b >= 224 then .cur = $b - 224 | .need = 2
    else .cur = $b - 192 | .need = 1 end)
  | .cps | map(if . > 1114111 or (. >= 55296 and . < 57344) then 65533 else . end) | implode;
def pct_decode:
  if test("%[0-9A-Fa-f]{2}") then gsub("(?<r>(?:%[0-9A-Fa-f]{2})+)"; .r[1:] | split("%") | map(hex_byte) | utf8_text)
  else . end;
# A replacement written into a file:// URL is %-escaped; a name kept as it is keeps its own escapes.
def url_part($url): if $url then @uri else . end;

# Where in a path (split on /, lower-cased, [0] empty) cleaning starts. {from}: names from this index on get
# placeholders; {user}, {vol}: the index of the account or volume name; {lib}: the index of a home's Library folder;
# {top}: the first index inside a temporary folder, where bundle IDs are recognised and App Translocation keeps its
# structure; {} (no from): elsewhere, a system or app place, where only account names are replaced. $tilde: the path
# began with ~/ or ~name/ (a home folder).
def place($lc; $tilde):
  if $tilde then {from: 1, lib: (if $lc[1] == "library" then 1 else null end)}
  else
    (if $lc[1] == "private" and ($lc[2] == "tmp" or $lc[2] == "var") then 2
     elif $lc[1:4] == ["system", "volumes", "data"] then 4 else 1 end) as $b
    | ($lc | length) as $len
    | if $lc[$b] == "users" and $len > $b + 1 then
        if $lc[$b + 1] == "shared" or ($lc[$b + 1] | startswith(".")) then {from: ($b + 1)}
        else {user: ($b + 1), from: ($b + 2), lib: (if $lc[$b + 2] == "library" then $b + 2 else null end)} end
      elif $lc[$b] == "volumes" and $len > $b + 1 then {vol: ($b + 1), from: ($b + 2)}
      elif $lc[$b] == "tmp" then {from: ($b + 1), top: ($b + 1)}
      elif $lc[$b] == "var" and $lc[$b + 1] == "tmp" then {from: ($b + 2), top: ($b + 2)}
      elif $lc[$b] == "var" and $lc[$b + 1] == "folders" and ($lc[$b + 4] == "t" or $lc[$b + 4] == "c") then
        {from: ($b + 5), top: ($b + 5)}
      else {} end
  end;

# True when an elsewhere path has no account name in it. Most paths in a capture are system and app paths, so this is
# checked before going name by name. Input: the state.
def unchanged_elsewhere($text):
  (.map.user // {}) as $mu
  | $mu == {} or (($text | ascii_downcase) as $t | all($mu | keys[]; ascii_downcase as $k | $t | contains($k) | not));

# A name kept by where it is: directly in ~/Library (Mail, Mobile Documents …), the first name below one of its
# structure folders (an app, vendor or bundle ID), and App Translocation with its UUID and `d` at the top of a
# temporary folder (an AppTranslocation folder anywhere else is a name like any other).
def kept_by_place($pl; $lc; $i; $n):
  ($pl.lib != null and ($i == $pl.lib + 1 or ($i == $pl.lib + 2 and LIBRARY_STRUCTURE[$lc[$pl.lib + 1]] == true)))
  or ($pl.top != null and $lc[$pl.top] == "apptranslocation" and ($i == $pl.top or $i == $pl.top + 1
                                                                     or ($i == $pl.top + 2 and $n == "d")));

# System accounts (root, daemon, nobody, _www …) are not people: ~root/ gets no account placeholder.
def system_account($n): $n == "root" or $n == "daemon" or $n == "nobody" or ($n | startswith("_"));

# One absolute path, ~/ or ~name/ path, $HOME/ or ${HOME}/ path, or file:// URL, cleaned name by name (General string
# cleaning, step 1). Input: the state. Output: {v: the cleaned path, s: the state}. Extra leading slashes (//Users/…)
# are kept and the path cleaned as usual. The fixed system structure (/System, but not /System/Volumes/Data, which
# holds /Users; /usr, /bin, /sbin, /dev) is kept whole: nothing a person names lives there. $esc: the path is from
# unquoted shell text, where a backslash escapes the next character (Secret\ Folder is the name Secret Folder).
def clean_path_opts($text; $esc):
  ([$text | capture("^(?<t>~(?<u>[A-Za-z0-9._-]*)|\\$HOME|\\$\\{HOME\\})/")] | .[0]) as $tc
  | ($tc != null) as $home
  | ($tc.u // "") as $tu
  | ($text | if startswith("file://localhost/") then "file://localhost" elif startswith("file://") then "file://"
             elif $home then $tc.t else "" end) as $pre0
  | ($text[($pre0 | length):] | capture("^(?<extra>/*)(?<rest>/[\\s\\S]*)$")? // {extra: "", rest: null}) as $split
  | $split.rest as $rest
  | if $rest == null or (($home | not) and ($rest | test("^/(?:System(?!/Volumes/)|usr|bin|sbin|dev)(?:/|$)"))) then {v: $text, s: .}
    else
      ($pre0 | startswith("file")) as $url
      | ($rest | split("/")) as $raw
      | (if $url then $raw | map(pct_decode)
         elif $esc then $raw | map(if index("\\") != null then gsub("\\\\(?<c>.)"; .c) else . end)
         else $raw end) as $names
      | ($names | map(ascii_downcase)) as $lc
      | place($lc; $home) as $pl
      | if $pl.from == null and unchanged_elsewhere($text) then {v: $text, s: .}
        else
          # ~name/ is that account's home folder: the name becomes its user placeholder.
          (if $tu != "" and (system_account($tu) | not) then placeholder("user"; $tu) | {pre: ("~" + .ph), s: .state} else {pre: $pre0, s: .} end) as $h
          | ($h.pre + $split.extra) as $pre
          | $h.s
          | reduce range(1; $raw | length) as $i ({s: ., out: [""]};
            $names[$i] as $n
            | if $n == "" or $n == "." or $n == ".." then .out += [$raw[$i]]
              elif $i == $pl.user then (.s | placeholder("user"; $n)) as $r | .s = $r.state | .out += [$r.ph]
              elif $i == $pl.vol then (.s | placeholder("volume"; $n)) as $r | .s = $r.state | .out += [$r.ph]
              elif $pl.from != null and $i >= $pl.from then
                # Kept names win over an account or volume of the same name (a NAS share called Downloads).
                if .s.keep[$n] == true then .out += [$raw[$i]]
                elif kept_by_place($pl; $lc; $i; $n) or (.s.map.name[$n] == null and (.s | kept_name($n; $i == $pl.top))) then
                  (.s | replace_accounts($n)) as $k | .out += [if $k == $n then $raw[$i] else $k | url_part($url) end]
                elif .s.map.name[$n] != null then .out += [.s.map.name[$n] | url_part($url)]
                elif (.s.map.user[$n] // .s.map.volume[$n]) != null then .out += [.s.map.user[$n] // .s.map.volume[$n]]
                else (.s | placeholder("name"; $n)) as $r | .s = $r.state | .out += [$r.ph | url_part($url)]
                end
              elif $pl.from == null and (.s.keep[$n] | not) then
                (.s | replace_accounts($n)) as $k | .out += [if $k == $n then $raw[$i] else $k | url_part($url) end]
              else .out += [$raw[$i]] end)
          | {v: ($pre + (.out | join("/"))), s: .s}
        end
    end;
def clean_path($text): clean_path_opts($text; false);

# True for a folder in a place whose names are cleaned (a home, /Users/Shared, /Volumes/<vol>, the temporary folders).
def in_cleaned_place:
  (sub("^/+"; "/") | split("/") | map(ascii_downcase)) as $lc | $lc[0] == "" and place($lc; false).from != null;

# $rel, a name or relative path in the folder $dir, cleaned as the last names of $dir/$rel, so it gets the placeholders
# it would get in a full path. `.`, `..`, leading dots and extensions stay. Input: the state. Output: {v, s}.
def clean_relative_opts($dir; $rel; $esc):
  ($rel | split("/") | length) as $k
  | clean_path_opts(($dir | sub("/+$"; "")) + "/" + $rel; $esc)
  | .v |= (split("/") | .[-$k:] | join("/"));
def clean_relative($dir; $rel): clean_relative_opts($dir; $rel; false);

# ---- mapped names in text ---------------------------------------------------------------------------------------
# Shell's backslash escapes undone: Secret\ Plan.pdf is the name Secret Plan.pdf.
def unescape: if index("\\") != null then gsub("\\\\(?<c>.)"; .c) else . end;

# $str with every name that already has a placeholder replaced, as a whole word or path component (General string
# cleaning, step 4): `open "Q3-acquisition.pdf"` becomes `open "name4.pdf"`. Only names in `words` (4 characters or
# more, not protected) count, and a program that ran (state.keep) stays. The text is split into words once and each
# word looked up, so the cost does not grow with the number of names; a name of several words is tried only where its
# first word is, with shell's backslash escapes undone (Secret\ Plan.pdf). A word with a full stop after it (end of a
# sentence) is looked up without it. Input: the state.
def replace_mapped($str):
  if .nwords == 0 or ($str | length) < 4 then $str
  elif .words[$str] != null and ((.single | not) or keychain_free($str)) then (if .keep[$str] then $str else .words[$str] end)
  else . as $s
    | [$str | scan(WORD_TOKENS)] as $t
    | if any($t[]; $s.words[.] != null or $s.multi[.] != null or (endswith(".") and $s.words[rtrimstr(".")] != null)) | not then $str
      else
        reduce range(0; $t | length) as $i ({out: "", skip: 0};
          if .skip > 0 then .skip -= 1
          else $t[$i] as $w
            | (if $s.multi[$w] == null then null
               else first($s.multi[$w] | keys | map(tonumber) | sort | reverse | .[]
                          | {n: ., real: ($t[$i:$i + .] | join("") | unescape)}
                          | select(.n <= ($t | length) - $i and $s.words[.real] != null and ($s.keep[.real] | not)
                                   and (($s.single | not) or keychain_free(.real)))) // null
               end) as $hit
            | if $hit != null then .out += $s.words[$hit.real] | .skip = $hit.n - 1
              elif $s.words[$w] != null and ($s.keep[$w] | not) then .out += $s.words[$w]
              elif ($w | endswith(".")) and $s.words[$w | rtrimstr(".")] != null and ($s.keep[$w | rtrimstr(".")] | not) then
                .out += $s.words[$w | rtrimstr(".")] + "."
              else .out += $w end
          end)
        | .out
      end
  end;

# Where paths are inside a string. A plain value (an argument, a NAME=value entry): a path starts at the beginning,
# after = or after a : that is followed by a path (PATH lists), and runs to the end, to the next such :, or to a ;, &&,
# || or | followed by a path or a space (/Users/x/Z5;/usr/bin/curl is two paths), with single &s and spaces kept in it
# (M&A Plan, P&L 2026.xlsx). A path field is one path, whole. A cleaned place's path also starts after any other
# character (-I/Users/…, @/tmp/…): reading too much there is safe. ~/, $HOME/ and ${HOME}/ start a home path.
def CLEANED_ROOT: "/(?i:Users|Volumes|tmp|private/tmp|private/var|var/tmp|var/folders)/";
def HOME_PREFIX: "~[A-Za-z0-9._-]*|\\$HOME|\\$\\{HOME\\}";
def PATH_PREFIX: "(?:file://(?:localhost)?|" + HOME_PREFIX + ")?";
def PLAIN_CHAR: "(?:(?!(?:;|&&|\\|\\|?)(?:\\s|~?/))(?:[^:]|:(?!~?/)))";
def PLAIN_PATHS:
  "(?<![^=:])" + PATH_PREFIX + "/" + PLAIN_CHAR + "*"
  + "|" + CLEANED_ROOT + PLAIN_CHAR + "*";

# Free text (sh -c, osascript -e: pipes, quotes, several paths) is read in segments. A quoted string ("…" with
# backslash escapes, or '…') is cleaned inside (QUOTED_PATHS). Outside quotes a path starts at the start or after a
# space or shell character and runs to the first space or shell character; backslash escapes (Secret\ Folder) are part
# of it. The one exception is a volume name with spaces followed by more path (/Volumes/Jdoe Passport/x): a volume
# name often has spaces, and it is the only place a space is read as part of a path. Other words after a path are
# words of their own (see rel_word).
def TEXT_CHAR: "(?:\\\\.|[^\\s\"'`|;&<>():,\\]}])";
def TEXT_NAME_CHAR: "(?:\\\\.|[^\\s\"'`|;&<>():,\\]}/])";
def TEXT_START: "(?<![^\\s=:(<>|;,`\\[{])";
def SPACED_VOLUME: "(?:file://(?:localhost)?)?(?:/System/Volumes/Data)?/(?i:Volumes)/" + TEXT_NAME_CHAR + "+(?:[ \\t]+" + TEXT_NAME_CHAR + "+)+(?=/)";
def TEXT_SEGMENTS:
  "\"(?:\\\\.|[^\"\\\\])*\"|'[^']*'"
  + "|" + SPACED_VOLUME + TEXT_CHAR + "*"
  + "|" + TEXT_START + PATH_PREFIX + "/" + TEXT_CHAR + "*"
  + "|" + CLEANED_ROOT + TEXT_CHAR + "*";
# A path in a cleaned place, at the start of a match.
def CLEANED_START: "^(?:file://(?:localhost)?)?(?:(?:" + HOME_PREFIX + ")/|(?:/System/Volumes/Data)?" + CLEANED_ROOT + ")";
# The words with a / that follow such a path in free text, each a word of its own (cp /Users/x/a.tgz out/x.tgz).
def TEXT_REL_WORD: "(?![-~/$])" + TEXT_NAME_CHAR + "*/" + TEXT_CHAR + "*";

# Inside quotes a path runs to the closing quote, spaces and all (Secret Folder), but stops before a space followed by
# another path (cp "/Users/a/x /tmp/y") and before a quote that ends a word (an inner "…" or \"…\").
def QUOTED_CHAR: "(?:(?![ \\t]+(?:file:|~[A-Za-z0-9._-]*/|\\$\\{?HOME\\}?/|/)|\\\\?[\"'](?:[\\s;|&)]|\\z))[^\\n\\r])";
def QUOTED_PATHS:
  "(?<![^\\s=:(<>|;,`\\[{\"'])" + PATH_PREFIX + "/" + QUOTED_CHAR + "*"
  + "|" + CLEANED_ROOT + QUOTED_CHAR + "*";

# A string that starts with a path in a cleaned place (or NAME= or --option= and one) is one value (M&A Plan, R&D):
# free text only when it also holds a line break or a second path after a space. A string that starts with a system
# or app path (/usr/bin/x;/Users/…, /usr/bin/open "/Users/…") keeps names, so it is read as free text and the paths
# after a separator or quote are cleaned on their own.
def free_text:
  if test("^(?:-{0,2}[A-Za-z_][A-Za-z0-9_-]*=)?(?:(?:" + HOME_PREFIX + ")/|(?:file://(?:localhost)?)?(?:/System/Volumes/Data)?" + CLEANED_ROOT + ")")
  then test("[\\n\\r]|\\s(?:~?/|file:|\\$\\{?HOME)")
  else test("[|;&<>`\\n\\r]|\\$\\(|\\s(?:~?/|file:|\\$\\{?HOME)|[\"'(,](?:~?/|file:|\\$\\{?HOME)") end;
# Shell code (state.code, see shell_text and code_arg: the value of sh -c behind any wrapper, osascript -e …, an ssh remote
# command) with a space and a cleaned-place path, at its start or glued after something (/Users/x/a.sh https://…,
# curl --data-binary @/Users/x/y -H …, cc -I/Users/x/y a.c), is free text too: there a space ends a word, so the path
# ends at it. A single argument (curl -F file=@/Users/x/John Smith.pdf, ssh -i '/Users/x/My Keys') is one value, and
# its path runs to its end.
def glued_in_code: test("\\s") and test(CLEANED_ROOT + "|[@=]~/");

# Where an unquoted path in free text ends when the name it ends in begins a mapped name of several words: the whole
# name (du -sh /Volumes/Jdoe Passport; …, once Jdoe Passport has its placeholder), and any path after it. Input: the state.
def extend_path($str; $start; $end):
  ($str[$start:$end] | split("/") | last) as $last
  | if $last == "" or .multi[$last] == null then $end
    else ($end - ($last | length)) as $at
      | [$str[$at:] | scan(WORD_TOKENS)] as $rt
      | . as $s
      | (first($s.multi[$last] | keys | map(tonumber) | sort | reverse | .[]
               | select(. <= ($rt | length)) | ($rt[0:.] | join("")) | select((. | unescape) as $u | $s.words[$u] != null)) // null) as $real
      | if $real == null then $end
        else ($at + ($real | length)) as $e2
          | $e2 + ([$str[$e2:] | match("^" + TEXT_CHAR + "*") | .length] | .[0] // 0)
        end
    end;

# ---- relative names --------------------------------------------------------------------------------------------
# What is never a relative name. Each is a regex on the whole argument.
#   GLUED_PATH      an option, an absolute, ~ or $ path, or a path glued after @ = : , (cleaned as paths)
#   SHELL_CHARS     shell or AppleScript code
#   URL_SCHEME      scheme://… (looksLikeUrl's first form, src/rules/args.ts)
#   HOST_PORT       host:port, host:port/… (localhost:8080/x, intranet:8080/a.sh)
#   USER_HOST       user@host: (scp, git)
#   LAUNCHD_TARGET  gui/501, user/501/label, pid/42
#   HEADER          Name: value (curl -H 'Accept: text/html')
def GLUED_PATH: "^[/~$-]|^[^A-Za-z0-9\\s.]+/|[@=:,]/";
def SHELL_CHARS: "[\"'`$;|<>\\n\\r(){}]|&&|&\\s";
def URL_SCHEME: "^[A-Za-z][A-Za-z0-9+.-]*://|://";
def HOST_PORT: "^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*:[0-9]+(?:/|$)";
def USER_HOST: "^[^\\s/]*@[^\\s/]*:";
def LAUNCHD_TARGET: "^(?:gui|user|pid|login|session)/[0-9]+(?:/|$)";
def HEADER: "^[A-Za-z][A-Za-z0-9-]*:\\s";
def NOT_RELATIVE: [GLUED_PATH, SHELL_CHARS, URL_SCHEME, HOST_PORT, USER_HOST, LAUNCHD_TARGET, HEADER] | join("|");
# host.tld or host.tld/… (looksLikeUrl's second form) whose last label is not a file extension: evil.com/a.sh is a
# host, board.zip and notes.txt/x are files.
def dotted_host($a):
  [$a | capture("^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.(?<e>[A-Za-z0-9-]+)(?::[0-9]+)?(?:/|$)") | FILE_EXTENSIONS[.e | ascii_downcase] != true] | any;
# wget's options that take the next argument as their value (WGET_SPEC in src/rules/args.ts): a short letter ending a
# cluster (-O, -qO), or a long name. Their values are files, not the URLs the download rule looks for.
def WGET_SHORT_VALUES: "aABDeiIlnoOPQRtTUwX";
def WGET_LONG_VALUES: {
  "--output-document": true, "--output-file": true, "--append-output": true, "--input-file": true, "--user-agent": true,
  "--header": true, "--post-data": true, "--post-file": true, "--directory-prefix": true, "--tries": true,
  "--timeout": true, "--wait": true, "--user": true, "--password": true, "--referer": true, "--load-cookies": true,
  "--save-cookies": true, "--execute": true, "--base": true, "--level": true, "--accept": true, "--reject": true,
  "--domains": true, "--quota": true, "--limit-rate": true, "--method": true, "--body-data": true, "--body-file": true,
  "--ca-certificate": true, "--ca-directory": true, "--certificate": true, "--private-key": true
};
def wget_value_option($prev):
  WGET_LONG_VALUES[$prev] == true
  or (($prev | test("^-[A-Za-z]+$"))
      and ([$prev[1:] | explode[] | [.] | implode] as $l
           | (first(range(0; $l | length) | . as $k | select(WGET_SHORT_VALUES | contains($l[$k]))) // -1) == ($l | length) - 1));
# looksLikeUrl from src/rules/args.ts, as it is: the wget rule only counts an argument it accepts. Keep in step with it.
def looks_like_url:
  test("^[a-z][a-z0-9+.-]*://"; "i") or test("^[a-z0-9-]+(?:\\.[a-z0-9-]+)+(?::[0-9]+)?(?:/|$)"; "i")
  or test("^[a-z0-9-]+(?::[0-9]+(?:/|$)|/)"; "i");

# A relative name to clean under its exec's cwd (General string cleaning, step 2). It looks like a path: it holds a /
# or whitespace, ends in an extension from FILE_EXTENSIONS, or has a mapped name of 4 or more characters as a part. It
# is nothing NOT_RELATIVE matches, not a host (dotted_host), not a program that ran, and not what the rules look for
# (protected_name), so zip, -r, launchctl load and find-generic-password stay. A wget positional ($url_arg), which its
# rule reads with looksLikeUrl, is not a relative name when looks_like_url accepts it (intranet/a.sh); wget's option
# values (-O file, --output-document=file) are files and are cleaned. Input: the state.
def relative_name($url_arg; $a):
  . as $s
  | ($a | test(NOT_RELATIVE) | not)
  and (dotted_host($a) | not)
  and (($url_arg and ($a | looks_like_url)) | not)
  and (($a | test("[/\\s]"))
       or FILE_EXTENSIONS[[$a | capture("\\.(?<e>[A-Za-z0-9]{1,11})$") | .e | ascii_downcase] | .[0] // ""] == true
       or any($a | split("/")[]; length >= 4 and ($s.map.name[.] // $s.map.user[.] // $s.map.volume[.]) != null))
  and (protected_name($a) | not) and ($s.keep[$a] | not);

# A relative argument cleaned. For wget, when the raw one does not look like a URL to the rules but the cleaned one
# would (Q3 Report/x becomes name5/name2, Merger_x/y name6/name7, which looksLikeUrl accepts), it is written
# ./name5/name2, so the download rule sees no URL that was not there. Only for wget: it is the only rule that reads
# arguments with looksLikeUrl, and every cleaned file name (name2.pdf) passes it. Input: the state. Output: {v, s}.
def clean_relative_arg($prog; $dir; $a):
  clean_relative($dir; $a)
  | if $prog == "wget" and (.v | looks_like_url) and ($a | looks_like_url | not) then .v = "./" + .v else . end;

# A word with a / after a cleaned-place path in free text: a word of its own, cleaned name by name as in a cleaned place
# (the exec's cwd when it is one, see shell_words; otherwise /Users/Shared stands for "some cleaned folder"), unless it is a host, URL or launchd target, which only has mapped
# names replaced. Input: the state. Output: {v, s}.
def rel_word($w):
  if ($w | test(URL_SCHEME + "|" + HOST_PORT + "|" + USER_HOST + "|" + LAUNCHD_TARGET)) or dotted_host($w) then {v: replace_mapped($w), s: .}
  else clean_relative_opts(.rel // "/Users/Shared"; $w; true) end;

# An argument, or the value of --option=value or NAME=value: {pre: what stays, val: what may be a relative name}.
def option_value($a):
  ([$a | capture("^(?<pre>--?[A-Za-z0-9][A-Za-z0-9_-]*=|[A-Za-z_][A-Za-z0-9_]*=)(?<val>.+)$")] | .[0]) // {pre: "", val: $a};

# ---- relative names in shell code ------------------------------------------------------------------------------
# Shell code run from a cleaned place (state.rel is the exec's cwd: sh -c behind any wrapper, su -c, an ssh remote
# command) names files relative to that folder. The text between its absolute paths is split into words on whitespace
# and shell operators (| ; & < > ( ), so 2>err.log is 2, > and err.log), a backslash keeping the next character in the
# word (Merger\ Deck.key); a quoted string is one word. Each word goes through relative_name, the test an argument
# gets, and is cleaned as a name in the cwd: hosts, URLs, user@host:, launchd targets, options and the words the rules
# look for stay; a short mapped name that is a folder of a relative path (HR/Pay.pdf) gets its placeholder.
def SHELL_SEP: "\\s|;&<>()\"'`";
def SHELL_TOKENS: "(?:\\\\.|[^" + SHELL_SEP + "])+|[" + SHELL_SEP + "]+";
def GLOB: "[*?\\[]";
# One word of shell code ($quoted: the inside of a quoted string) cleaned as a relative name: {v, s}, or null when it
# is not one. NAME=value and --option=value are cleaned in the value. An unquoted word with a glob (Delta/*.pdf) is
# cleaned in the folders before the glob. In code that runs security (state.sec), a quoted keychain phrase (jdoe Safe
# Storage) is left to replace_mapped: which program it belongs to is not known here. In any other code it is a name.
# Input: the state.
def shell_word_clean($w; $quoted):
  .rel as $dir
  | (if $quoted then {pre: "", val: $w} else option_value($w) end) as $o
  | (if $quoted then $o.val else $o.val | unescape end) as $u
  | if $quoted and .sec and ($u | test(KEYCHAIN_PHRASES)) then null
    elif ($quoted | not) and ($u | test(GLOB)) then
      ($o.val | split("/")) as $c
      | (first(range(0; $c | length) | select($c[.] | test(GLOB))) // 0) as $g
      | if $g == 0 then null
        else ($c[0:$g] | join("/") + "/") as $head
          | if relative_name(false; $head | unescape) then
              clean_relative_opts($dir; $head; true) | .v = $o.pre + .v + ($c[$g:] | join("/"))
            else null end
        end
    elif relative_name(false; $u) then clean_relative_opts($dir; $o.val; $quoted | not) | .v = $o.pre + .v
    else null end;
# Unquoted shell code with no absolute path in it: its relative words cleaned, mapped names replaced in the rest.
# Input: the state. Output: {v, s}.
def shell_words($str):
  reduce ($str | scan(SHELL_TOKENS)) as $t ({s: ., out: "", pend: ""};
    if $t | test("^[" + SHELL_SEP + "]") then .pend += $t
    else (.s | shell_word_clean($t; false)) as $r
      | if $r == null then .pend += $t
        else .pend as $p | .out += (.s | replace_mapped($p)) + $r.v | .pend = "" | .s = $r.s end
    end)
  | .pend as $p | {v: (.out + (.s | replace_mapped($p))), s: .s};
# The text around the paths clean_matches finds: mapped names replaced and, in shell code run from a cleaned place,
# relative names cleaned ($mode "text": words; "quoted": the whole inside of a quoted string). Input: the state.
def clean_free($str; $mode):
  if .rel == null or $mode == "plain" then {v: replace_mapped($str), s: .}
  elif $mode == "quoted" then shell_word_clean($str; true) // {v: replace_mapped($str), s: .}
  else shell_words($str) end;

# Every path the regex finds in $str cleaned, and mapped names replaced in the text between. $mode: "plain",
# "quoted" (the inside of a quoted string) or "text" (free text in segments, see TEXT_SEGMENTS). A match that begins
# // right after a : is a URL's host part (https://host/…), left for the host step. Input: the state. Output: {v, s}.
def clean_matches($re; $str; $mode):
  [$str | match($re; "g")] as $ms
  | (if $mode == "text" then "text" else "plain" end) as $gm
  | if $ms == [] then clean_free($str; $mode)
    else
      reduce $ms[] as $m ({s: ., out: "", at: 0};
        if $m.offset < .at then .
        else
          .at as $at
          | ($m.offset + $m.length) as $end0
          | (if $m.offset - $at < 4 and .s.rel == null then {v: $str[$at:$m.offset], s: .s}
             else .s | clean_free($str[$at:$m.offset]; $gm) end) as $g
          | .s = $g.s | $g.v as $gap
          | $m.string[0:1] as $q
          | if $mode == "text" and ($q == "\"" or $q == "'") then
              (.s | clean_matches(QUOTED_PATHS; $m.string[1:-1]; "quoted")) as $r
              | .out += $gap + $q + $r.v + $q | .s = $r.s | .at = $end0
            elif ($m.string | startswith("//")) and $m.offset > 0 and $str[$m.offset - 1:$m.offset] == ":" then
              .out += $gap + $m.string | .at = $end0
            else
              (if $mode == "text" then .s | extend_path($str; $m.offset; $end0) else $end0 end) as $end
              | (.s | clean_path_opts($str[$m.offset:$end]; $mode == "text")) as $r
              | .out += $gap + $r.v | .s = $r.s | .at = $end
              | if $mode == "text" and ($str[$m.offset:$end] | test(CLEANED_START)) then
                  ([$str[$end:] | match("^(?:[ \\t]+" + TEXT_REL_WORD + ")+") | .string] | .[0] // "") as $tail
                  | if $tail == "" then .
                    else reduce ($tail | [scan("[ \\t]+|[^ \\t]+")])[] as $w (.;
                        if ($w | test("^[ \\t]")) then .out += $w else (.s | rel_word($w)) as $r | .out += $r.v | .s = $r.s end)
                      | .at = $end + ($tail | length)
                    end
                else . end
            end
        end)
      | .at as $at
      | (if ($str | length) - $at < 4 and .s.rel == null then {v: $str[$at:], s: .s} else .s | clean_free($str[$at:]; $gm) end) as $g
      | {v: (.out + $g.v), s: $g.s}
    end;

# A string with the paths in it cleaned and mapped names replaced. $field: the string is a path field (…path,
# item_url, app_url).
def clean_string($str; $field):
  if $field then
    (if ($str | test("^(?:/|~[A-Za-z0-9._-]*/|file://)")) then clean_path($str) else {v: replace_mapped($str), s: .} end)
  elif .rel != null then clean_matches(TEXT_SEGMENTS; $str; "text")
  elif ($str | index("/")) == null then {v: replace_mapped($str), s: .}
  elif ($str | free_text) or (.code and ($str | glued_in_code)) then clean_matches(TEXT_SEGMENTS; $str; "text")
  else clean_matches(PLAIN_PATHS; $str; "plain") end;

# ---- events -----------------------------------------------------------------------------------------------------
# Fields left unchanged (Precedence, step 1): team IDs, cdhashes, times, tty paths, entitlements; and signing_id,
# which a later step cleans by its own rule. Numbers are never strings, so the walk does not see them.
def exempt($p):
  {"team_id": true, "cdhash": true, "time": true, "start_time": true, "signing_id": true}[$p[-1] | tostring]
  or ($p | index(["entitlements"])) != null or ($p | index(["tty"])) != null;
def path_field($p):
  {"path": true, "dyld_exec_path": true, "executable_path": true, "item_url": true, "app_url": true}[$p[-1] | tostring] == true;

# A folder and a bare name in it, as some events report a new file: create and rename's new_path {dir, filename},
# link's {target_dir, target_filename}, clone's and copyfile's {target_dir, target_name}. BARE_NAMES: each name's key
# and its folder's. named_in_dir gives the keys of the folder and the name, or null.
def BARE_NAMES: {"filename": "dir", "target_filename": "target_dir", "target_name": "target_dir"};
def named_in_dir($p):
  if type != "object" then null
  else . as $o
    | first(BARE_NAMES | to_entries[]
            | select(($o[.key] | type) == "string" and ($o[.value] | type) == "object" and ($o[.value].path | type) == "string"
                     and (.key != "filename" or $p[-1] == "new_path"))
            | {dir: .value, name: .key}) // null
  end;

# What the walk stops at: a string that holds a / (no path without one), every string once there are mapped names
# to look for or relative arguments to clean ($all), and the objects named_in_dir knows.
def worth_cleaning($all):
  if type == "string" then $all or index("/") != null
  elif type == "object" then . as $o | any(BARE_NAMES | keys_unsorted[]; ($o[.] | type) == "string")
  else false end;

# security run in shell code, as a word: security, /usr/bin/security.
def SECURITY_WORD: "(?:^|[\\s;&|(`])(?:[^\\s;&|()`]*/)?security(?=[\\s;&|)`]|$)";

# Programs whose -c or -e value (or -lc, -ne …, --eval, --command) is code: free text, never a relative name.
def CODE_PROGRAMS: "^(?:sh|bash|zsh|dash|ksh|csh|tcsh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|osascript|node|php)$";
def code_value($prog; $prev): ($prog | test(CODE_PROGRAMS)) and ($prev | test("^-[A-Za-z]*[ceE]$|^--(?:eval|command)$"));

# ssh's options that take a value (ssh(1)): attached (-i/Users/x/key, -oIdentityFile=…) or the next argument. A value
# letter that ends a cluster (-i, -vi) takes the next argument.
def SSH_NEXT_VALUE: "^-[^bcDEeFIiJLlmOopQRSWwB]*[bcDEeFIiJLlmOopQRSWwB]$";
# The index in ssh's argv where the remote command starts: the first argument after the host that is neither an
# option nor an option's value (ssh reads options after the host too: ssh host -p 2222 -i key cmd). null when there is
# no command. The host is the first such argument. Everything before the command is a single value. After the host,
# -- ends the options.
def ssh_command_index($args):
  first(foreach range(1; $args | length) as $i ({skip: false, host: false, cmd: null};
          $args[$i] as $a
          | if .skip then .skip = false
            elif ($a | type) != "string" then .
            elif $a == "--" then (if .host then .cmd = $i + 1 else . end)
            elif $a | startswith("-") then .skip = ($a | test(SSH_NEXT_VALUE))
            elif .host then .cmd = $i
            else .host = true end;
          .cmd | select(. != null))) // null;

# A shell, as an argv element: sh, /bin/zsh. su counts: its -c value is run by the account's shell. An assignment
# (SHELL=/bin/zsh) or an option's value (--shell=/bin/bash) is not one. LOGIN_SHELL_WORD: argv[0] may also be -zsh, a
# login shell (how sudo -i and su -l run it); anywhere else -sh or -su is a cluster of options (du -sh, grep -sh).
def SHELL_WORD: "^(?:[^=\\s]*/)?(?:sh|bash|zsh|dash|ksh|csh|tcsh|fish|su)$";
def LOGIN_SHELL_WORD: "^(?:[^=\\s]*/)?-?(?:sh|bash|zsh|dash|ksh|csh|tcsh|fish|su)$";
# A shell's options that take the next argument as their value (bash -o pipefail -c …).
def SHELL_VALUE_OPTIONS: {"-o": true, "+o": true, "-O": true, "+O": true, "--rcfile": true, "--init-file": true};
# True when argv[$i] is shell code, where a space ends a word and relative names are files: ssh's remote command ($cmd:
# ssh_command_index, null for other programs), or the value of -c or of a cluster ending in c (-lc, -xc) when a shell
# comes before it in argv, whatever runs that shell (sh -c, sudo sh -c, env -i bash --noprofile -c, xargs sh -c,
# su - root -c), with only the shell's options between the two: in `bash deploy.sh -c X` the -c is the script's own
# option and X a single value. su takes an account name there, so anything may stand between su and -c.
def shell_text($args; $i; $cmd):
  ($cmd != null and $i >= $cmd)
  or ((($args[$i - 1] | if type == "string" then . else "" end) | test("^-[A-Za-z]*c$"))
      and any(range(0; $i - 1);
              . as $j
              | ($args[$j] | type) == "string" and ($args[$j] | test(if $j == 0 then LOGIN_SHELL_WORD else SHELL_WORD end))
                and (($args[$j] | test(if $j == 0 then "(?:^|/)-?su$" else "(?:^|/)su$" end))
                     or all(range($j + 1; $i - 1);
                            ($args[.] | type) == "string"
                            and (($args[.] | test("^[-+]")) or SHELL_VALUE_OPTIONS[$args[. - 1] | tostring] == true)))));
# True when argv[$i] is code of any kind: shell code ($sh: shell_text), or the value of a code option of another
# program that runs code (code_value: python -c, perl -e, osascript -e, node --eval …).
def code_arg($prog; $args; $i; $sh):
  $sh or ((($prog | test(LOGIN_SHELL_WORD)) | not)
          and code_value($prog | ltrimstr("-"); $args[$i - 1] | if type == "string" then . else "" end));

# The value-taking short options of wget and curl (WGET_SPEC, CURL_SPEC in src/rules/args.ts).
def SHORT_VALUES($prog): if $prog == "wget" then "aABDeiIlnoOPQRtTUwX" elif $prog == "curl" then "AbcCdDeEFHKmoPQrtTuUwxXyYz" else "" end;
# For wget and curl, a short cluster whose value-taking letter has its value attached (-OAcme.pdf, -sLoout.txt):
# {pre: the cluster up to that letter, val: the value}; otherwise option_value.
def arg_value($prog; $a):
  SHORT_VALUES($prog) as $sv
  | if $sv != "" and ($a | test("^-[A-Za-z]")) and ($a | startswith("--") | not) then
      ([$a[1:] | explode[] | [.] | implode] as $l
       | first(range(0; $l | length) | . as $k | select($sv | contains($l[$k]))) // null) as $k
      | if $k != null and $k < ($a | length) - 2 then {pre: $a[0:$k + 2], val: $a[$k + 2:]} else option_value($a) end
    else option_value($a) end;

# The event (input) cleaned, with the state the cleaning leaves and the key entries it created:
#   {event, state, new: [{kind, placeholder, real}]}
# Every string is walked, so a field nobody thought of cannot carry a name through. Programs the event runs are kept
# before any of its strings is cleaned. create.acl is dropped (it can name users and groups). A new file's separate
# name (named_in_dir) is cleaned as the last name of its folder. When an exec's cwd is in a cleaned place, its
# arguments that are relative names are cleaned as names in that folder; option names stay, and so does argv[0]
# unless it has folders (./Q3 Kit/tool: the folders are cleaned, the program's name is kept as a program that ran).
def clean_event($state):
  (if (.event.create | type) == "object" then del(.event.create.acl) else . end) as $e
  | (try $e.event.exec.cwd.path catch null) as $cwd
  | (try $e.event.exec.args catch null) as $args
  | (($cwd | type) == "string" and ($args | type) == "array" and ($cwd | in_cleaned_place)) as $relc
  | (if ($args | type) == "array" then ($args[0] | if type == "string" then split("/") | last else "" end) else "" end) as $prog
  | (if $prog == "ssh" then ssh_command_index($args) else null end) as $cmd
  | [$e | paths(worth_cleaning($relc or $state.nwords > 0))] as $ps
  | (reduce ($e | exec_names($ps)[]) as $n ($state; if .keep[$n] then . else .keep[$n] = true end)) as $s0
  | reduce $ps[] as $p ({e: $e, s: ($s0 | .new = [])};
      ($e | getpath($p)) as $v
      | if ($v | type) == "object" then
          ($v | named_in_dir($p)) as $k
          | if $k == null then .
            else $v[$k.dir].path as $dir | $v[$k.name] as $name
              | if ($dir | startswith("/")) and $name != "" then
                  (.s | clean_relative($dir; $name)) as $r
                  | .s = $r.s | .e |= setpath($p + [$k.name]; $r.v)
                else . end
            end
        elif exempt($p) then .
        elif BARE_NAMES[$p[-1] | tostring] != null and ($e | getpath($p[:-1]) | named_in_dir($p[:-1])) != null then .
        else
          (($p | length) == 4 and $p[0:3] == ["event", "exec", "args"]) as $arg
          | ($arg and $p[3] > 0 and keychain_value($prog; $v)) as $kc
          | ($arg and $p[3] > 0 and shell_text($args; $p[3]; $cmd)) as $sh
          | ($arg and $p[3] > 0 and code_arg($prog; $args; $p[3]; $sh)) as $code
          # Shell code is never a relative name. One word of an ssh command (ssh host ls Board/Q3.pdf) can be.
          | if $relc and $arg and ($kc | not)
               and (if $p[3] == 0 then ($v | index("/")) != null
                    else ($code and ($cmd == null or ($v | test("\\s")))) | not end)
               and (arg_value($prog; $v) as $o
                    | ($prog == "wget" and $o.pre == "" and $p[3] > 0
                       and (wget_value_option($args[$p[3] - 1] | if type == "string" then . else "" end) | not)) as $url_arg
                    | .s | relative_name($url_arg; $o.val)) then
              arg_value($prog; $v) as $o
              | (.s | clean_relative_arg($prog; $cwd; $o.val)) as $r
              | .s = $r.s | .e |= setpath($p; $o.pre + $r.v)
            else
              (if $kc then .s | .single = true | clean_string($v; false) | .s.single = false
                 elif $code then .s | .code = true | .rel = (if $relc and $sh then $cwd else null end)
                                 | .sec = ($v | test(SECURITY_WORD))
                                 | clean_string($v; false) | .s.code = false | .s.rel = null | .s.sec = false
                 else .s | clean_string($v; path_field($p)) end) as $r
              | .s = $r.s | if $r.v != $v then .e |= setpath($p; $r.v) else . end
            end
        end)
  | {event: .e, state: .s, new: .s.new};

# One raw line against the state: {s: new state, emit: [event to write], new: [key entries]}.
def step($line):
  . as $s
  | if ($line | test("^[ \t\r]*$")) then {s: $s, emit: [], new: []}
    else
      ($s | .stats.eventsIn += 1) as $counted
      | (try ($line | fromjson) catch null) as $e
      | if ($e | type) != "object" then {s: ($counted | .stats.unreadable += 1), emit: [], new: []}
        else
          ($counted | track_seq($e)) as $seen
          | ([try ($e | clean_event($seen)) catch null] | .[0]) as $r
          # A cleaning that failed, yielded nothing, or produced no state: dropped, and counted apart from lines that
          # do not parse, so a bug in this program cannot thin a capture unnoticed.
          | if ($r | type) != "object" or ($r.state | type) != "object" or ($r.new | type) != "array" then
              {s: ($seen | .stats.uncleaned += 1), emit: [], new: []}
            else
              { s: (reduce $r.new[] as $n ($r.state; .stats.placeholders[$n.kind] += 1) | .stats.eventsOut += 1),
                emit: [$r.event], new: $r.new }
            end
        end
    end;

# Side channel first, then the event, so a key line is written before the event that needs it is.
def extract:
  (.new[] | "K\t\(.kind)\t\(.placeholder)\t\(.real | tojson)\n" | stderr | empty),
  (if .done then "S\t\(.s.stats | tojson)\n" | stderr | empty else empty end),
  .emit[];

# The prescan of `clean -i FILE`: the names of every program the capture runs, so a dropper's name is kept from its
# first appearance, before it runs. Lines that do not parse, or events it cannot read, are skipped here (the cleaning
# pass drops and counts them).
def prescan:
  reduce (inputs | (try fromjson catch null) | objects
          | try exec_names([paths(type == "string" and index("/") != null)])[] catch empty) as $n ({}; .[$n] = true)
  | keys;

if $cfg[0].prescan == true then prescan
else
  foreach ((inputs | {line: .}), {end: true}) as $in (
    {s: initial_state($cfg[0]), emit: [], new: []};
    if $in.end then {s: .s, emit: [], new: [], done: true} else .s | step($in.line) end;
    extract
  )
end
