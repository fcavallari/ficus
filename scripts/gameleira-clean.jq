# gameleira-clean.jq: the program scripts/gameleira-clean.sh runs as `jq -n -R -c --unbuffered --slurpfile cfg CONFIG`.
#
# It reads the capture as raw lines, keeps what it has learned across lines in a state value and writes each cleaned
# event to stdout as one line of JSON. It also talks to the script on stderr, one line per message, in two kinds:
#
#   K<TAB>kind<TAB>placeholder<TAB>real as a JSON string      a placeholder was just created; the script appends it to
#                                                              the key file at once, so a cut-short capture keeps its key
#   S<TAB>stats as JSON                                        once, at the very end
#
# Fail closed: a line that does not parse as a JSON object, or an event the cleaner cannot clean, is dropped and counted.
# Nothing of it is written anywhere.
#
# $cfg[0] is {seeds: [{kind, value}], domains: [string], key: [{kind, placeholder, real}], keep: [string]}, or
# {prescan: true} for the first pass of `clean -i FILE`, which only lists the programs the capture runs (as a JSON
# array on stdout) so the script can put them in `keep` before the cleaning pass.
#
# The cleaner's state: {map: {<kind>: {<real>: <placeholder>}}, next: {<kind>: int}, keep: {<name>: true},
# words: {<real>: <placeholder>}, multi: {<first word>: [{real, n}]}, nwords: int, stats: {...}, lastSeq: number|null,
# new: [...]}.
# `map` says which placeholder a real value already has, `next` the number the next placeholder of a kind gets, `keep`
# the names that stay as they are, `words` and `multi` the mapped names free text is searched for (replace_mapped) and
# `nwords` how many there are (jq counts an object's keys one by one, so `length` would cost as much as the object),
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
  "electrum": true, "metamask": true, "ledger": true, "live": true, "atomic": true, "wallet": true, "coinomi": true
};

# What separates words in free text, and the text as alternating words and separators (joined, the text again).
def WORD_SEP: "\\s/\"'`|;&<>(){}\\[\\]=:,$\\\\";
def WORD_TOKENS: "[^" + WORD_SEP + "]+|[" + WORD_SEP + "]+";

# A word the rules look for, a standard folder name, or a versioned interpreter (python3.11, perl5.30).
def protected_word($w):
  ($w | ascii_downcase) as $l
  | PROTECTED[$l] == true or KEEP[$l] == true or ($l | test("^(?:python|perl|ruby|php|node)[0-9.]*$"));
# What the rules match as a phrase, whatever else is around it: a keychain service ending in Safe Storage
# (SAFE_STORAGE), a wallet name (WALLET), a browser account (BROWSER_ACCOUNT), and osascript's dialog words.
def RULE_PHRASES:
  "(?i)safe storage$|\\b(?:exodus|electrum|metamask|ledger live|atomic wallet|coinomi)\\b|display ?dialog|hidden ?answer"
  + "|^(?:google )?(?:chrome|chromium|brave|microsoft edge|edge|opera|vivaldi|arc)(?: browser)?$";
# A name the rules need as it is: all its words are protected (Chrome Safe Storage, Ledger Live), or it holds a rule
# phrase (Gameleira Lab Safe Storage, Exodus Backup).
def protected_name($n):
  ([$n | scan("[^" + WORD_SEP + "]+")] as $w | ($w | length) > 0 and all($w[]; protected_word(.)))
  or ($n | test(RULE_PHRASES));

# A new placeholder's real value, made findable in free text (General string cleaning, step 4): names of 4 or more
# characters that are not protected, of the kinds that are names (not hosts, emails or data, which have their own
# steps). A name of several words (Q3 Financials, M&A Plan) is also listed under its first word, longest first, so
# replace_mapped finds it from that word without looking at every name. Input: the state.
def index_word($kind; $real; $ph):
  if ({"user": true, "realname": true, "name": true, "volume": true, "seed": true}[$kind] | not)
     or ($real | length) < 4 or .words[$real] != null or protected_name($real) then .
  else .words[$real] = $ph | .nwords += 1
    | [$real | scan(WORD_TOKENS)] as $t
    | if ($t | length) > 1 then .multi[$t[0]] = ((.multi[$t[0]] // []) + [{real: $real, n: ($t | length)}] | sort_by(-.n))
      else . end
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
    words: {}, multi: {}, nwords: 0,
    stats: { eventsIn: 0, eventsOut: 0, unreadable: 0, seqGaps: 0, redacted: 0, placeholders: {} },
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
def clean_relative($dir; $rel):
  ($rel | split("/") | length) as $k
  | clean_path(($dir | sub("/+$"; "")) + "/" + $rel)
  | .v |= (split("/") | .[-$k:] | join("/"));

# ---- mapped names in text ---------------------------------------------------------------------------------------
# $str with every name that already has a placeholder replaced, as a whole word or path component (General string
# cleaning, step 4): `open "Q3-acquisition.pdf"` becomes `open "name4.pdf"`. Only names in `words` (4 characters or
# more, not protected) count, and a program that ran (state.keep) stays. The text is split into words once and each
# word looked up, so the cost does not grow with the number of names; a name of several words is tried only where its
# first word is. A word with a full stop after it (end of a sentence) is looked up without it. Input: the state.
def replace_mapped($str):
  if .nwords == 0 or ($str | length) < 4 then $str
  elif .words[$str] != null then (if .keep[$str] then $str else .words[$str] end)
  else . as $s
    | [$str | scan(WORD_TOKENS)] as $t
    | if any($t[]; $s.words[.] != null or $s.multi[.] != null or (endswith(".") and $s.words[rtrimstr(".")] != null)) | not then $str
      else
        reduce range(0; $t | length) as $i ({out: "", skip: 0};
          if .skip > 0 then .skip -= 1
          else $t[$i] as $w
            | (first(($s.multi[$w] // [])[] | select(. as $m | ($t[$i:$i + $m.n] | join("")) == $m.real and ($s.keep[$m.real] | not))) // null) as $hit
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
# of it. A path in a cleaned place also runs on over a space when the next word holds a / (/Volumes/Jdoe Passport/x):
# shell would split it there, but reading too much in a cleaned place is safe, and the words cannot leak.
def TEXT_CHAR: "(?:\\\\.|[^\\s\"'`|;&<>():,\\]}])";
def TEXT_ON: "[ \\t]+(?=[^\\s\"'`|;&<>():,\\]}/~$-][^\\s\"'`|;&<>():,\\]}]*/)";
def TEXT_START: "(?<![^\\s=:(<>|;,`\\[{])";
def TEXT_SEGMENTS:
  "\"(?:\\\\.|[^\"\\\\])*\"|'[^']*'"
  + "|" + TEXT_START + "(?:" + HOME_PREFIX + "|(?:file://(?:localhost)?)?(?:/System/Volumes/Data)?(?=" + CLEANED_ROOT + "))/(?:" + TEXT_CHAR + "|" + TEXT_ON + ")*"
  + "|" + TEXT_START + PATH_PREFIX + "/" + TEXT_CHAR + "*"
  + "|" + CLEANED_ROOT + "(?:" + TEXT_CHAR + "|" + TEXT_ON + ")*";
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

# Where an unquoted path in free text ends when the name it ends in begins a mapped name of several words: the whole
# name (du -sh /Volumes/Jdoe Passport; …, once Jdoe Passport has its placeholder), and any path after it. Input: the state.
def extend_path($str; $start; $end):
  ($str[$start:$end] | split("/") | last) as $last
  | if $last == "" or .multi[$last] == null then $end
    else ($end - ($last | length)) as $at
      | (first(.multi[$last][] | .real | select(length > ($last | length) and $str[$at:$at + length] == .)) // null) as $real
      | if $real == null then $end
        else ($at + ($real | length)) as $e2
          | $e2 + ([$str[$e2:] | match("^" + TEXT_CHAR + "*") | .length] | .[0] // 0)
        end
    end;

# Every path the regex finds in $str cleaned, and mapped names replaced in the text between. $mode: "plain",
# "quoted" (the inside of a quoted string) or "text" (free text in segments, see TEXT_SEGMENTS). A match that begins
# // right after a : is a URL's host part (https://host/…), left for the host step. Input: the state. Output: {v, s}.
def clean_matches($re; $str; $mode):
  [$str | match($re; "g")] as $ms
  | if $ms == [] then {v: replace_mapped($str), s: .}
    else
      reduce $ms[] as $m ({s: ., out: "", at: 0};
        if $m.offset < .at then .
        else
          .at as $at
          | ($m.offset + $m.length) as $end0
          | (if $m.offset - $at < 4 then $str[$at:$m.offset] else .s | replace_mapped($str[$at:$m.offset]) end) as $gap
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
            end
        end)
      | .at as $at
      | {v: (.out + (if ($str | length) - $at < 4 then $str[$at:] else .s | replace_mapped($str[$at:]) end)), s: .s}
    end;

# A string with the paths in it cleaned and mapped names replaced. $field: the string is a path field (…path,
# item_url, app_url).
def clean_string($str; $field):
  if $field then
    (if ($str | test("^(?:/|~[A-Za-z0-9._-]*/|file://)")) then clean_path($str) else {v: replace_mapped($str), s: .} end)
  elif ($str | index("/")) == null then {v: replace_mapped($str), s: .}
  elif ($str | free_text) then clean_matches(TEXT_SEGMENTS; $str; "text")
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
# link's {target_dir, target_filename}, clone's and copyfile's {target_dir, target_name}. The keys of the folder and the
# name, or null.
def named_in_dir($p):
  if type != "object" then null
  elif $p[-1] == "new_path" and (.dir | type) == "object" and (.dir.path | type) == "string" and (.filename | type) == "string" then
    {dir: "dir", name: "filename"}
  elif (.target_dir | type) == "object" and (.target_dir.path | type) == "string" then
    if (.target_filename | type) == "string" then {dir: "target_dir", name: "target_filename"}
    elif (.target_name | type) == "string" then {dir: "target_dir", name: "target_name"}
    else null end
  else null end;

# What the walk stops at: a string that holds a / (no path without one), every string once there are mapped names
# to look for or relative arguments to clean ($all), and the objects named_in_dir knows.
def worth_cleaning($all):
  if type == "string" then $all or index("/") != null
  elif type == "object" then (.filename | type) == "string" or (.target_filename | type) == "string" or (.target_name | type) == "string"
  else false end;

# Programs whose -c or -e value (or -lc, -ne …, --eval, --command) is code: free text, never a relative name.
def CODE_PROGRAMS: "^(?:sh|bash|zsh|dash|ksh|csh|tcsh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|osascript|node|php)$";
def code_value($prog; $prev): ($prog | test(CODE_PROGRAMS)) and ($prev | test("^-[A-Za-z]*[ceE]$|^--(?:eval|command)$"));

# An argument, or the value of --option=value or NAME=value: {pre: what stays, val: what may be a relative name}.
def option_value($a):
  ([$a | capture("^(?<pre>--?[A-Za-z0-9][A-Za-z0-9_-]*=|[A-Za-z_][A-Za-z0-9_]*=)(?<val>.+)$")] | .[0]) // {pre: "", val: $a};

# A relative name to clean under its exec's cwd (General string cleaning, step 2). It looks like a path: it holds a /
# or whitespace, ends in an extension from FILE_EXTENSIONS, or has a mapped name of 4 or more characters as a part. It
# is not an option, an absolute or ~ path or one glued to @, =, : or , (cleaned as paths), a URL, user@host:, host.tld/…,
# a header (Accept: text/html), a launchctl target (gui/501), shell or AppleScript code, a program that ran, or what
# the rules look for (protected_name). So zip, -r, launchctl load and find-generic-password stay. Input: the state.
def relative_name($a):
  . as $s
  | ($a | test("^[/~$-]|^[^A-Za-z0-9\\s.]+/|[@=:,]/|[\"'`$;|<>\\n\\r(){}]|&&|&\\s|://|^[^\\s/]*@[^\\s/]*:|^(?:gui|user|pid|login|session)/[0-9]+(?:/|$)|^[A-Za-z][A-Za-z0-9-]*:\\s") | not)
  and ([$a | capture("^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.(?<e>[A-Za-z0-9-]+)(?::[0-9]+)?/") | FILE_EXTENSIONS[.e | ascii_downcase] != true] | any | not)
  and (($a | test("[/\\s]"))
       or FILE_EXTENSIONS[[$a | capture("\\.(?<e>[A-Za-z0-9]{1,11})$") | .e | ascii_downcase] | .[0] // ""] == true
       or any($a | split("/")[]; length >= 4 and ($s.map.name[.] // $s.map.user[.] // $s.map.volume[.]) != null))
  and (protected_name($a) | not) and ($s.keep[$a] | not);

# The event (input) cleaned, with the state the cleaning leaves and the key entries it created:
#   {event, state, new: [{kind, placeholder, real}]}
# Every string is walked, so a field nobody thought of cannot carry a name through. Programs the event runs are kept
# before any of its strings is cleaned. create.acl is dropped (it can name users and groups). A new file's separate
# name (named_in_dir) is cleaned as the last name of its folder. When an exec's cwd is in a cleaned place, its
# arguments that are relative names are cleaned as names in that folder (argv[0] and option names stay).
def clean_event($state):
  (if (.event.create | type) == "object" then del(.event.create.acl) else . end) as $e
  | (try $e.event.exec.cwd.path catch null) as $cwd
  | (try $e.event.exec.args catch null) as $args
  | (($cwd | type) == "string" and ($args | type) == "array" and ($cwd | in_cleaned_place)) as $relc
  | (if $relc then ($args[0] | if type == "string" then split("/") | last else "" end) else "" end) as $prog
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
        elif ({"filename": true, "target_filename": true, "target_name": true}[$p[-1] | tostring])
             and ($e | getpath($p[:-1]) | named_in_dir($p[:-1])) != null then .
        elif $relc and ($p | length) == 4 and $p[0:3] == ["event", "exec", "args"] and $p[3] > 0
             and (code_value($prog; $args[$p[3] - 1] | if type == "string" then . else "" end) | not)
             and (option_value($v) as $o | .s | relative_name($o.val)) then
          option_value($v) as $o
          | (.s | clean_relative($cwd; $o.val)) as $r
          | .s = $r.s | .e |= setpath($p; $o.pre + $r.v)
        else
          (.s | clean_string($v; path_field($p))) as $r
          | .s = $r.s | if $r.v != $v then .e |= setpath($p; $r.v) else . end
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
          | (try ($e | clean_event($seen)) catch null) as $r
          | if $r == null then {s: ($seen | .stats.unreadable += 1), emit: [], new: []}
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
# first appearance, before it runs. Lines that do not parse are skipped here and dropped by the cleaning pass.
def prescan:
  reduce (inputs | (try fromjson catch null) | objects
          | exec_names([paths(type == "string" and index("/") != null)])[]) as $n ({}; .[$n] = true)
  | keys;

if $cfg[0].prescan == true then prescan
else
  foreach ((inputs | {line: .}), {end: true}) as $in (
    {s: initial_state($cfg[0]), emit: [], new: []};
    if $in.end then {s: .s, emit: [], new: [], done: true} else .s | step($in.line) end;
    extract
  )
end
