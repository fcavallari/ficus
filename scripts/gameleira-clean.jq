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
# $cfg[0] is {seeds: [{kind, value}], domains: [string], key: [{kind, placeholder, real}], keep: [string]}.
#
# The cleaner's state: {map: {<kind>: {<real>: <placeholder>}}, next: {<kind>: int}, keep: {<name>: true},
# stats: {...}, lastSeq: number|null, new: [...]}. `map` says which placeholder a real value already has, `next` the
# number the next placeholder of a kind gets, `keep` the names that stay as they are, `lastSeq` the highest
# global_seq_num seen, `new` the key entries the event being cleaned has created. `new` is emptied for each event, never
# deleted and added back: jq does not reuse a deleted key's slot, so that would grow the state with every event.

# The first run of digits in a placeholder is its number: user3, Person 3, .name3, name3.pdf, host3.internal.invalid.
def placeholder_number: ([scan("[0-9]+")] | .[0] // "0") | tonumber;

# The state a run starts with: the loaded key's values keep their placeholders, and numbering goes on after them.
def initial_state($cfg):
  { map: (reduce $cfg.key[] as $k ({}; .[$k.kind][$k.real] = $k.placeholder)),
    next: (reduce $cfg.key[] as $k ({}; .[$k.kind] = ([.[$k.kind] // 1, ($k.placeholder | placeholder_number) + 1] | max))),
    keep: (reduce $cfg.keep[] as $n ({}; .[$n] = true)),
    stats: { eventsIn: 0, eventsOut: 0, unreadable: 0, seqGaps: 0, redacted: 0, placeholders: {} },
    lastSeq: null, new: [] };

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

# The placeholder `real` already has, or a new one numbered on from `next` (which a loaded key has moved on).
def placeholder($kind; $real):
  .map[$kind][$real] as $have
  | if $have != null then {ph: $have, state: .}
    else (.next[$kind] // 1) as $n
      | placeholder_form($kind; $real; $n; (if $kind == "name" then kept_extension($real) else "" end)) as $ph
      | {ph: $ph, state: (.map[$kind][$real] = $ph | .next[$kind] = $n + 1
                          | .new += [{kind: $kind, placeholder: $ph, real: $real}])}
    end;

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

# One absolute path, ~/ or ~name/ path, or file:// URL, cleaned name by name (General string cleaning, step 1). Input: the state.
# Output: {v: the cleaned path, s: the state}. Extra leading slashes (//Users/…) are kept and the path cleaned as usual.
# The fixed system structure (/System, but not /System/Volumes/Data, which holds /Users; /usr, /bin, /sbin, /dev) is
# kept whole: nothing a person names lives there.
def clean_path($text):
  ([$text | capture("^~(?<u>[A-Za-z0-9._-]*)/") | .u] | .[0]) as $tu
  | ($text | if startswith("file://localhost/") then "file://localhost" elif startswith("file://") then "file://"
             elif $tu != null then "~" + $tu else "" end) as $pre0
  | ($text[($pre0 | length):] | capture("^(?<extra>/*)(?<rest>/[\\s\\S]*)$")? // {extra: "", rest: null}) as $split
  | $split.rest as $rest
  | if $rest == null or ($tu == null and ($rest | test("^/(?:System(?!/Volumes/)|usr|bin|sbin|dev)(?:/|$)"))) then {v: $text, s: .}
    else
      ($pre0 | startswith("file")) as $url
      | ($rest | split("/")) as $raw
      | (if $url then $raw | map(pct_decode) else $raw end) as $names
      | ($names | map(ascii_downcase)) as $lc
      | place($lc; $tu != null) as $pl
      | if $pl.from == null and unchanged_elsewhere($text) then {v: $text, s: .}
        else
          # ~name/ is that account's home folder: the name becomes its user placeholder.
          (if ($tu // "") != "" then placeholder("user"; $tu) | {pre: ("~" + .ph), s: .state} else {pre: $pre0, s: .} end) as $h
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

# Where paths are inside a string. A plain value (an argument, a NAME=value entry): a path starts at the beginning,
# after = or after a : that is followed by a path (PATH lists), and runs to the end or to the next such :, spaces,
# & and all. Free text (sh -c, osascript -e: pipes, quotes before a path, two paths): a quoted path runs to its quote,
# an unquoted one to the first space or shell character, with backslash escapes. A path field is one path, whole.
# A cleaned place's path also starts after any other character (-I/Users/…, @/tmp/…): reading too much there is safe.
def CLEANED_ROOT: "/(?i:Users|Volumes|tmp|private/tmp|private/var|var/tmp|var/folders)/";
def PLAIN_PATHS:
  "(?<![^=:])(?:file://(?:localhost)?|~[A-Za-z0-9._-]*)?/(?:[^:]|:(?!~?/))*"
  + "|" + CLEANED_ROOT + "(?:[^:]|:(?!~?/))*";
def TEXT_PATHS:
  "(?<=\")(?:file://(?:localhost)?|~[A-Za-z0-9._-]*)?/[^\"\\n]*"
  + "|(?<=')(?:file://(?:localhost)?|~[A-Za-z0-9._-]*)?/[^'\\n]*"
  + "|(?<![^\\s=:(<>|;,`\\[{])(?:file://(?:localhost)?|~[A-Za-z0-9._-]*)?/(?:\\\\.|[^\\s\"'`|;&<>():,\\]}])*"
  + "|" + CLEANED_ROOT + "(?:\\\\.|[^\\s\"'`|;&<>():,\\]}])*";
# A string that starts with a path, or NAME= or --option= and a path, is one value (M&A Plan, R&D): free text only when it also
# holds a line break or a second path after a space.
def free_text:
  if test("^(?:-{0,2}[A-Za-z_][A-Za-z0-9_-]*=)?(?:/|~[A-Za-z0-9._-]*/|file:)") then test("[\\n\\r]|\\s(?:~?/|file:)")
  else test("[|;&<>`\\n\\r]|\\$\\(|\\s(?:~?/|file:)|[\"'(,](?:~?/|file:)") end;

# Every path the regex finds in $str, cleaned. A match that begins // right after a : is a URL's host part
# (https://host/…), left for the host step. Input: the state. Output: {v, s}.
def clean_matches($re; $str):
  [$str | match($re; "g")] as $ms
  | if $ms == [] then {v: $str, s: .}
    else
      reduce $ms[] as $m ({s: ., out: "", at: 0};
        (if ($m.string | startswith("//")) and $m.offset > 0 and $str[$m.offset - 1:$m.offset] == ":" then {v: $m.string, s: .s}
         else .s | clean_path($m.string) end) as $r
        | .out += $str[.at:$m.offset] + $r.v | .at = $m.offset + $m.length | .s = $r.s)
      | {v: (.out + $str[.at:]), s: .s}
    end;

# A string with the paths in it cleaned. $field: the string is a path field (…path, item_url, app_url).
def clean_string($str; $field):
  if $field then (if ($str | test("^(?:/|~[A-Za-z0-9._-]*/|file://)")) then clean_path($str) else {v: $str, s: .} end)
  elif ($str | free_text) then clean_matches(TEXT_PATHS; $str)
  else clean_matches(PLAIN_PATHS; $str) end;

# ---- events -----------------------------------------------------------------------------------------------------
# Fields left unchanged (Precedence, step 1): team IDs, cdhashes, times, tty paths, entitlements; and signing_id,
# which a later step cleans by its own rule. Numbers are never strings, so the walk does not see them.
def exempt($p):
  {"team_id": true, "cdhash": true, "time": true, "start_time": true, "signing_id": true}[$p[-1] | tostring]
  or ($p | index(["entitlements"])) != null or ($p | index(["tty"])) != null;
def path_field($p):
  {"path": true, "dyld_exec_path": true, "executable_path": true, "item_url": true, "app_url": true}[$p[-1] | tostring] == true;

# What the walk stops at: a string that holds a / (no path without one), or a {dir: {path}, filename} object.
def worth_cleaning:
  if type == "string" then index("/") != null
  elif type == "object" then (.filename | type) == "string" and (.dir | type) == "object" and (.dir.path | type) == "string"
  else false end;

# The event (input) cleaned, with the state the cleaning leaves and the key entries it created:
#   {event, state, new: [{kind, placeholder, real}]}
# Every string is walked, so a field nobody thought of cannot carry a name through. Programs the event runs are kept
# before any of its strings is cleaned. create.acl is dropped (it can name users and groups). A new file's separate
# `filename` is cleaned as the last name of its folder.
def clean_event($state):
  (if (.event.create | type) == "object" then del(.event.create.acl) else . end) as $e
  | [$e | paths(worth_cleaning)] as $ps
  | (reduce ($e | exec_names($ps)[]) as $n ($state; if .keep[$n] then . else .keep[$n] = true end)) as $s0
  | reduce $ps[] as $p ({e: $e, s: ($s0 | .new = [])};
      ($e | getpath($p)) as $v
      | if ($v | type) == "object" then
          ($v.dir.path) as $dir
          | if $p[-1] == "new_path" and ($dir | startswith("/")) and $v.filename != "" and ($v.filename | index("/")) == null then
              (.s | clean_path(($dir | rtrimstr("/")) + "/" + $v.filename)) as $r
              | .s = $r.s | .e |= setpath($p + ["filename"]; $r.v | split("/") | last)
            else . end
        elif exempt($p) then .
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

foreach ((inputs | {line: .}), {end: true}) as $in (
  {s: initial_state($cfg[0]), emit: [], new: []};
  if $in.end then {s: .s, emit: [], new: [], done: true} else .s | step($in.line) end;
  extract
)
