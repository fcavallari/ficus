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
# `clear` raw values known to hold no account name or seed in any form (at most 8192; emptied when one is added) and
# `clearn` how many, `sec` whether the quoted string being cleaned is an argument of security, `ci` the user and realname placeholders by
# lower-cased real value, `acct` the account names and seeds (lower-cased) with their placeholders,
# `acctl` those lower-cased values longest first, `acctn` how many there are and `acctany`, `acctre` the regexes
# add_acct builds from them (General string cleaning, step 7),
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

# Account names that are short or common words: the summary lists them, since they are replaced only where they
# cannot be another word (see replace_seeds).
def COMMON_ACCOUNT_WORDS: {
  "admin": true, "user": true, "test": true, "dev": true, "code": true, "mac": true, "guest": true, "home": true, "work": true
};
# A weak account word: shorter than 4 characters, a common word or one the rules look for (code, test).
def weak_account($k): ($k | length) < 4 or COMMON_ACCOUNT_WORDS[$k | ascii_downcase] == true or protected_word($k);

# A new placeholder's real value, made findable in free text (General string cleaning, step 4): names of 4 or more
# characters that are not protected, of the kinds that are names, and hosts and emails that are not a weak word
# (ping buildbox, after ssh buildbox mapped it; data has no words). For a name of several words (Q3 Financials, M&A Plan: words and separators as WORD_TOKENS splits them),
# `multi` notes under its first word how many it has, so replace_mapped can join that many from the text and look the
# result up in `words`: one lookup per distinct count, however many names share the first word (Screenshot …).
# Input: the state.
def index_word($kind; $real; $ph):
  if ({"user": true, "realname": true, "name": true, "volume": true, "seed": true, "host": true, "email": true}[$kind] | not)
     or ($real | length) < 4 or .words[$real] != null or protected_name($real)
     or (($kind == "host" or $kind == "email") and weak_account($real)) then .
  else .words[$real] = $ph | .nwords += 1
    | [$real | scan(WORD_TOKENS)] as $t
    | if ($t | length) > 1 then .multi[$t[0]][$t | length | tostring] = true else . end
  end;

# An account name or seed, made findable anywhere (acct, General string cleaning step 7). Most strings hold none, so
# each is first tested against one regex of them all: `acctall` (every name in any form: a raw value that fails it
# goes in `clear`, see seed_free), `acctany` (paths, signing IDs) or `acctre` (replace_seeds: a name shorter than 4
# characters or protected only before an @). A case-insensitive regex costs less in jq than ascii_downcase, but with
# many seeds still more than anything else per string, hence `clear`. Input: the state.
def regex_escape: gsub("(?<c>[\\\\^$.|?*+()\\[\\]{}])"; "\\\(.c)");
# A seed as a regex for text: a space in it may be written with a backslash before it (Jane\ Doe in shell code).
def seed_regex: regex_escape | gsub(" "; "\\\\? ");
def add_acct($real; $ph):
  ($real | ascii_downcase) as $l
  | if $l == "" or .acct[$l] != null then .
    else .acct[$l] = $ph | .acctl = (.acctl + [$l] | sort_by(length) | reverse) | .acctn += 1
      | .acctany = (.acctl | map(regex_escape) | join("|"))
      | .acctre = (.acctl | map(seed_regex + (if length < 4 or protected_word(.) then "@" else "" end)) | join("|"))
      | .acctall = (.acctl | map(seed_regex) | join("|"))
      | .clear = {} | .clearn = 0 | .envk = {} | .envkn = 0
    end;

# The placeholder `real` already has, or a new one numbered on from `next` (which a loaded key has moved on). An account
# name found on the way (/Users/<name>/) is an account name everywhere from then on. An account or full name has one
# placeholder whatever its case (`ci`, lower-cased): JDoe from -S and /Users/jdoe/ are one person.
def placeholder($kind; $real):
  ($kind == "user" or $kind == "realname" or $kind == "host" or $kind == "email") as $ci
  | (.map[$kind][$real] // (if $ci then .ci[$kind][$real | ascii_downcase] else null end)) as $have
  | if $have != null then {ph: $have, state: .}
    else (.next[$kind] // 1) as $n
      | placeholder_form($kind; $real; $n; (if $kind == "name" then kept_extension($real) else "" end)) as $ph
      | {ph: $ph, state: (.map[$kind][$real] = $ph | .next[$kind] = $n + 1 | index_word($kind; $real; $ph)
                          | if $ci then .ci[$kind][$real | ascii_downcase] = $ph else . end
                          | if $kind == "user" then add_acct($real; $ph) else . end
                          | .new += [{kind: $kind, placeholder: $ph, real: $real}])}
    end;

# The state a run starts with: the loaded key's values keep their placeholders, and numbering goes on after them. The
# seeds (Seeds: -S, and the account names, full names, hosts and seeds of a loaded key) are account names and seeds
# from the start; a -S value without a placeholder gets one now, so it is in the key (its K line is written before the
# first event) whether or not the capture names it.
def initial_state($cfg):
  { map: (reduce $cfg.key[] as $k ({}; .[$k.kind][$k.real] = $k.placeholder)),
    next: (reduce $cfg.key[] as $k ({}; .[$k.kind] = ([.[$k.kind] // 1, ($k.placeholder | placeholder_number) + 1] | max))),
    keep: (reduce $cfg.keep[] as $n ({}; .[$n] = true)),
    ci: (reduce ($cfg.key[] | select(.kind == "user" or .kind == "realname" or .kind == "host" or .kind == "email")) as $k ({};
           .[$k.kind][$k.real | ascii_downcase] //= $k.placeholder)),
    # The -D domains, as a regex for internal_names and as the lower-case literals net_maybe looks for. nf: values
    # pre_test found nothing in; envk: environment names by class (see clean_env).
    domre: ($cfg.domains // [] | map(regex_escape) | join("|")),
    domlit: [$cfg.domains // [] | .[] | ascii_downcase] | unique, nf: {}, nfn: 0, envk: {}, envkn: 0,
    words: {}, multi: {}, nwords: 0, netc: {}, netn: 0, netp: false, single: false, code: false, rel: null, sec: false, acct: {}, acctl: [], acctn: 0, acctany: "", acctre: "", acctall: "", clear: {}, clearn: 0,
    stats: { eventsIn: 0, eventsOut: 0, unreadable: 0, uncleaned: 0, seqGaps: 0, redacted: 0, placeholders: {} },
    lastSeq: null, new: [] }
  | reduce $cfg.key[] as $k (.; index_word($k.kind; $k.real; $k.placeholder))
  | reduce ($cfg.key[] | select({"user": true, "realname": true, "host": true, "seed": true}[.kind])) as $k (.;
      add_acct($k.real; $k.placeholder) | reduce ($k.forms // [])[] as $f (.; add_acct($f; $k.placeholder)))
  | reduce ($cfg.seeds // [])[] as $sd (.;
      placeholder($sd.kind; $sd.value) as $r | $r.state | add_acct($sd.value; $r.ph)
      # The same seed composed or decomposed (NFC, NFD) has the same placeholder.
      | reduce ($sd.forms // [])[] as $f (.; add_acct($f; $r.ph)))
  | reduce .new[] as $n (.; .stats.placeholders[$n.kind] += 1);

# The structure folders of ~/Library whose first name below is an app's, a vendor's or a bundle ID (Ruling A):
# ~/Library/Application Support/Microsoft is kept, what Microsoft keeps below it is not.
def LIBRARY_STRUCTURE: {
  "application support": true, "caches": true, "containers": true, "group containers": true, "preferences": true,
  "logs": true, "saved application state": true, "httpstorages": true, "webkit": true, "cookies": true,
  "launchagents": true
};

# A bundle (Foo.app, X.framework …) or Go's build folder: kept wherever it is.
def bundle_name: test("(?i:\\.(?:app|framework|bundle|plugin|kext|xpc|appex))$|^(?i:go-build)");
# A bundle whose name has no dot before its suffix (Code.app, Visual Studio Code.app): the rules read such app names,
# so account names inside are left alone (seed_kept, replace_accounts); host names, full names and other seeds are
# replaced there like anywhere. One named by a bundle ID (com.jdoe.Helper.xpc) has its parts replaced like any bundle ID.
def plain_bundle_name: bundle_name and (sub("(?i:\\.[a-z]+)$"; "") | index(".") == null);
# The apps shell-under-app does not count as a launcher of shells (src/rules/rules.ts, the parent path test). A bundle of
# exactly one of these names is kept whole, whatever seed it equals, so that test reads the same name.
def RULE_APPS: {
  "Terminal": true, "iTerm": true, "iTerm2": true, "Visual Studio Code": true, "Code": true, "Cursor": true, "Xcode": true,
  "Claude": true, "Warp": true, "Ghostty": true, "Alacritty": true, "kitty": true, "WezTerm": true
};
def rule_app_bundle: endswith(".app") and RULE_APPS[.[:-4]] == true;
# A reverse-DNS bundle ID (com.apple.launchd.x, with or without .plist), recognised only at the top of a temporary
# folder: it has a common first label and no document extension, so it.budget.cuts.xlsx is a person's file.
def bundle_id:
  test("^(?:group\\.)?(?:com|org|net|io|edu|gov|dev|app)(?:\\.[A-Za-z0-9_-]+){2,}$")
  and (([capture("\\.(?<e>[A-Za-z0-9]+)$").e][0] // "" | ascii_downcase) as $e | $e == "plist" or FILE_EXTENSIONS[$e] != true);

# True when a name in a cleaned place stays as it is: a program that ran (state.keep), a standard name, a bundle, or
# (with $ids, at the top of a temporary folder) a bundle ID. Input: the state.
def kept_name($n; $ids):
  .keep[$n] == true or KEEP[$n | ascii_downcase] == true or ($n | bundle_name) or ($ids and ($n | bundle_id));

# Account names and seeds in a name or signing ID, case-insensitively, wherever they stand between dots, dashes and
# the ends, however many parts they span: jdoe -> user1, com.jdoe.agent.plist -> com.user1.agent.plist,
# com.Janes-MacBook-Pro.tool -> com.host1.internal.invalid.tool, a platform UUID that is the whole value -> seed2.
# Longest first. Only names that already have a placeholder are replaced, so the state does not change. Input: the state.
# $mode "all": every account name and seed; "bundle": not the weak account words (code in Code.app); "program": no
# account names, only full names, hosts and other seeds.
def replace_parts_opts($n; $mode):
  if .acctn == 0 then $n
  else .acctany as $re
    | if ($n | test($re; "i") | not) then $n
      else .acct as $a
        | reduce (.acctl[] | select(. as $k
                                     | ($mode == "all" or ($a[$k] | startswith("user") | not) or ($mode == "bundle" and (weak_account($k) | not)))
                                       and ($n | test($k | regex_escape; "i")))) as $k ($n;
            # A host followed by .local is that host (Janes-MacBook-Pro.local).
            gsub("(?<![^.\\-])" + ($k | regex_escape) + (if $a[$k] | endswith(".internal.invalid") then "(?:\\.local)?" else "" end)
                 + "(?![^.\\-])"; $a[$k]; "i"))
      end
  end;
def replace_parts($n): replace_parts_opts($n; "all");

# Account names and seeds in a path's name (replace_parts). In a bundle with a plain name (Code.app, Visual Studio
# Code.app), whose name the rules read, only a weak account word stays (code in Code.app); other account names, full
# names, hosts and other seeds are replaced (jdoe-tools.app becomes user1-tools.app, Jane Doe.app Person 1.app). A
# bundle named like an app the rules list (RULE_APPS) is kept whole. Input: the state.
def replace_accounts($n):
  if ($n | plain_bundle_name) then (if ($n | rule_app_bundle) then $n else replace_parts_opts($n; "bundle") end)
  else replace_parts($n) end;

# The file names of the programs and scripts an event runs: the last component of every process's executable.path,
# exec's script.path and dyld_exec_path, a launch item's executable_path, and argv[0]. Input: the event. $ps: the
# paths of the event's strings that hold a / (clean_event has them already; every program path holds one).
def exec_name_path($p):
  $p[-2:] == ["executable", "path"] or $p[-2:] == ["script", "path"] or $p[-1] == "dyld_exec_path" or $p[-1] == "executable_path";
def exec_names($ps):
  . as $e
  | [ ($ps[] | select(exec_name_path(.)) as $p | $e | getpath($p)), .event.exec.args[0]?, .event.btm_launch_item_add.executable_path?
      | strings | sub("/+$"; "") | split("/") | last | select(. != null and . != "") ];

# ---- emails, internal hosts and URLs (General string cleaning, steps 5 and 6) -----------------------------------
# These run on a raw value before every other step, so a host is never taken for a relative name (evil.sh) or a mapped
# folder (acme:8080), and the key holds the address as written. What they write is inert to the later steps: a host
# placeholder is a dotted host (dotted_host), a URL keeps its scheme (URL_SCHEME), and seed_kept skips placeholders.
#
# Internal: private and link-local IPv4 (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8) and IPv6 (fc00::/7,
# fe80::/10, ::1); names ending in .local, .internal, .corp, .lan, .home.arpa; names under a -D domain (state.domre);
# a host that already has a placeholder (a host seed: Janes-MacBook-Pro, and with .local after it); and a single-label
# name in a URL, a user@host: form or ssh's host (intranet/a.sh, deploy@buildbox:/srv). localhost stays: it names no
# machine. Public hosts stay: a command-and-control domain is evidence.
def IPV4_INTERNAL: "(?:10\\.[0-9]{1,3}|127\\.[0-9]{1,3}|172\\.(?:1[6-9]|2[0-9]|3[01])|192\\.168|169\\.254)\\.[0-9]{1,3}\\.[0-9]{1,3}";
def IPV6_INTERNAL: "(?:[fF][cdCD][0-9a-fA-F]{2}|[fF][eE][89abAB][0-9a-fA-F]):(?:[0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}|::1";
def internal_names($dom): "(?:[A-Za-z0-9-]+\\.)+(?:local|internal|corp|lan|home\\.arpa)" + (if $dom == "" then "" else "|(?:[A-Za-z0-9-]+\\.)*(?:" + $dom + ")" end);

# Cheap tests before any regex: most strings hold none of these. contains costs a fraction of a regex in jq, which
# compiles its pattern on every call. Input: the string (net_maybe: the state).
def maybe_ipv4: contains("10.") or contains("127.") or contains("172.") or contains("192.168") or contains("169.254");
def maybe_ipv6: contains("::") or contains("fe80:") or contains("FE80:");
# maybe_names: on a lower-cased copy (names are case-insensitive: Build01.CoRp, wiki.ACME.com); $domlit the -D domains.
# A suffix counts only after a label (build01.corp), not after a / (~/.local/bin).
def maybe_names($domlit):
  ((contains(".local") or contains(".corp") or contains(".lan") or contains(".internal") or contains(".arpa"))
   and test("[a-z0-9-]\\.(?:local|corp|lan|internal|arpa)"))
  or (. as $str | any($domlit[]; . as $d | $str | contains($d)));
def net_maybe($str):
  .domlit as $dl
  | ($str | contains("@") or contains("://") or maybe_ipv4 or maybe_ipv6) or ($str | ascii_downcase | maybe_names($dl));

# The placeholder of a host. One host has one placeholder whatever its case (state.ci), and a known host followed by
# .local is that host (Janes-MacBook-Pro.local is the host seed Janes-MacBook-Pro). Input: the state. Output: {ph, state}.
def host_placeholder($h):
  ($h | ascii_downcase) as $l
  | (.ci.host[$l] // (if $l | endswith(".local") then .ci.host[$l[:-6]] else null end)) as $have
  | if $have != null then {ph: $have, state: .} else placeholder("host"; $h) end;

# True when $h (no brackets, no port) is an internal host. $single: a single-label name counts (URLs, user@host:, ssh's
# host). Input: the state.
def internal_host($h; $single):
  ($h | ascii_downcase) as $l
  | .domre as $dom
  | $l != "" and $l != "localhost"
    and (($single and ($l | test("^[a-z0-9_-]+$")))
         or ($l | test("^(?:" + IPV4_INTERNAL + "|" + IPV6_INTERNAL + ")$"))
         or ($l | test("^(?:" + internal_names($dom) + ")$"; "i"))
         or .ci.host[$l] != null
         or (($l | endswith(".local")) and .ci.host[$l[:-6]] != null));

# A host as written ([fd12::1] with brackets): its placeholder when internal, else as it is. Input: the state. {v, s}.
def clean_host($h; $single):
  ($h | if startswith("[") and endswith("]") then .[1:-1] else . end) as $bare
  | if internal_host($bare; $single) then host_placeholder($bare) | {v: .ph, s: .state} else {v: $h, s: .} end;

# A query or fragment: each value becomes a data placeholder, names stay (?id=data1&t=data2); a part without = is a
# value. Input: the state. Output: {v, s}.
def clean_query($q):
  reduce ($q | split("&"))[] as $kv ({s: ., out: []};
    ($kv | index("=")) as $i
    | (if $i == null then {k: "", v: $kv} else {k: $kv[:$i + 1], v: $kv[$i + 1:]} end) as $c
    # A value with a redacted credential shape in it is redacted whole (the shape was counted when it was redacted).
    | if $c.v == "" then .out += [$kv]
      elif ($c.v | contains("\u0002")) then .out += [$c.k + "\u0002"]
      else (.s | placeholder("data"; $c.v)) as $r | .s = $r.state | .out += [$c.k + $r.ph] end)
  | {v: (.out | join("&")), s: .s};

# The file extensions that are also top-level domains (evil.sh, x.zip): a host ending in one is a host.
def TLD_EXTENSIONS: {"sh": true, "py": true, "pl": true, "rs": true, "md": true, "so": true, "ps": true, "zip": true, "mov": true, "dot": true};
# ssh, scp and the like name user@host logins, not mailboxes.
def SSH_FAMILY: {"ssh": true, "scp": true, "sftp": true, "rsync": true, "mosh": true, "autossh": true, "ssh-copy-id": true, "sshpass": true};
# Programs whose positional arguments are hosts (not URLs): a dotted one is a host, never a relative name.
def HOST_PROGRAMS: {
  "ping": true, "ping6": true, "nc": true, "ncat": true, "netcat": true, "telnet": true, "traceroute": true,
  "traceroute6": true, "dig": true, "host": true, "nslookup": true, "whois": true, "ftp": true, "sftp": true, "mosh": true
};
# Shell code whose command, at the end of $before, is one of these programs (behind sudo, env, nohup … if any).
# Programs that run the command after them, with their options that take a value (short letters, long names):
# sudo -u root wget …, env -u FOO curl …, nice -n 5 …, timeout -s KILL 30 … (timeout also takes a duration first).
def WRAPPER_OPTIONS: {
  "sudo": {short: "ugCDhprtUT", long: {"--user": true, "--group": true, "--close-from": true, "--chdir": true, "--host": true,
                                      "--prompt": true, "--role": true, "--type": true, "--other-user": true, "--command-timeout": true}},
  "doas": {short: "uC", long: {}},
  "env": {short: "uCSP", long: {"--unset": true, "--chdir": true, "--split-string": true}},
  "nohup": {short: "", long: {}}, "command": {short: "", long: {}}, "time": {short: "", long: {}},
  "exec": {short: "a", long: {}},
  "nice": {short: "n", long: {"--adjustment": true}},
  "timeout": {short: "sk", long: {"--signal": true, "--kill-after": true}},
  "xargs": {short: "EIJLnPRSs", long: {}},
  # caffeinate -t secs -w pid; arch -arch name -e VAR=value -d VAR (-arm64, -x86_64, -i386 are flags); builtin.
  "caffeinate": {short: "tw", long: {}},
  "arch": {short: "de", long: {"-arch": true}},
  "builtin": {short: "", long: {}}
};
# True when $o, an option of the wrapper $wrap, takes the next word as its value.
def wrapper_value_option($wrap; $o):
  WRAPPER_OPTIONS[$wrap] as $spec
  | $spec.long[$o] == true or (($o | test("^-[A-Za-z]+$")) and ($spec.short | contains($o[-1:])));
# The wrappers as a regex, each with options that may take a value.
def WRAPPER_RE: "(?:(?:" + (WRAPPER_OPTIONS | keys | join("|")) + ")(?:\\s+-\\S+(?:\\s+[^\\s;&|()`-]\\S*)?)*\\s+)*";
def COMMAND_BEFORE($progs):
  "(?:^|[;&|(`\\n\"'])\\s*" + WRAPPER_RE + "(?:[^\\s;&|()`\"']*/)?(?:" + $progs + ")\\s[^;&|()`\\n]*$";
def LOGIN_PROGRAMS: SSH_FAMILY | keys | join("|");
# Shell code that ends in ssh's host position: ssh (mosh …) and its options, each with a value or not.
def SSH_HOST_BEFORE:
  "(?:^|[;&|(`\\n\"'])\\s*" + WRAPPER_RE + "(?:[^\\s;&|()`\"']*/)?"
  + "(?:ssh|mosh|autossh|ssh-copy-id)(?:\\s+-[A-Za-z]+(?:\\s+[^\\s-]\\S*)?)*\\s+$";

# Every match of $re in $str replaced by f, which gets {m: the match, s: the state, t: $str} and gives {v, s}. Input:
# the state. Output: {v, s}.
def net_sub($str; $re; f):
  [$str | match($re; "g")] as $ms
  | if $ms == [] then {v: $str, s: .}
    else reduce $ms[] as $m ({s: ., out: "", at: 0};
           ({m: $m, s: .s, t: $str} | f) as $r
           | .out += $str[.at:$m.offset] + $r.v | .s = $r.s | .at = $m.offset + $m.length)
      | {v: (.out + $str[.at:]), s: .s}
    end;

# A scheme URL anywhere (file:// is a path, cleaned by step 1).
def URL_RE: "(?<![A-Za-z0-9+.-])(?![Ff][Ii][Ll][Ee]:)[A-Za-z][A-Za-z0-9+.-]*://[^\\s\"'`<>|;(){}\\\\]*";
# x@y, an email or a user@host login: the domain or host as far as it goes.
def AT_RE: "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*)";
# Emails and internal hosts in a value (steps 5 and 6, without URLs): x@y as an email, or as a login, whose host is
# cleaned and user left to step 7; then internal host names and addresses. x@y is a login in an argument of an
# ssh-family program ($login "all"), in user@host:path form in one of git ($login "colon"), and in shell code ($code)
# as ssh's host or in user@host:path form after an ssh-family or git command (COMMAND_BEFORE, SSH_HOST_BEFORE);
# anywhere else it is an email when its domain ends in a top-level domain. Paths included: the path step then keeps
# the placeholders in a name and maps what is around them (ph_name), so a field and an argument agree. Input: the state.
# Output: {v, s}.
def net_shapes($str; $code; $login):
  (if $str | contains("@") then
       net_sub($str; AT_RE;
         .m.string as $x | .t as $t | (.m.offset + .m.length) as $e
         | ($x | index("@")) as $at | $x[$at + 1:] as $dom
         | if ($x | test("^person[0-9]+@example\\.invalid$"; "i")) then {v: $x, s: .s}
           elif ($t[$e:$e + 2] | test("^:[^\\s]")) as $colon
                | $login == "all" or ($colon and $login == "colon")
                  or ($code and ($t[:.m.offset] as $b
                                 | ($colon and ($b | test(COMMAND_BEFORE(LOGIN_PROGRAMS + "|git"))))
                                   or ($b | test(SSH_HOST_BEFORE)))) then
             .s | clean_host($dom; true) | .v = $x[:$at + 1] + .v
           elif ($dom | test("^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$"))
                and ($dom | split(".") | last | ascii_downcase) as $tld
                | FILE_EXTENSIONS[$tld] != true or TLD_EXTENSIONS[$tld] == true then
             .s | placeholder("email"; $x) | {v: .ph, s: .state}
           else {v: $x, s: .s} end)
     else {v: $str, s: .} end)
  | .v as $s3 | .s
  # One regex of the kinds the value may hold (each regex is compiled on every call).
  # An address may follow a letter, a colon or a / (-h10.0.0.5, TCP:10.0.0.5:4444, /dev/tcp/10.0.0.5/4444,
  # /Users/x/10.0.0.9/), not a digit or a dot (110.0.0.1, 1.10.0.0.5). A name may stand in a path, and before a final
  # file extension (/usr/local/var/log/nginx/wiki.acme.corp.log), not before more labels (com.example.corp.agent).
  | [ (if $s3 | maybe_ipv4 then "(?<![0-9.])(?:" + IPV4_INTERNAL + ")(?![0-9]|\\.[0-9])" else empty end),
      (if $s3 | maybe_ipv6 then "(?<![0-9A-Za-z:._-])(?:" + IPV6_INTERNAL + ")(?![0-9A-Za-z:])" else empty end),
      (.domlit as $dl | if $s3 | ascii_downcase | maybe_names($dl) then
         "(?<![A-Za-z0-9._%+-])(?!host[0-9]+\\.internal\\.invalid)(?i:" + internal_names(.domre) + ")(?![A-Za-z0-9-])"
         + "(?:(?=\\.(?i:" + (FILE_EXTENSIONS | keys | join("|")) + ")(?![A-Za-z0-9.-]))|(?!\\.[A-Za-z0-9]))" else empty end) ] as $res
  | if $res == [] then {v: $s3, s: .}
    else net_sub($s3; $res | join("|"); .m.string as $h | .s | host_placeholder($h) | {v: .ph, s: .state}) end;



# Which kinds the value being cleaned may hold (state.netp: false, or {at, ip4, ip6, names}, set from the whole value
# by clean_event), and whether $x, a part of it, may hold one of them: a cheap test before net_shapes in each name.
# Input: the state.
def net_flags($str):
  .domlit as $dl
  # An @ counts before a dotted name (jane@acme.com), not node@18 in a Homebrew path; an address prefix only before a
  # whole private address. One regex each, only for a value net_maybe let through.
  | {at: ($str | contains("@") and test("@[A-Za-z0-9-]+\\.[A-Za-z]")),
     ip4: ($str | maybe_ipv4 and test(IPV4_INTERNAL)),
     ip6: ($str | maybe_ipv6), names: ($str | ascii_downcase | maybe_names($dl))};
def net_hint($x):
  .netp as $f | .domlit as $dl
  | $f != false
    and (($f.at and ($x | contains("@"))) or ($f.ip4 and ($x | maybe_ipv4)) or ($f.ip6 and ($x | maybe_ipv6))
         or ($f.names and ($x | contains(".")) and ($x | ascii_downcase | maybe_names($dl))));

# An email, internal host or private address in a path's name, when the value may hold one (net_hint; steps 1, 5
# and 6): {v: the name with them replaced (a host keeps a file extension after it: wiki.acme.corp.plist), whole: true
# when the name was one of them, s: the state}, or null. Input: the state.
def net_name($n):
  if (net_hint($n) | not) then null
  else ([$n | capture("^(?<b>.+)(?<e>\\.[A-Za-z0-9]{1,11})$")] | .[0]) as $c
    | net_shapes($n; false; "") as $r
    | (if $r.v != $n or $c == null or FILE_EXTENSIONS[$c.e[1:] | ascii_downcase] != true then $r + {e: ""}
       else net_shapes($c.b; false; "") as $q | if $q.v == $c.b then $r + {e: ""} else $q + {e: $c.e} end end) as $x
    | if $x.e == "" and $x.v == $n then null
      else {v: ($x.v + $x.e), s: $x.s,
            whole: ($x.v | test("^(?:host[0-9]+\\.internal\\.invalid|person[0-9]+@example\\.invalid)$"))} end
  end;
# A kept name with the emails and internal hosts in it replaced (net_name), as {v, s}. Input: the state.
def net_in_name($n): net_name($n) as $r | if $r == null then {v: $n, s: .} else {v: $r.v, s: $r.s} end;

# A name kept in a path: account names and seeds replaced (a program's name keeps account names: $program), and
# emails and internal hosts in it (net_in_name). Input: the state. Output: {v, s}.
def kept_clean($n; $program):
  (if $program then replace_parts_opts($n; "program") else replace_accounts($n) end) as $k | net_in_name($k);

# A host or email placeholder (what net_shapes writes), and a name in a cleaned place holding one (backup-10.0.0.5
# became backup-host1.internal.invalid): the placeholders stay, each run of letters and digits around them gets a
# name placeholder (name5-host1.internal.invalid), a file extension after them stays. So no key row's real value holds
# a placeholder, and the same name gives the same result in a field and an argument. A redaction (REDACTED) in a name
# stays the same way (/tmp/<redacted>.txt). Input: the state. Output: {v, s}.
def PH_RE: "host[0-9]+\\.internal\\.invalid|person[0-9]+@example\\.invalid|\u0002";
def ph_name($n):
  reduce ($n | [match("(?:" + PH_RE + ")|(?:(?!" + PH_RE + ")[\\s\\S])+"; "g") | .string])[] as $p ({v: "", s: .};
    if ($p | test("^(?:" + PH_RE + ")$")) or ($p | test("^[^A-Za-z0-9]*$"))
       or (($p | test("^\\.[A-Za-z0-9]{1,11}$")) and FILE_EXTENSIONS[$p[1:] | ascii_downcase] == true) then .v += $p
    else ($p | capture("^(?<a>[^A-Za-z0-9]*)(?<c>[\\s\\S]*?)(?<z>[^A-Za-z0-9]*)$")) as $c
      | (.s | placeholder("name"; $c.c)) as $r | .s = $r.state | .v += $c.a + $r.ph + $c.z end);

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
  .acctn == 0 or .clear[$text] == true or (.acctany as $re | $text | test($re; "i") | not);

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
      | if $pl.from == null and unchanged_elsewhere($text) and (net_hint($text) | not) then {v: $text, s: .}
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
                if .s.keep[$n] == true then
                  (.s | kept_clean($n; true)) as $k | .s = $k.s | .out += [if $k.v == $n then $raw[$i] else $k.v | url_part($url) end]
                elif kept_by_place($pl; $lc; $i; $n) or (.s.map.name[$n] == null and (.s | kept_name($n; $i == $pl.top))) then
                  (.s | kept_clean($n; false)) as $k | .s = $k.s | .out += [if $k.v == $n then $raw[$i] else $k.v | url_part($url) end]
                elif .s.map.name[$n] != null then .out += [.s.map.name[$n] | url_part($url)]
                elif (.s.map.user[$n] // .s.map.volume[$n]) != null then .out += [.s.map.user[$n] // .s.map.volume[$n]]
                elif ($n | test(PH_RE)) then (.s | ph_name($n)) as $r | .s = $r.s | .out += [$r.v | url_part($url)]
                else
                  # A name that is an internal host or address, or an email already met, has that placeholder (the same
                  # in a path as anywhere); any other name, one with an email or host inside included, a name placeholder.
                  (.s | net_name($n)) as $nn
                  | if $nn != null and $nn.whole and (($nn.v | startswith("host")) or .s.ci.email[$n | ascii_downcase] != null) then
                      .s = $nn.s | .out += [$nn.v | url_part($url)]
                    else (.s | placeholder("name"; $n)) as $r | .s = $r.state | .out += [$r.ph | url_part($url)] end
                end
              elif $pl.from == null then
                (.s | kept_clean($n; .keep[$n] == true)) as $k | .s = $k.s
                | .out += [if $k.v == $n then $raw[$i] else $k.v | url_part($url) end]
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

# ---- account names and seeds ----------------------------------------------------------------------------------
# What ends a word around an account name. A token stops at whitespace too. A part (a path component, a quoted name,
# a whole argument: Code Helper (Plugin).app, "Code Tools.app") only at a /, a quote, a line break or a shell operator.
def SEED_TOKEN: "[^\\s\"'`=:;|&<>(),/\\\\\\[\\]{}]*";
def SEED_PART: "[^/\"'`\\n\\r:=;|&<>]*";

# True when an account name or seed found in $t (the match $m) is to stay: inside an option name (--code, --no-code),
# a variable's name ($HOME, ${HOME}, HOME=, JDOE_DIR=), a kept program name that is the whole token, a bundle named
# like an app the rules list (Claude.app, RULE_APPS), or a placeholder already written (Person 2,
# person1@example.invalid).
# A weak account word (shorter than 4 characters, common or a rule word: code; never a strong account name, host,
# full name or other seed) is also kept inside a plain bundle that is the whole token (Code.app) or the whole part it
# is in (Visual Studio Code.app), since the rules read app names; jdoe.app and "jdoe has Zoom.app" lose jdoe. An
# account name is kept inside a kept program name of several words (Code Helper (Plugin), "Code Helper"): in a path
# component always, elsewhere only when it is a weak word. In shell code ($code) a part that runs from the start of the code and has a
# space is a command, not a name (ls jdoe Code.app), so it does not count.
# Input: the state.
def seed_kept($t; $m; $code):
  $m.offset as $o | ($o + $m.length) as $e
  | ($t[([$o - 256, 0] | max):$o]) as $before
  | ($t[$e:$e + 256]) as $after
  | ([$before | match(SEED_TOKEN + "$") | .string] | .[0] // "") as $l
  | ([$after | match("^" + SEED_TOKEN) | .string] | .[0] // "") as $r
  | ($l + $m.string + $r) as $tok
  | ($l | test("^-+[A-Za-z0-9_-]*$"))
    or ($before | test("[$]\\{?[A-Za-z0-9_]*$"))
    or (($l | test("^[A-Za-z0-9_]*$")) and ($after | test("^[A-Za-z0-9_]*=")))
    # A program's name keeps an account name in it (jdoe-agent), never a full name, host or other seed (ruling I4).
    or (.keep[$tok] == true and (.acct[$m.string | gsub("\\\\(?= )"; "") | ascii_downcase] // "" | startswith("user")))
    or ($tok | rule_app_bundle)
    # A path component named like an app shell-under-app lists (/Applications/Visual Studio Code.app/): its parent test.
    or (([$before | match(SEED_PART + "$") | .string] | .[0] // "") as $pl
        | ([$after | match("^" + SEED_PART) | .string] | .[0] // "") as $pr
        | ($pl + $m.string + $pr | rule_app_bundle) and $after[($pr | length):($pr | length) + 1] == "/")
    or ($tok | test("^(?i:person[0-9]+@example\\.invalid|host[0-9]+\\.internal\\.invalid)$"))
    or ($m.string == "Person" and ($after | test("^ [0-9]")))
    or ((.acct[$m.string | gsub("\\\\(?= )"; "") | ascii_downcase] // "" | test("^user[0-9]+$"))
        and weak_account($m.string) as $weak
        | ((($tok | plain_bundle_name) and $weak)
           or (([$before | match(SEED_PART + "$") | .string] | .[0] // "") as $pl
               | ([$after | match("^" + SEED_PART) | .string] | .[0] // "") as $pr
               | ($pl + $m.string + $pr) as $part
               | (($before | length) - ($pl | length)) as $i
               | (($code | not) or ($pl | length) < $o or ($part | test("\\s") | not))
                 and ((($part | plain_bundle_name) and $weak)
                      or (.keep[$part | sub("^\\s+"; "") | sub("\\s+$"; "")] == true
                          and ($weak or (if $i > 0 then $before[$i - 1:$i] else "" end) == "/" or $after[($pr | length):($pr | length) + 1] == "/"))))));

# $str with account names and seeds replaced, case-insensitively, as whole words (General string cleaning, step 7; a
# word ends at anything but a letter or digit, so jdoe_backup is user1_backup):
# `ssh jdoe@host`, `USER=jdoe`, `display dialog "Jane Doe"`, a serial in an ioreg argument. Runs on a value after the
# other steps, so the names inside paths and the mapped names are placeholders by then. A name shorter than 4
# characters, or one the rules look for (test, build: protected_word), is replaced only before an @ (an email or
# user@host); elsewhere it is too likely another word, and the summary lists it. Input: the state.
def replace_seeds_opts($str; $code):
  if .acctn == 0 then $str
  elif (.acctre as $re | $str | test($re; "i") | not) then $str
  else . as $s
    | [$s.acctl[] | select(seed_regex as $k | $str | test($k; "i"))] as $hits
    | if $hits == [] then $str
      else reduce $hits[] as $k ($str;
        . as $t
        | (($k | length) < 4 or protected_word($k)) as $weak
        | [$t | match("(?<![^\\W_])" + ($k | seed_regex) + (if $s.acct[$k] | endswith(".internal.invalid") then "(?:\\.local)?" else "" end)
                      + "(?![^\\W_])"; "gi")
           | select(($weak | not) or $t[.offset + .length:.offset + .length + 1] == "@")
           | select(. as $m | $s | seed_kept($t; $m; $code) | not)] as $ms
        | if $ms == [] then $t
          else reduce $ms[] as $m ({out: "", at: 0};
                 .out += $t[.at:$m.offset] + ($s.acct[$k] | if $m.string | contains("\\") then gsub(" "; "\\ ") else . end)
                 | .at = $m.offset + $m.length)
            | .out + $t[.at:]
          end)
      end
  end;

# A signing ID with account names and seeds replaced as whole parts between dots and dashes (Precedence, step 2;
# replace_parts): com.jdoe.tool -> com.user1.tool. Apple's (com.apple.*) are never touched. Input: the state.
def replace_id_parts($v): if ($v | startswith("com.apple.")) then $v else replace_parts($v) end;

def replace_seeds($str): replace_seeds_opts($str; false);

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

# The text before a quoted string in shell code ends inside a security command: the command after the last ; & | ( `
# or line break is security (by name or path), behind sudo, env, nohup, command or exec if any.
def SECURITY_COMMAND:
  "(?:^|[;&|(`\\n])\\s*(?:(?:sudo|env|nohup|command|exec)\\s+(?:-\\S+\\s+)*)*(?:[^\\s;&|()`]*/)?security\\s[^;&|()`\\n]*$";

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
              (.s | .sec = ($str[:$m.offset] | test(SECURITY_COMMAND)) | clean_matches(QUOTED_PATHS; $m.string[1:-1]; "quoted")) as $r
              | .out += $gap + $q + $r.v + $q | .s = ($r.s | .sec = false) | .at = $end0
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
# Fields left unchanged (Precedence, step 1): team IDs, cdhashes, times, tty paths, entitlements. signing_id has a rule
# of its own (replace_id_parts). Numbers are never strings, so the walk does not see them.
def exempt($p):
  {"team_id": true, "cdhash": true, "time": true, "start_time": true}[$p[-1] | tostring]
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

# One URL (General string cleaning, step 6): user info removed and counted as redacted (a credential, never in the key),
# an internal host replaced, path segments cleaned like names in a cleaned place (with their %-escapes undone, as in a
# file:// URL), query and fragment values made data placeholders. Without a scheme (a curl or wget argument: evil.sh,
# intranet/a.sh, acme:8080/p) it is read the same way. Input: the state. Output: {v, s}.
def clean_url($u0):
  # User info whose password holds an unescaped / (https://bob:p/w0rd@host/x): everything after the scheme up to the
  # last @ before any ? or #, when it starts user:password and the password does not start like a port.
  ([$u0 | capture("^(?<sch>[A-Za-z][A-Za-z0-9+.-]*://)(?<ui>[^/?#@:]+:(?![0-9]*(?:/|$))[^?#]*)@(?<rest>[^@?#]*(?:[?#][\\s\\S]*)?)$")]
   | .[0]) as $odd
  # Not when the authority already holds an @ before its first / (bob:pw@host/a/b@c.com: the user info ends there).
  | ($odd != null and ($odd.ui | contains("/")) and ($odd.ui | split("/")[0] | contains("@") | not)) as $isodd
  | (if $isodd then .stats.redacted += 1 else . end)
  | (if $isodd then $odd.sch + $odd.rest else $u0 end) as $u
  | ($u | capture("^(?<sch>[A-Za-z][A-Za-z0-9+.-]*://)?(?<auth>[^/?#]*)(?<path>/[^?#]*)?(?<q>\\?[^#]*)?(?<f>#[\\s\\S]*)?$")) as $c
  | ($c.auth | capture("^(?<ui>[\\s\\S]*)@(?<hp>[^@]*)$") // {ui: null, hp: .}) as $a
  | ($a.hp | capture("^(?<h>\\[[^\\]]*\\])(?<p>[\\s\\S]*)$") // capture("^(?<h>[^:]*)(?<p>[\\s\\S]*)$")) as $hp
  | (if $a.ui != null and $a.ui != "\u0002" then .stats.redacted += 1 else . end)
  | clean_host($hp.h; true) as $h
  | $h.s
  # A port is digits; anything else there (a password with a / in it, unescaped) is data.
  | (if $hp.p == "" or ($hp.p | test("^:[0-9]*$")) then {v: $hp.p, s: .} else placeholder("data"; $hp.p[1:]) | {v: (":" + .ph), s: .state} end) as $port
  | $port.s
  | (if $c.path == null or $c.path == "/" then {v: ($c.path // ""), s: .}
     else clean_path("file:///Users/Shared" + $c.path) | .v |= .[20:] end) as $pa
  | $pa.s
  | (if $c.q == null then {v: "", s: .} else clean_query($c.q[1:]) | .v = "?" + .v end) as $q
  | $q.s
  | (if $c.f == null then {v: "", s: .} else clean_query($c.f[1:]) | .v = "#" + .v end) as $f
  | {v: (($c.sch // "") + $h.v + $port.v + $pa.v + $q.v + $f.v), s: $f.s};

# curl's long options that take the next argument (CURL_SPEC in src/rules/args.ts).
def CURL_LONG_VALUES: {
  "--output": true, "--header": true, "--data": true, "--data-raw": true, "--data-binary": true, "--data-urlencode": true,
  "--request": true, "--user-agent": true, "--user": true, "--referer": true, "--cookie": true, "--cookie-jar": true,
  "--form": true, "--max-time": true, "--connect-timeout": true, "--proxy": true, "--output-dir": true, "--config": true,
  "--dump-header": true, "--write-out": true, "--upload-file": true, "--cert": true, "--retry": true, "--range": true,
  "--resolve": true, "--url": true
};
def curl_value_option($prev):
  CURL_LONG_VALUES[$prev] == true
  or (($prev | test("^-[A-Za-z]+$"))
      and ([$prev[1:] | explode[] | [.] | implode] as $l
           | (first(range(0; $l | length) | . as $k | select(SHORT_VALUES("curl") | contains($l[$k]))) // -1) == ($l | length) - 1));
# A value without a scheme whose host part ends in a file extension that is no top-level domain (Board.pdf,
# notes.txt/x): a file, even where curl or wget would read a URL, so it is cleaned as a name.
def file_like_host:
  (test("^[A-Za-z][A-Za-z0-9+.-]*://") | not)
  and ((capture("^[^/:]*\\.(?<e>[A-Za-z0-9]+)(?:[:/]|$)") | .e | ascii_downcase) as $e
       | FILE_EXTENSIONS[$e] == true and TLD_EXTENSIONS[$e] != true) // false;
# True when $w, the argument after $prev, is a URL to curl or wget (what the download rule reads with looksLikeUrl):
# a positional, or curl's --url value; not a file name (file_like_host).
def url_position($prog; $prev; $w):
  ($prog == "curl" or $prog == "wget") and ($w | startswith("-") | not) and ($w | file_like_host | not)
  and (($prog == "curl" and $prev == "--url")
       or ((if $prog == "curl" then curl_value_option($prev) else wget_value_option($prev) end | not) and ($w | looks_like_url)));
# What argv[$i] is to the network, as a whole: "url" (url_position), "host" (ssh's host: [user@]host; or a dotted
# positional of a HOST_PROGRAMS program that is not an option's value, or whose last label is not a file extension),
# or null.
def net_position($prog; $args; $i; $sshhost):
  ($args[$i]) as $w | ($args[$i - 1] | if type == "string" then . else "" end) as $prev
  | if ($w | type) != "string" then null
    elif url_position($prog; $prev; $w) then "url"
    elif $sshhost == $i then "ssh"
    elif HOST_PROGRAMS[$prog] == true and ($w | test("^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$"))
         and (($prev | test("^-[A-Za-z]$") | not) or FILE_EXTENSIONS[$w | split(".") | last | ascii_downcase] != true) then "host"
    else null end;

# The index of ssh's host in argv (see ssh_command_index), or null.
def ssh_host_index($args):
  first(foreach range(1; $args | length) as $i ({skip: false, host: null};
          $args[$i] as $a
          | if .skip then .skip = false
            elif ($a | type) != "string" then .
            elif $a == "--" then .
            elif $a | startswith("-") then .skip = ($a | test(SSH_NEXT_VALUE))
            else .host = $i end;
          .host | select(. != null))) // null;

# A whole argument in a network position, cleaned. Input: the state. Output: {v, s}.
def clean_net_word($kind; $w):
  if $kind == "url" then clean_url($w)
  elif $kind == "ssh" then
    ([$w | capture("^(?<u>[\\s\\S]*@)?(?<h>[^@]*)$")] | .[0]) as $c
    | if $c == null then {v: $w, s: .} else clean_host($c.h; true) | .v = ($c.u // "") + .v end
  else clean_host($w; false) end;

# Shell code as words (a quoted string is part of its word) and separators, for code_urls.
def CODE_WORDS: "(?:\"(?:\\\\.|[^\"\\\\])*\"|'[^']*'|\\\\.|[^\\s\"'`;|&<>()])+|[;|&()`\\n]+|[<>]+";
# A word without its quotes, when it is all one quoted string or has no quotes or backslashes; else null.
def plain_word:
  if test("^\"[^\"\\\\]*\"$") or test("^'[^']*'$") then .[1:-1]
  elif test("^[^\"'\\\\]*$") then . else null end;
# curl and wget's URL arguments in shell code (url_position, as for argv): each command's words are read after
# assignments and wrappers (sudo, env …), and a word after a redirection is a file. A cleaned URL is written as a
# token (\u0001N\u0001, unrest_urls puts it back) that the later steps of the shell code leave alone: they would take
# evil.sh for a relative file name, and /tmp/name3 in evil.com/tmp/name3 for a path to clean again. A quoted word that
# runs curl or wget is read as shell code too (do shell script "curl …", sh -c 'wget …'). Input: the state.
# Output: {v, s, prot: the cleaned URLs, by token number from $n0}.
def code_urls_from($str; $n0):
  ($str | contains("\u0001") | not) as $tok
  | reduce ($str | match(CODE_WORDS; "g")) as $m ({s: ., out: "", at: 0, cmd: null, prev: "", prot: [], wrap: null, skipv: false, dur: false};
    $m.string as $w
    | if ($w | test("^[;|&()`\n]")) then .cmd = null | .prev = "" | .wrap = null | .skipv = false | .dur = false
      elif ($w | test("^[<>]")) then .prev = $w
      elif .cmd == null then
        # Before the command: assignments, wrappers, their options and option values, timeout's duration.
        if .skipv then .skipv = false
        elif ($w | test("^[A-Za-z_][A-Za-z0-9_]*=")) then .
        elif WRAPPER_OPTIONS[$w] != null then .wrap = $w | .dur = ($w == "timeout")
        elif ($w | startswith("-")) then .skipv = (.wrap != null and wrapper_value_option(.wrap; $w))
        elif .dur then .dur = false
        else .cmd = ($w | plain_word // "" | split("/") | last) | .prev = "" end
      else
        ($w | plain_word) as $u
        # A scheme URL is cleaned already (URL_RE).
        | if (.cmd == "curl" or .cmd == "wget") and $u != null and ($u | contains("://") | not) and (.prev | test("^[<>]") | not)
             and (.cmd as $c | .prev as $pv | $c | url_position($c; $pv; $u)) then
            (.s | clean_url($u)) as $r
            | (if $tok then "\u0001\($n0 + (.prot | length))\u0001" else $r.v end) as $put
            | .out += $str[.at:$m.offset] + (if $u == $w then $put else $w[:1] + $put + $w[-1:] end)
            | .at = $m.offset + $m.length | .s = $r.s | if $tok then .prot += [$r.v] else . end
          elif $u != null and $u != $w and ($u | contains("curl") or contains("wget")) then
            (.s | code_urls_from($u; $n0 + (.prot | length))) as $r
            | if $r.v == $u then .s = $r.s
              else .out += $str[.at:$m.offset] + $w[:1] + $r.v + $w[-1:] | .at = $m.offset + $m.length | .s = $r.s | .prot += $r.prot end
          else . end
        | .prev = ($u // $w)
      end)
  | {v: (.out + $str[.at:]), s: .s, prot: .prot};
def code_urls($str): code_urls_from($str; 0);
# The URLs code_urls set aside, put back into the cleaned value.
def unrest_urls($prot): if $prot == [] then . else gsub("\u0001(?<i>[0-9]+)\u0001"; $prot[.i | tonumber]) end;

# ---- credentials, data and the environment (Precedence, steps 3 and 4) -----------------------------------------
# Recognised credentials become <redacted>, are counted (stats.redacted) and never reach the key. Values that may be a
# secret or evidence (a curl request body, a long encoded run) become data placeholders, their real value in the key.
# Both run on a raw value before every other step, so a secret is never taken for a name, host or email (which the key
# would hold). Until a value is written back, a redaction is the marker \u0002 (REDACTED), one character the later steps
# leave alone: <redacted> itself would read as a redirection in shell code, and its word as a name. unmark writes it
# out. Replacement is in place: an argument or environment entry is rewritten, never removed or split.
def REDACTED: "\u0002";
def unmark: if contains("\u0002") then split("\u0002") | join("<redacted>") else . end;

# Credential shapes, recognised anywhere: AWS access keys, GitHub tokens, Slack tokens, sk- API keys, JWTs, PEM
# private key blocks, and the token of an Authorization header outside curl's -H (git -c http.extraHeader=…), whose
# name and scheme stay (the part a regex captures as p). One regex of the kinds a cheap test finds (each regex is compiled on every call); no shape is
# shorter than 15 characters. Input: the string.
def shape_res:
  if length < 15 then []
  else [ (if contains("AKIA") or contains("ASIA") then "(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])" else empty end),
         (if contains("ghp_") or contains("gho_") or contains("ghs_") or contains("github_pat_") then
            "(?<![A-Za-z0-9_])(?:gh[pos]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})" else empty end),
         (if contains("xox") then "(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}" else empty end),
         (if contains("sk-") or contains("sk_") then "(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,})" else empty end),
         (if contains("eyJ") then "(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*" else empty end),
         # A header has a colon; its name may be written in any case (AUTHORIZATION:).
         (if contains(":") and (ascii_downcase | contains("authorization")) then "(?<p>(?i:authorization)\\s*:\\s*(?:(?i:bearer|basic|token)\\s+)?)[A-Za-z0-9._~+/-]{8,}=*" else empty end),
         (if contains("PRIVATE KEY") then
            "-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:[\\s\\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|[\\s\\S]*$)" else empty end) ]
  end;
def shape_maybe: shape_res as $r | $r != [] and test($r | join("|"));
# Every credential shape in $str redacted. Input: the state. Output: {v, s}.
def redact_shapes($str):
  ($str | shape_res | join("|")) as $re
  | if $re == "" then {v: $str, s: .}
    else ([$str | match($re; "g")] | length) as $k
      | if $k == 0 then {v: $str, s: .} else {v: ($str | gsub($re; "\(.p // "")\u0002")), s: (.stats.redacted += $k)} end
    end;

# A run of 32 or more base64, base64url or hex characters (a payload, a key) that is not part of a path, a file name,
# a dotted name (bundle ID, host), an option name or an email: it does not start or end next to a / . - @ or ~. It is
# data when it is hex with digits and letters, or base64 with capitals, small letters and digits that change kind
# often (a quarter of its characters), as random text does and words (AutofillServerCommunication2) do not. UUIDs have
# dashes (no hex run) and one case of letters (no base64). A run with a / may be a path (Application Support/Code/…,
# Projects/Acme2Merger/Draft7): it is data only when no part between slashes is a word of 4 or more letters and the
# kind changes on half its characters; random base64 changes on about two thirds. Input: the run.
def ENTROPY_RUN: "(?<![A-Za-z0-9+/_.~@\\\\-])[A-Za-z0-9+_][A-Za-z0-9+/_-]{31,}={0,2}(?![A-Za-z0-9+/=_.@\\\\-])";
def high_entropy:
  if test("^[0-9A-Fa-f]+$") then test("[0-9]") and test("[A-Fa-f]")
  else (index("/") != null) as $sl
    | test("[A-Z]") and test("[a-z]") and test("[0-9]")
    and (($sl | not) or all(split("/")[]; test("^[A-Za-z]{4,}$") | not))
    and ((gsub("/"; "") | explode | map(if . >= 65 and . <= 90 then 0 elif . >= 97 and . <= 122 then 1 elif . >= 48 and . <= 57 then 2 else 3 end)
          | . as $c | [range(1; length) | select($c[.] != $c[. - 1])] | length) * (if $sl then 2 else 4 end) >= (gsub("/"; "") | length))
  end;
def entropy_maybe: length >= 32 and any(match(ENTROPY_RUN; "g"); .string | high_entropy);
# Every such run in $str a data placeholder; the text around it stays. Input: the state. Output: {v, s}.
def map_entropy($str):
  reduce ([$str | match(ENTROPY_RUN; "g")] | map(select(.string | high_entropy)))[] as $m ({s: ., out: "", at: 0};
    (.s | placeholder("data"; $m.string)) as $r
    | .out += $str[.at:$m.offset] + $r.ph | .s = $r.state | .at = $m.offset + $m.length)
  | {v: (.out + $str[.at:]), s: .s};

# What a value may hold, tested once and remembered: {m: net_maybe (an email, host or URL), sh: a credential shape,
# en: an encoded run ($ent: the value may have one; paths, file names and network words may not), s}. Most values come
# back in event after event, so one with none of them is noted (state.nf: 1 for none but an encoded run not looked
# for, 2 for none at all; at most 8192 values of up to 1 KB, emptied when full). Input: the state.
def pre_test($str; $ent):
  (.nf[$str] // 0) as $c
  | if $c == 2 or ($c == 1 and ($ent | not)) then {m: false, sh: false, en: false, s: .}
    else
      (if $c == 1 then false else net_maybe($str) end) as $m
      | (if $c == 1 then false else $str | shape_maybe end) as $sh
      | ($ent and ($str | entropy_maybe)) as $en
      | {m: $m, sh: $sh, en: $en,
         s: (if $m or $sh or $en or ($str | utf8bytelength) > 1024 then .
             else (if .nfn >= 8192 then .nf = {} | .nfn = 0 else . end)
               | (if .nf[$str] == null then .nfn += 1 else . end) | .nf[$str] = (if $ent then 2 else 1 end) end)}
    end;

# Names that look secret, in NAME=value arguments, assignments, environment entries and headers.
def SECRET_NAME: "(?i)password|passwd|token|secret|api_?key|auth|credential";
def SECRET_HEADER: "(?i)auth|cookie|password|passwd|token|secret|api[-_]?key|credential";
# Long options whose value is a secret, for any program: --password, --http-password, --access-token, --api-key …
# (not --password-stdin or --token-file).
def SECRET_LONG: "^--(?:[A-Za-z0-9]+[-_])*(?:password|passwd|token|secret|api[-_]?key|apikey)$";
# A cheap test before the generic options are looked at: one regex over the whole command.
def SECRET_WORDS: "(?i)pass|token|secret|api.?key|auth|credential";
def secret_assignment: test("^[A-Za-z_][A-Za-z0-9_]*=.") and (.[:index("=")] | test(SECRET_NAME));

# An edit: {i: the index in the command, v: its new value}.
# Generic credentials in $a from index $from: --secret=value, --secret value (not when $nonext: mysql's --password
# alone asks for it) and NAME=value with a secret-looking name.
def generic_edits($a; $from; $nonext):
  if ([$a[$from:][] | strings] | join(" ") | test(SECRET_WORDS) | not) then []
  else [ range($from; $a | length) as $i | $a[$i] as $x | select($x | type == "string" and (contains("\u0002") | not))
         | if ($x | startswith("--")) then
             ($x | index("=")) as $q
             | if $q != null then (if $q < ($x | length) - 1 and ($x[:$q] | test(SECRET_LONG; "i")) then {i: $i, v: ($x[:$q + 1] + REDACTED)} else empty end)
               elif ($nonext | not) and ($x | test(SECRET_LONG; "i")) and ($a[$i + 1] | type == "string" and (startswith("-") | not)) then {i: ($i + 1), v: REDACTED}
               else empty end
           elif ($x | contains("=")) and ($x | secret_assignment) then {i: $i, v: ($x[:($x | index("=")) + 1] + REDACTED)}
           else empty end ]
  end;

# dscl: the password after -authonly <user>, the passwords after -passwd <user>, -P's value.
def dscl_edits($a):
  [ range(1; $a | length) as $j | $a[$j] as $x
    | if $x == "-authonly" or $x == "authonly" or $x == "-passwd" or $x == "passwd" then range($j + 2; $a | length) | {i: ., v: REDACTED}
      elif $x == "-P" and $j + 1 < ($a | length) then {i: ($j + 1), v: REDACTED}
      else empty end ];

# security: the options that carry a password, by subcommand. Not find-*-password's bare -w (the keychain-access rule
# reads it), and not -p where it is a path (find-internet-password, add-internet-password).
def SECURITY_SECRETS: {
  "add-generic-password": "wX", "add-internet-password": "wX", "unlock-keychain": "p", "create-keychain": "p",
  "set-keychain-password": "op", "set-generic-password-partition-list": "k", "set-internet-password-partition-list": "k",
  "set-key-partition-list": "k", "import": "P", "export": "P"
};
def security_edits($a):
  (reduce range(1; $a | length) as $j ({sub: null, skip: false};
     if .sub != null then . elif .skip then .skip = false
     elif ($a[$j] | type) != "string" then .
     elif $a[$j] == "-p" then .skip = true
     elif ($a[$j] | startswith("-")) then .
     else .sub = $j end) | .sub) as $k
  | (if $k == null then "" else SECURITY_SECRETS[$a[$k]] // "" end) as $l
  | if $l == "" then []
    else [ range($k + 1; $a | length) as $j | $a[$j] as $x | select($x | type == "string")
           | if ($x | test("^-[A-Za-z]$")) and ($l | contains($x[1:])) and $j + 1 < ($a | length) then {i: ($j + 1), v: REDACTED}
             elif ($x | test("^-[A-Za-z].")) and ($l | contains($x[1:2])) then {i: $j, v: ($x[:2] + REDACTED)}
             else empty end ]
    end;

# curl's option values: [{i, o: the option (a letter, or a long name), pre: what stays before an attached value}].
def CURL_MORE_LONG_VALUES: {"--data-ascii": true, "--json": true, "--form-string": true, "--proxy-user": true, "--oauth2-bearer": true, "--pass": true, "--proxy-header": true};
def curl_values($a):
  reduce range(1; $a | length) as $i ({pend: null, out: [], done: false};
    $a[$i] as $x
    | if .pend != null then .out += [{i: $i, o: .pend, pre: ""}] | .pend = null
      elif .done or ($x | type) != "string" or ($x | startswith("-") | not) or $x == "-" then .
      elif $x == "--" then .done = true
      elif ($x | startswith("--")) then (if CURL_LONG_VALUES[$x] or CURL_MORE_LONG_VALUES[$x] then .pend = $x else . end)
      else arg_value("curl"; $x) as $o
        | if $o.pre != "" and ($o.pre | startswith("--") | not) then .out += [{i: $i, o: $o.pre[-1:], pre: $o.pre}]
          elif curl_value_option($x) then .pend = $x[-1:]
          else . end
      end)
  | .out;
# What curl's credential options hold: a secret, a cookie (name=value; without = it is a file of cookies) or a header
# (Authorization, Cookie, Proxy-Authorization and the like: the value goes, the name stays).
def CURL_SECRETS: {
  "u": "all", "U": "all", "--user": "all", "--proxy-user": "all", "--oauth2-bearer": "all", "--pass": "all",
  "b": "cookie", "--cookie": "cookie", "H": "header", "--header": "header", "--proxy-header": "header"
};
def curl_edits($a):
  [ curl_values($a)[] | . as $c | CURL_SECRETS[$c.o] as $kind | select($kind != null)
    | ($a[$c.i] | if type == "string" then .[($c.pre | length):] else null end) as $val
    | select($val != null and $val != "")
    | if $kind == "all" or ($kind == "cookie" and ($val | contains("="))) then {i: $c.i, v: ($c.pre + REDACTED)}
      elif $kind == "header" then
        ([$val | capture("^(?<n>[^:]+:\\s*)(?<r>[\\s\\S]+)$")] | .[0]) as $h
        | if $h != null and ($h.n | test(SECRET_HEADER)) then {i: $c.i, v: ($c.pre + $h.n + REDACTED)} else empty end
      else empty end ];

# Other programs' password options: a value after the option (next) or attached to it (attached: -pSECRET). sshpass
# runs a command after its own options (until: the options that take a value): that command's -p is its own (ssh -p
# 2222), and it is read as a command too (command_secrets).
def MYSQL_FAMILY: {"mysql": true, "mysqldump": true, "mysqladmin": true, "mysqlimport": true, "mysqlshow": true, "mysqlcheck": true,
                   "mysqlpump": true, "mysqlsh": true, "mariadb": true, "mariadb-dump": true, "mariadb-admin": true};
def SECRET_OPTIONS($prog):
  if MYSQL_FAMILY[$prog] or $prog == "7z" or $prog == "7za" or $prog == "7zz" then {attached: "-p", next: {}}
  elif $prog == "sshpass" then {attached: "-p", next: {"-p": true}, until: {"-p": true, "-f": true, "-d": true, "-P": true}}
  elif $prog == "zip" or $prog == "unzip" then {attached: "-P", next: {"-P": true}}
  elif $prog == "openssl" then {attached: null, next: {"-pass": true, "-passin": true, "-passout": true, "-k": true}}
  else null end;
# The index of the command a program like sshpass runs: the first word after its options and their values.
def wrapped_at($a; $values):
  first(foreach range(1; $a | length) as $i ({skip: false, at: null};
          if .skip then .skip = false
          elif ($a[$i] | type) != "string" or ($a[$i] | startswith("-") | not) then .at = $i
          else .skip = ($values[$a[$i]] == true) end;
          .at | select(. != null))) // null;
def option_edits($a; $spec):
  (if $spec.until == null then ($a | length) else wrapped_at($a; $spec.until) // ($a | length) end) as $end
  | [ range(1; $end) as $j | $a[$j] as $x | select($x | type == "string")
    | if $spec.next[$x] and $j + 1 < $end then {i: ($j + 1), v: REDACTED}
      elif $spec.attached != null and ($x | startswith($spec.attached)) and ($x | length) > 2 then {i: $j, v: ($spec.attached + REDACTED)}
      else empty end ];

# The recognised credentials in a command ($a[0] is its program, $prog that program's name) redacted, in place: the
# Credentials list of the spec. Input: the state. Output: {v: the command, s}.
def redact_args($a; $prog):
  ( generic_edits($a; 1; MYSQL_FAMILY[$prog] == true)
    + (if $prog == "dscl" then dscl_edits($a) elif $prog == "security" then security_edits($a) elif $prog == "curl" then curl_edits($a)
       else SECRET_OPTIONS($prog) as $o | if $o == null then [] else option_edits($a; $o) end end) ) as $ed
  | if $ed == [] then {v: $a, s: .}
    else . as $st
      | (reduce $ed[] as $d ({a: $a, n: 0, done: {}};
           if .done[$d.i | tostring] then . else .a[$d.i] = $d.v | .n += 1 | .done[$d.i | tostring] = true end)) as $r
      | {v: $r.a, s: ($st | .stats.redacted += $r.n)}
    end;

# curl's request bodies (-d, --data*, --json, -F, --form*) as data placeholders, whole, unless they name a file to send
# (@file, name=@file, name=<file: a path, cleaned as one) or hold a redaction already (TOKEN=<redacted>). A credential
# shape in a body is redacted before the body is keyed. Input: the state. Output: {v: the command, s}.
def CURL_DATA: {"d": "d", "--data": "d", "--data-ascii": "d", "--data-binary": "d", "--json": "d", "--data-raw": "raw",
                "--data-urlencode": "url", "F": "form", "--form": "form", "--form-string": "raw"};
def map_data($a; $prog):
  if $prog != "curl" then {v: $a, s: .}
  else reduce (curl_values($a)[] | select(CURL_DATA[.o] != null)) as $c ({a: $a, s: .};
         CURL_DATA[$c.o] as $kind
         | ($a[$c.i] | if type == "string" then .[($c.pre | length):] else "" end) as $val
         | if $val == "" or ($val | contains("\u0002"))
              or ($kind == "d" and ($val | startswith("@"))) or ($kind == "url" and ($val | test("^[^=]*@")))
              or ($kind == "form" and ($val | test("^[^=]*=[@<]"))) then .
           else (.s | redact_shapes($val)) as $r
             | ($r.s | placeholder("data"; $r.v | unmark)) as $p
             | .a[$c.i] = $c.pre + $p.ph | .s = $p.state
           end)
    | {v: .a, s: .s}
  end;

# Where the command starts in a list of words: after assignments (NAME=value) and wrappers (sudo, env, nohup …: see
# WRAPPER_OPTIONS) with their options and option values. null when there is none.
def command_at($w; $from):
  reduce range($from; $w | length) as $i ({at: null, wrap: null, skipv: false, dur: false};
    if .at != null then .
    else ($w[$i] // "") as $x | ($x | split("/") | last // "") as $b
      | if .skipv then .skipv = false
        elif ($x | test("^[A-Za-z_][A-Za-z0-9_]*=")) then .
        elif WRAPPER_OPTIONS[$b] != null then .wrap = $b | .dur = ($b == "timeout")
        elif ($x | startswith("-")) and .wrap != null then .skipv = wrapper_value_option(.wrap; $x)
        elif .dur then .dur = false
        else .at = $i end
    end)
  | .at;

# One command (a list of words: strings, or null where a word is not plain): credentials redacted and request bodies
# keyed, behind wrappers too (sudo -u root curl -u bob:pw …: the wrapper's own option values are not the command's).
# Input: the state. Output: {v, s}.
def command_secrets($w):
  (($w[0] // "") | split("/") | last // "") as $p0
  | (if WRAPPER_OPTIONS[$p0] != null or ($p0 | test("^[A-Za-z_][A-Za-z0-9_]*=")) then command_at($w; 0) else 0 end) as $k
  | if $k == null then {v: $w, s: .} | .v as $x | .s | generic_edits($x; 0; false) as $ed
      | if $ed == [] then {v: $x, s: .} else .stats.redacted += ($ed | map(.i) | unique | length) | {v: (reduce $ed[] as $d ($x; .[$d.i] = $d.v)), s: .} end
    else
      (($w[$k] // "") | split("/") | last // "") as $prog
      | redact_args($w[$k:]; $prog) as $r0
      # The command sshpass runs.
      | (SECRET_OPTIONS($prog).until // null) as $u
      | ($r0 | if $u == null then . else wrapped_at($r0.v; $u) as $c
           | if $c == null then . else .v as $v | .s | command_secrets($v[$c:]) | .v = $v[:$c] + .v end end) as $r
      | ($r.s | map_data($r.v; $prog)) as $d
      | (if $k == 0 then {v: [], s: $d.s}
         else ($w[:$k]) as $pre | $d.s | generic_edits($pre; 0; false) as $ed
           | if $ed == [] then {v: $pre, s: .}
             else .stats.redacted += ($ed | map(.i) | unique | length) | {v: (reduce $ed[] as $e ($pre; .[$e.i] = $e.v)), s: .} end
         end) as $h
      | {v: ($h.v + $d.v), s: $h.s}
    end;

# Credentials and request bodies in an exec's arguments (argv), and in ssh's remote command when it comes as several
# arguments (ssh host mysql -pX). An argument that is code (sh -c 'TOKEN=x curl …') is not one NAME=value: its commands
# are read in the walk (code_secrets), so an edit here is undone. Input: the state. Output: {v, s}.
def argv_secrets($args):
  if ($args | length) < 2 then {v: $args, s: .}
  else ($args[0] | if type == "string" then split("/") | last // "" else "" end) as $prog
    | command_secrets([$args[] | if type == "string" then . else null end])
    | (if $prog == "ssh" then ssh_command_index($args) else null end) as $sc
    | (if $sc == null or $sc >= ($args | length) then .
       else .v as $v | .s | command_secrets($v[$sc:]) | .v = $v[:$sc] + .v end) as $r
    | [range(1; $args | length) as $i
       | select(($args[$i] | type) == "string" and $r.v[$i] != $args[$i] and ($args[$i] | test("\\s")))
       | select(code_arg($prog; $args; $i; shell_text($args; $i; $sc)))
       | $i] as $code
    | {v: [range(0; $args | length) as $i
           | if ($args[$i] | type) != "string" or ($code | index([$i])) != null then $args[$i] else $r.v[$i] end],
       s: ($r.s | .stats.redacted -= ($code | length))}
  end;

# The same in shell code (sh -c, su -c, osascript -e, ssh's remote command, behind wrappers: what code_arg finds),
# command by command: CODE_WORDS splits it as code_urls does, a word after a redirection is a file and left out. A
# quoted word keeps its quotes; a quoted word that is code itself (bash -c "…", do shell script "…") is read the same
# way. A cheap test first: nothing can match without one of these words.
def code_maybe:
  contains("=") or contains("--") or contains("assword") or contains("curl") or contains("dscl") or contains("security") or contains("mysql")
  or contains("mariadb") or contains("sshpass") or contains("zip") or contains("7z") or contains("openssl");
# A word of shell code as the shell reads it: '…' as it is, "…" with \" \\ \$ \` undone, \x outside quotes as x.
def SHELL_PIECE: "'([^']*)'|\"((?:\\\\[\\s\\S]|[^\"\\\\])*)\"|\\\\([\\s\\S])|([^'\"\\\\]+)|([\\s\\S])";
def shell_unquote:
  [scan(SHELL_PIECE) | if .[0] != null then .[0] elif .[1] != null then .[1] | gsub("\\\\(?<c>[\"\\\\$`\n])"; .c)
                       else .[2] // .[3] // .[4] end] | join("");
# A value written back as one shell word: as it is when nothing in it is special to the shell, else in '…'.
def shell_quote: if test("^[^\\s'\"\\\\$`;&|<>()*?\\[\\]{}#~]*$") then . else "'" + gsub("'"; "'\\''") + "'" end;
def CODE_SEPARATORS: {";": true, "|": true, "&": true, "(": true, ")": true, "`": true, "\n": true};
# AppleScript's do shell script … password "…" (osascript -e, or in shell code) is redacted first: the keyword password
# outside a string, then a string. A string is matched whole first, so the word password inside one (display dialog
# "Enter your password " default answer "") is text, not the parameter.
def APPLESCRIPT_PASSWORD: "\"(?:[^\"\\\\]|\\\\.)*\"|(?<p>(?i:\\bpassword)\\s+)\"(?:[^\"\\\\]|\\\\.)*\"";
def code_secrets($str0):
  if ($str0 | code_maybe | not) then {v: $str0, s: .}
  else
    (if $str0 | contains("assword") | not then [] else [$str0 | match(APPLESCRIPT_PASSWORD; "g") | select(.captures[0].string != null)] end) as $pm
    | ($pm | length) as $ap
    | (if $ap == 0 then $str0
       else reduce $pm[] as $m ({out: "", at: 0};
              .out += $str0[.at:$m.offset] + $m.captures[0].string + "\"\u0002\"" | .at = $m.offset + $m.length)
         | .out + $str0[.at:] end) as $str
    | .stats.redacted += $ap
    | (reduce ($str | match(CODE_WORDS; "g")) as $m ({cmds: [], cur: [], redir: false};
       $m.string[:1] as $c
       | if CODE_SEPARATORS[$c] then .cmds += [.cur] | .cur = [] | .redir = false
         elif $c == "<" or $c == ">" then .redir = true
         elif .redir then .redir = false
         else .cur += [$m] end)
     | .cmds + [.cur] | map(select(length > 0))) as $cmds
    | reduce $cmds[] as $c ({s: ., ed: []};
        # Each word as the shell reads it; a plain word ("…", '…' or no quotes) keeps its quotes when it is written back,
        # any other word that changes is written as one shell word (shell_quote).
        ($c | map(.string | plain_word)) as $pw
        | ($c | map(.string | plain_word // shell_unquote)) as $u
        | (.s | command_secrets($u)) as $r
        | .s = $r.s
        | reduce range(0; $c | length) as $i (.;
            $c[$i] as $m | $m.string as $raw
            | if $r.v[$i] != $u[$i] then
                .ed += [{at: $m.offset, len: $m.length,
                         text: (if $pw[$i] == null then $r.v[$i] | shell_quote
                                elif $raw != $pw[$i] then $raw[:1] + $r.v[$i] + $raw[-1:] else $r.v[$i] end)}]
              else
                # Quoted code in the code: "…" (only \" escaped inside) or '…'.
                ($pw[$i] // (if $raw | test("^\"(?:[^\"\\\\]|\\\\\")*\"$") then $raw[1:-1] | gsub("\\\\\""; "\"") else null end)) as $in
                | if $in == null or $in == $raw or ($in | code_maybe | not) then .
                  else (.s | code_secrets($in)) as $q
                    | if $q.v == $in then .s = $q.s
                      else .s = $q.s
                        | .ed += [{at: $m.offset, len: $m.length,
                                   text: ($raw[:1] + (if $raw[:1] == "\"" and $pw[$i] == null then $q.v | gsub("\""; "\\\"") else $q.v end) + $raw[-1:])}]
                      end
                  end
              end))
    | if .ed == [] then {v: $str, s: .s}
      else (reduce (.ed | sort_by(.at))[] as $e ({out: "", at: 0}; .out += $str[.at:$e.at] + $e.text | .at = $e.at + $e.len)
            | .out + $str[.at:]) as $v
        | {v: $v, s: .s}
    end
  end;

# The environment (exec.env), in place: names kept, with account names and seeds in them replaced as parts (JDOE_HOME
# becomes user1_HOME), except the standard names (SAFE_ENV, USER, LOGNAME: an account called home leaves HOME alone); a value redacted, except those of the useful variables (PATH, SHELL, TMPDIR, HOME, PWD, OLDPWD,
# LANG, LC_*, TERM*, __CF*, DYLD_*: injection evidence), which are cleaned like any other value; a secret-looking name
# (SECRET_NAME) always redacted. An entry without =, or whose name is not a variable's (/Users/jdoe/Board minutes=1),
# is redacted whole; an empty value stays empty. Only secret-looking names count as redacted credentials; the other
# values are redacted by policy. Names come back in every exec, so each name's class and cleaned form are remembered
# (state.envk: {c: "k" keep, "r" redact, "s" secret, "x" not a name; n: the name cleaned}; at most 4096, emptied when
# an account name or seed is added). Input: the state. Output: {v: the environment, keep: [true at the indices still
# to clean], s}.
def SAFE_ENV: {"PATH": true, "SHELL": true, "TMPDIR": true, "HOME": true, "PWD": true, "OLDPWD": true, "LANG": true};
def env_class:
  if test("^[A-Za-z_][A-Za-z0-9_]*$") | not then "x"
  elif test(SECRET_NAME) then "s"
  elif SAFE_ENV[.] or startswith("LC_") or startswith("TERM") or startswith("__CF") or startswith("DYLD_") then "k"
  else "r" end;
def clean_env($env):
  reduce range(0; $env | length) as $i ({v: $env, keep: [], s: .};
    $env[$i] as $x
    | if ($x | type) != "string" then .
      else ($x | index("=")) as $q
        | if $q == null then .v[$i] = "<redacted>"
          else $x[:$q] as $n
            | (.s.envk[$n] // {c: ($n | env_class), n: (if SAFE_ENV[$n] or $n == "USER" or $n == "LOGNAME" then $n else .s | replace_seeds($n) end)}) as $k
            | (if .s.envk[$n] == null then .s |= ((if .envkn >= 4096 then .envk = {} | .envkn = 0 else . end) | .envk[$n] = $k | .envkn += 1) else . end)
            | $k.c as $c | $k.n as $cn
            | if $c == "x" then .v[$i] = "<redacted>"
              elif $q == ($x | length) - 1 then (if $cn != $n then .v[$i] = $cn + "=" else . end)
              elif $c == "k" then .keep[$i] = true | (if $cn != $n then .v[$i] = $cn + $x[$q:] else . end)
              else .v[$i] = $cn + "=<redacted>" | if $c == "s" then .s.stats.redacted += 1 else . end end
          end
      end)
  | {v: .v, keep: .keep, s: .s};

# An exec's arguments and environment with their credentials and request bodies taken out, before any other step reads
# them. Input: the state. Output: {e: the event, envk: the environment indices left to clean (null: all), s}.
def pre_exec($e):
  (try $e.event.exec catch null) as $x
  | if ($x | type) != "object" then {e: $e, envk: null, s: .}
    else
      (if ($x.args | type) == "array" then argv_secrets($x.args) else {v: null, s: .} end) as $a
      | ($a.s | if ($x.env | type) == "array" then clean_env($x.env) else {v: null, keep: null, s: .} end) as $n
      | {e: ($e | if $a.v != null then .event.exec.args = $a.v else . end | if $n.v != null then .event.exec.env = $n.v else . end),
         envk: $n.keep, s: $n.s}
    end;

# The steps of clean_net, in this order: scheme URLs; in shell code ($code), curl and wget's URL arguments; then
# net_shapes. Input: the state. Output: {v, s, prot} (prot: see code_urls).
def net_steps($str; $code; $login):
  (if $str | contains("://") then net_sub($str; URL_RE; .m.string as $u | .s | clean_url($u)) else {v: $str, s: .} end)
  | .v as $s1 | .s
  | (if $code and ($s1 | contains("curl") or contains("wget")) then code_urls($s1) else {v: $s1, s: ., prot: []} end)
  | .v as $s2 | .prot as $prot | .s
  | net_shapes($s2; $code; $login) | .prot = $prot;

# Emails, internal hosts and URLs in a value (General string cleaning, steps 5 and 6; net_steps), after the cheap
# test (net_maybe). What it made of a value outside code and logins is cached (state.netc, at most 4096 values of up to 1 KB,
# emptied when full): environment entries come back in event after event, and most that hold an @ or a URL do. A
# cached value gives the placeholders it would get again, and the user info it removed is counted again. Input: the
# state. Output: {v, s}.
# net_maybe, remembered (pre_test: it lower-cases the value, which costs more than the rest of the test). Input: the
# state. Output: {m: what net_maybe says, s}.
def net_test($str): pre_test($str; false) | {m, s};
# clean_net with net_test's answer $m given.
def clean_net_m($str; $code; $login; $m):
  if ($m or ($code and ($str | contains("curl") or contains("wget")))) | not then {v: $str, s: ., prot: []}
  elif $code or $login != "" then net_steps($str; $code; $login)
  elif .netc[$str] != null then .netc[$str] as $c | {v: $c.v, s: (.stats.redacted += $c.r), prot: []}
  else .stats.redacted as $r0
    | net_steps($str; false; "")
    | if ($str | utf8bytelength) > 1024 then .
      else .v as $v | .s |= ((if .netn >= 4096 then .netc = {} | .netn = 0 else . end)
                              | .netc[$str] = {v: $v, r: (.stats.redacted - $r0)} | .netn += 1) end
  end;
def clean_net($str; $code; $login): net_test($str) as $t | $t.s | clean_net_m($str; $code; $login; $t.m);

# True when the raw value $v holds no account name or seed in any form: known (state.clear: executable paths and
# environment entries come back in event after event) or tested now. Input: the state.
def seed_free($v): .acctn == 0 or .clear[$v] == true or (.acctall as $re | $v | test($re; "i") | not);
# The state with $v noted as seed-free; the list is emptied when it reaches 8192, so it costs little to keep.
# Values over 1 KB are not noted: a few thousand of them would hold hundreds of MB.
def note_clear($v):
  if .acctn == 0 or .clear[$v] == true or ($v | utf8bytelength) > 1024 then .
  else (if .clearn >= 8192 then .clear = {} | .clearn = 0 else . end) | .clear[$v] = true | .clearn += 1 end;

# The event (input) cleaned, with the state the cleaning leaves and the key entries it created:
#   {event, state, new: [{kind, placeholder, real}]}
# Every string is walked, so a field nobody thought of cannot carry a name through. Programs the event runs are kept
# before any of its strings is cleaned. create.acl is dropped (it can name users and groups). A new file's separate
# name (named_in_dir) is cleaned as the last name of its folder. When an exec's cwd is in a cleaned place, its
# arguments that are relative names are cleaned as names in that folder; option names stay, and so does argv[0]
# unless it has folders (./Q3 Kit/tool: the folders are cleaned, the program's name is kept as a program that ran).
# Credentials and data come first (Precedence, steps 3 and 4): an exec's arguments and environment before the walk
# (pre_exec), then in each value shell code's commands (code_secrets), credential shapes and encoded runs.
def clean_event($state):
  (if (.event.create | type) == "object" then del(.event.create.acl) else . end) as $e0
  | (try $e0.event.exec.cwd.path catch null) as $cwd
  # Every string: an email or host needs no / and no name mapped before it.
  | [$e0 | paths(worth_cleaning(true))] as $ps
  | (reduce ($e0 | exec_names($ps)[]) as $n ($state; if .keep[$n] then . else .keep[$n] = true end)) as $s0
  | ($s0 | .new = [] | pre_exec($e0)) as $pre
  | $pre.e as $e | $pre.envk as $envk
  | (try $e.event.exec.args catch null) as $args
  | (($cwd | type) == "string" and ($args | type) == "array" and ($cwd | in_cleaned_place)) as $relc
  | (if ($args | type) == "array" then ($args[0] | if type == "string" then split("/") | last // "" else "" end) else "" end) as $prog
  | (if $prog == "ssh" then ssh_command_index($args) else null end) as $cmd
  | (if $prog == "ssh" then ssh_host_index($args) else null end) as $sshhost
  | reduce $ps[] as $p ({e: $e, s: $pre.s};
      (if .s.netp != false then .s.netp = false else . end)
      | ($e | getpath($p)) as $v
      | if ($v | type) == "object" then
          ($v | named_in_dir($p)) as $k
          | if $k == null then .
            else $v[$k.dir].path as $dir | $v[$k.name] as $name
              | if ($dir | startswith("/")) and $name != "" then
                  (.s | pre_test($name; false)) as $t
                  | ($t.s | if $t.sh then redact_shapes($name) else {v: $name, s: .} end) as $x
                  | ($x.s | clean_net_m($x.v; false; ""; $t.m)) as $nn
                  | (.s = $nn.s | .s.netp = (if $t.m then .s | net_flags($x.v) else false end) | .s | clean_relative($dir; $nn.v)) as $r
                  | .s = ($r.s | .netp = false) | .e |= setpath($p + [$k.name]; $r.s | replace_seeds($r.v) | unmark)
                else . end
            end
        elif $p[-1] == "signing_id" then
          if ($v | type) != "string" then .
          elif (.s | seed_free($v)) then .s |= note_clear($v)
          else (.s | replace_id_parts($v)) as $w | if $w != $v then .e |= setpath($p; $w) else . end end
        elif exempt($p) then .
        elif BARE_NAMES[$p[-1] | tostring] != null and ($e | getpath($p[:-1]) | named_in_dir($p[:-1])) != null then .
        # Environment values redacted by pre_exec are done.
        elif $envk != null and $p[2] == "env" and ($p | length) == 4 and $p[1] == "exec" and $envk[$p[3]] != true then .
        elif $v == "\u0002" then .e |= setpath($p; "<redacted>")
        else
          (($p | length) == 4 and $p[0:3] == ["event", "exec", "args"]) as $arg
          | ($arg and $p[3] > 0 and keychain_value($prog; $v)) as $kc
          | ($arg and $p[3] > 0 and shell_text($args; $p[3]; $cmd)) as $sh
          | ($arg and $p[3] > 0 and code_arg($prog; $args; $p[3]; $sh)) as $code
          # A whole argument curl or wget reads as a URL, ssh's host, or a host argument (ping, nc …): a URL or host,
          # never a relative name, so evil.sh stays and intranet/a.sh gets a host placeholder.
          | (if $arg and $p[3] > 0 and ($kc | not) and ($code | not) then net_position($prog; $args; $p[3]; $sshhost) else null end) as $np
          # Credentials and data: shell code's commands, then credential shapes and encoded runs (not in a path, a
          # URL or host word, whose runs are names: pre_test's $ent).
          | (if $code then .s | code_secrets($v) else {v: $v, s: .s} end) as $c
          | ($c.s | pre_test($c.v; $np == null and (path_field($p) | not))) as $t
          | ($t.s | if $t.sh then redact_shapes($c.v) else {v: $c.v, s: .} end) as $x
          | .s = $x.s | $x.v as $v1
          | if $np != null then
              (.s | clean_net_word($np; $v1)) as $r
              | ($r.s | replace_seeds($r.v) | unmark) as $w
              | .s = $r.s | if $w != $v then .e |= setpath($p; $w) else . end
            else
            # Emails, internal hosts and URLs first (steps 5 and 6), then the other steps on what they leave; a path
            # field that holds a path is a path, whose names are names.
            # The host step runs first on every value; the path step cleans what it left in names (state.netp, net_name).
            # Path fields too: the host step works the same in a path field and in an argument (ph_name).
            (.s | clean_net_m($v1; $code; if ($arg | not) or $code then "" elif SSH_FAMILY[$prog] == true then "all"
                                              elif $prog == "git" then "colon" else "" end; $t.m)) as $n
            | .s = (if $t.m then $n.s | .netp = net_flags($v1) else $n.s end)
            # Encoded runs after the host step, so a URL's query value is keyed once, whole, as in a curl argument.
            | (if $t.en then .s | map_entropy($n.v) else {v: $n.v, s: .s} end) as $en
            | .s = $en.s | $en.v as $u | $n.prot as $prot
            # Shell code is never a relative name. One word of an ssh command (ssh host ls Board/Q3.pdf) can be.
            | if $relc and $arg and ($kc | not)
                 and (if $p[3] == 0 then ($u | index("/")) != null
                      else ($code and ($cmd == null or ($u | test("\\s")))) | not end)
                 and (arg_value($prog; $u) as $o
                      | ($prog == "wget" and $o.pre == "" and $p[3] > 0 and ($o.val | file_like_host | not)
                         and (wget_value_option($args[$p[3] - 1] | if type == "string" then . else "" end) | not)) as $url_arg
                      | .s | relative_name($url_arg; $o.val)) then
                arg_value($prog; $u) as $o
                | (.s | clean_relative_arg($prog; $cwd; $o.val)) as $r
                | .s = $r.s | ($r.s | replace_seeds($o.pre + $r.v | unrest_urls($prot)) | unmark) as $w | if $w != $v then .e |= setpath($p; $w) else . end
              else
                ((if $kc then .s | .single = true | clean_string($u; false) | .s.single = false
                   elif $code then .s | .code = true | .rel = (if $relc and $sh then $cwd else null end)
                                   | clean_string($u; false) | .s.code = false | .s.rel = null
                   else .s | clean_string($u; path_field($p)) end) | .v |= unrest_urls($prot)) as $r
                | ($r.s | seed_free($r.v)) as $free
                | (if $free then $r.v else $r.s | replace_seeds_opts($r.v; $code) end | unmark) as $w
                | .s = (if $free then $r.s | note_clear($r.v) else $r.s end)
                | if $w != $v then .e |= setpath($p; $w) else . end
              end
            end
        end)
  | {event: .e, state: (.s | .netp = false), new: .s.new};

# One raw line against the state: {s: new state, emit: [event to write], new: [key entries]}.
def step($line):
  . as $s
  | if ($line | test("^[ \t\r]*$")) then {s: $s, emit: [], new: []}
    else
      ($s | .stats.eventsIn += 1) as $counted
      | (try ($line | fromjson) catch null) as $e0
      # The characters the cleaner uses as markers (U+0001: code_urls, U+0002: REDACTED) become U+FFFD in every string
      # first, so none in the capture can hide a credential or a body. JSON writes them as \u0001 and \u0002.
      | (if ($e0 | type) == "object" and ($line | contains("\\u0001") or contains("\\u0002") or contains("\u0001") or contains("\u0002"))
         then $e0 | walk(if type == "string" then gsub("[\u0001\u0002]"; "\ufffd") else . end) else $e0 end) as $e
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

# A key entry as the K line the script appends to the key file.
def key_line: "K\t\(.kind)\t\(.placeholder)\t\(.real | tojson)\n";

# Side channel first, then the event, so a key line is written before the event that needs it is.
def extract:
  (.new[] | key_line | stderr | empty),
  (if .done then "S\t\(.s.stats | tojson)\n" | stderr | empty else empty end),
  .emit[];

# The prescan of `clean -i FILE`: the names of every program the capture runs, so a dropper's name is kept from its
# first appearance, before it runs. Lines that do not parse, or events it cannot read, are skipped here (the cleaning
# pass drops and counts them).
def prescan:
  reduce (inputs | (try fromjson catch null) | objects
          | try exec_names([paths(type == "string" and index("/") != null)])[] catch empty) as $n ({}; .[$n] = true)
  | keys;

# The account names the summary warns about: shorter than 4 characters, a common word, or a word the rules look for.
def short_accounts: [.map.user // {} | keys[] | select(length < 4 or COMMON_ACCOUNT_WORDS[ascii_downcase] == true or protected_word(.))];

if $cfg[0].prescan == true then prescan
else
  initial_state($cfg[0]) as $s0
  # The seeds' key entries, before the first event.
  | ($s0.new[] | key_line | stderr | empty),
    foreach ((inputs | {line: .}), {end: true}) as $in (
      {s: ($s0 | .new = []), emit: [], new: []};
      if $in.end then {s: (.s | .stats.shortAccounts = short_accounts), emit: [], new: [], done: true} else .s | step($in.line) end;
      extract
    )
end
