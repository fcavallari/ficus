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
# stats: {...}, lastSeq: number|null}. `map` says which placeholder a real value already has, `next` the number the next
# placeholder of a kind gets, `keep` the names that stay as they are, `lastSeq` the highest global_seq_num seen.

# The first run of digits in a placeholder is its number: user3, Person 3, .name3, name3.pdf, host3.internal.invalid.
def placeholder_number: ([scan("[0-9]+")] | .[0] // "0") | tonumber;

# The state a run starts with: the loaded key's values keep their placeholders, and numbering goes on after them.
def initial_state($cfg):
  { map: (reduce $cfg.key[] as $k ({}; .[$k.kind][$k.real] = $k.placeholder)),
    next: (reduce $cfg.key[] as $k ({}; .[$k.kind] = ([.[$k.kind] // 1, ($k.placeholder | placeholder_number) + 1] | max))),
    keep: (reduce $cfg.keep[] as $n ({}; .[$n] = true)),
    stats: { eventsIn: 0, eventsOut: 0, unreadable: 0, seqGaps: 0, redacted: 0, placeholders: {} },
    lastSeq: null };

# Events Endpoint Security dropped show as holes in global_seq_num, which is consecutive in a complete capture.
def track_seq($e):
  ($e.global_seq_num | if type == "number" then . else null end) as $n
  | if $n == null then .
    else (if .lastSeq != null and $n > .lastSeq + 1 then .stats.seqGaps += ($n - .lastSeq - 1) else . end)
      | .lastSeq = ([.lastSeq, $n] | map(select(. != null)) | max)
    end;

# The event (input) cleaned, with the state the cleaning leaves and the key entries it created:
#   {event, state, new: [{kind, placeholder, real}]}
# Later tasks do the cleaning here.
def clean_event($state): {event: ., state: $state, new: []};

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
