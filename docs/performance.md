# Performance

Targets: an 11,610-event, 28.6 MB capture from drop to the triage screen in under 5 seconds; a 500 MB capture loads without crashing the tab, slower is acceptable. The worker streams the file in 4 MB slices and keeps only the fields the model needs.

Measured on an Apple M5 Max, 48 GB, Node 24, and the in-app browser pane (Chromium) with `dist/index.html` served over HTTP:

| Capture | Where | Result |
|---|---|---|
| a lab capture, 28.6 MB, 11,610 events | browser, from the file input's change event to the triage screen | 0.09 s on first load, 0.3 to 0.5 s on later ones (includes writing the capture record to IndexedDB). Under the 5 s target. |
| a schema v6 sample, 1.5 MB | browser, same measure | about 0.1 s |
| `scratch/big.jsonl`, 516 MB, 208,980 events | browser, same measure | 4.6 s, no crash. Switching from Triage to Tree and back took about 1.2 s and the tree rendered rows; interactivity was not otherwise tested. Tab heap read 69 MB afterwards. |
| `scratch/big.jsonl` | Node: stream lines through `ModelBuilder`, then `analyze` | 1.1 s total (parse 1.0 s, analyze 0.04 s). Peak `heapUsed` 292 MB, peak RSS 587 MB, 232 MB retained after GC. For comparison the 28.6 MB capture alone peaks at 23 MB heap. |

Caveat: `scratch/big.jsonl` is the 28.6 MB capture repeated 18 times with `global_seq_num` offset by `n x 10,000,000` per copy (`node scripts/make-big.mjs [capture.jsonl]`). Every copy repeats the same pids and audit tokens, so the model still sees 4,722 processes, not 18 times as many; the test proves load volume and memory behaviour on very large inputs, not a capture with 500 MB of distinct processes. A real capture with many distinct processes would retain more memory per event. The browser was driven by feeding the file to the page's file input from script, not by a physical drag from Finder. Because the capture fingerprint is taken from the file's head, `big.jsonl` has the same fingerprint as the capture it was made from and replaces it within a session; that is the “a capture that grows keeps its verdicts” behaviour working as designed.

To reproduce: `node scripts/make-big.mjs path/to/capture.jsonl` (writes `scratch/big.jsonl`, 516 MB for that capture, gitignored), load it, then delete it.
