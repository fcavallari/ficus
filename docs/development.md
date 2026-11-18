# Development and tests

```bash
npm test             # builds dist/ first (pretest), then runs the whole suite
npx vitest run test/rules.test.ts   # one file while iterating (needs dist/ only for build.test.ts)
```

A fresh clone runs most of the suite. `test/fixtures/synthetic-lab.jsonl` is a small hand-built capture (eslogger schema 11, an invented user `alice`, invented pids and tokens) that tells the steps of a lab intrusion, plus noise: a download, a script piped into `bash`, a fake password dialog, staging in `/tmp`, an orphaned process, a launch agent written by a shell redirect with its `btm` event, a login item registered by an app in Downloads, a recon burst, a process whose `exec` the capture missed, and a parent that started before the capture. `scripts/make-synthetic-lab.mjs` writes it (`node scripts/make-synthetic-lab.mjs`); a test checks the committed file is exactly what the script produces. The parser, model, rules, session and UI tests run on it.

The tests that check the code against real captures are kept, but they need files that are not in this repo (one is a capture of a private Mac, the others are third-party malware samples): `es-lab.jsonl` and `SpriteTreeSamples/*.json` in the repo's parent directory. When they are missing those tests are skipped and the run prints one note saying so. Set `FIXTURES_DIR` to a directory with the same layout (the `.json` samples are read from `$FIXTURES_DIR/SpriteTreeSamples/`) to run them:

```bash
FIXTURES_DIR=/path/to/captures npm test
```

`npm run dev` also accepts `?load=<file>` to open a development session named `dev` with a capture from the directory above the repo already loaded. That code is compiled out of the production build, and `test/build.test.ts` checks that it stays out.

## Roadmap

XPC connection edges are planned.
