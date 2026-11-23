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

## The am-i-pwned plugin copy

The am-i-pwned skill lives in the `am-i-pwned` plugin of Automattic's `claude-code-plugins` repo (`plugins/am-i-pwned`). Ficus owns two things the skill uses: the indicator list [`src/rules/indicators.json`](../src/rules/indicators.json) and the developer tooling folders in `src/rules/locations.ts`. The plugin holds generated copies of them (its `references/known-indicators.md`, the generated block of `lib/indicators.sh` and the tooling-folder list in `lib/signatures.sh`), each stamped with a hash of its source. Nothing in the plugin is edited by hand for these.

After changing either source:

```bash
node scripts/gen-indicators.mjs     # writes the copies into the plugin checkout
```

then commit the result in the `claude-code-plugins` repo, bump the plugin's version and changelog there, and commit here. The generator looks for the checkout at `~/WORK/claude-code-plugins` (or `$AM_I_PWNED_DIR`, or `--to DIR` for the skill folder); `--check` changes nothing and exits 1 when a copy is behind, 2 when there is no checkout, and 3 when a target file or marker is missing (a skill folder of the old layout, say).

Two things keep the copy from being forgotten:

- `.githooks/pre-commit` runs when a commit touches one of the sources. It writes the copy and stops the commit, so the plugin repo gets its commit first. Turn it on once per clone with `git config core.hooksPath .githooks`.
- `test/plugin-sync.test.ts` fails when the plugin checkout's copy is behind, or when its latest commit there is. It is skipped where no checkout exists (the Pages build).

## Roadmap

XPC connection edges are planned.
