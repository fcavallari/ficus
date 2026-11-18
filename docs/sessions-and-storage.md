# Running Ficus, sessions and storage

Verdicts are kept per session (one investigation, usually one Mac) in the browser's IndexedDB, so they survive closing the tab.

The quickest way is the hosted copy: **https://fcavallari.github.io/ficus/**. It is the same single file, rebuilt from `main` on every push. The Content-Security-Policy travels inside the page, so it still cannot send a capture anywhere; GitHub only serves the file. Sessions saved there stay in that browser, under the `fcavallari.github.io` origin, which every GitHub Pages project of this account shares.

To run it yourself, build once, then serve the result on localhost:

```bash
npm ci
npm run build        # writes dist/index.html, a single self-contained file
npm run serve        # vite preview, http://localhost:4173
```

This is the way that has been tested: the [measurements](performance.md) were taken over HTTP, with sessions persisting in IndexedDB.

You can also open `dist/index.html` straight from Finder (double-click, or Open With a browser). That should work, since the page needs no server, but it has not been verified in every browser. If your browser does not keep sessions when the page is opened from disk (they are gone after you quit and reopen it), use `npm run serve`. Browsers may also give every `file://` page one shared storage origin.

Sessions are stored per origin, so a session made at `file://` is not visible at `http://localhost:4173` or on the hosted copy, and the other way round. Use one and stick to it. Parsed captures are not stored; after reopening a session, re-drop the capture file and your verdicts reattach to it. In Chrome, Edge and other Chromium browsers the session remembers where each capture came from instead, so *Reload all captures* (or *Reload* beside one capture) reads them again. A web page never sees a file's path: what is remembered is the browser's handle to the file, kept in this browser's IndexedDB and not in saved session files. After a browser restart, Chrome asks again for access to each file; a file that was moved or deleted is named, and has to be added again. Safari and Firefox give no handles, so there captures are re-added by hand.

A capture is identified by its first 200 complete lines (plus the first event's sequence number and time), so a capture that is still growing keeps its verdicts when you drop it again later. A capture shorter than 200 complete lines can change identity as it grows: until it has 200 lines, a longer version of the file counts as a new capture. A pretty-printed export (see [Mac Monitor traces](mac-monitor.md)) is identified by its first 200 records instead, since each record spans many lines.

Loaded captures stay in memory up to 300 MB of input file size per page; the least recently used one is dropped first (never the one on screen) and shows “Re-add <file> to continue”. Its verdicts are kept.
