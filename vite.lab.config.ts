import { defineConfig } from 'vite';

// The lab's summarizer as one self-contained ES module for Node, built the way the MCP server is (vite.mcp.config.ts).
// Run it as `node dist-lab/lab-summarize.mjs RUN_DIR [EXPECTED_TSV]`.
export default defineConfig({
  ssr: { noExternal: true },
  build: {
    ssr: 'lab/summarize-cli.ts',
    outDir: 'dist-lab',
    emptyOutDir: true,
    target: 'node20',
    rollupOptions: { output: { entryFileNames: 'lab-summarize.mjs', format: 'es' } },
  },
});
