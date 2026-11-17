import { defineConfig } from 'vite';

// The MCP server as one self-contained ES module for Node. Built apart from the app so dist/ keeps only index.html.
// Node built-ins stay external; the SDK and zod are bundled in so the file runs with no node_modules beside it.
export default defineConfig({
  ssr: { noExternal: true },
  build: {
    ssr: 'src/mcp/main.ts',
    outDir: 'dist-mcp',
    emptyOutDir: true,
    target: 'node20',
    rollupOptions: { output: { entryFileNames: 'ficus-mcp.mjs', format: 'es' } },
  },
});
