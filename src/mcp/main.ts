// Entry point of the Ficus MCP server: the five tools, spoken over stdio to whatever started this process.
// The bundle lives in dist-mcp/, so ../scripts/ is the folder holding the cleaner scripts beside it.
import { fileURLToPath } from 'node:url';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ficusPaths } from './home';
import { createServer } from './server';

const server = createServer({
  paths: ficusPaths(),
  scriptsDir: fileURLToPath(new URL('../scripts/', import.meta.url)),
});

await server.connect(new StdioServerTransport());
