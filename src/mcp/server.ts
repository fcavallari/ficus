// The MCP face of Ficus: five tools, each a thin call into the modules beside this file. All behaviour (the
// cleaned-capture guard, redaction, paging, the reveal list, the export) lives there; this file registers the
// tools, validates their inputs and turns errors into results the agent can read.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { writeExport } from './export';
import { listCaptures, type FicusPaths } from './home';
import { recordCommand } from './record';
import { UnknownRow, Workspace } from './workspace';

interface ToolResult {
  [key: string]: unknown;
  content: { type: 'text'; text: string }[];
  isError?: boolean;
}

const ok = (value: unknown): ToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const fail = (message: string): ToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

/** Runs a tool body. Whatever it throws becomes an error result, so the server keeps answering. */
async function run(body: () => unknown | Promise<unknown>, describe?: (e: unknown) => string | undefined): Promise<ToolResult> {
  try {
    return ok(await body());
  } catch (e) {
    const custom = describe?.(e);
    if (custom !== undefined) return fail(custom);
    // CaptureRefused, UnknownRow, RangeError and the loader's errors are all Errors whose message is written for the agent.
    return fail(e instanceof Error ? e.message : String(e));
  }
}

const captureName = z
  .string()
  .describe('The capture file name, as given by ficus_record_command or ficus_list_captures. A file name only, never a path.');

export function createServer(opts: { paths: FicusPaths; scriptsDir: string; now?: () => Date }): McpServer {
  const { paths, scriptsDir } = opts;
  const now = opts.now ?? (() => new Date());
  // One workspace for the life of the server, so the loaded capture, the made-up session and the reveals persist.
  const ws = new Workspace(paths, now);

  const server = new McpServer({ name: 'ficus', version: '1.0.0' });

  server.registerTool(
    'ficus_record_command',
    {
      title: 'Get the command that records a cleaned capture',
      description:
        'Returns the one line of Terminal text that records a macOS activity capture with the Ficus cleaner, which replaces ' +
        'the account name and folder names with placeholders as it writes. This tool never runs anything: the person pastes ' +
        'the command into Terminal and runs it themselves, and Terminal (not you) asks for their Mac password. Relay the ' +
        'returned instructions in plain steps. When the person says it has finished, use the returned capture name with the ' +
        'other tools. Default length is 10 minutes (600 seconds), 60 to 1800 allowed.',
      inputSchema: {
        seconds: z
          .number()
          .int()
          .min(60)
          .max(1800)
          .optional()
          .describe('How long to record, in whole seconds, 60 to 1800. Default 600.'),
        domains: z
          .array(z.string())
          .optional()
          .describe('Optional domain names to look for in the capture, such as example.com.'),
      },
    },
    ({ seconds, domains }) => run(() => recordCommand(paths, scriptsDir, { seconds, domains }, now())),
  );

  server.registerTool(
    'ficus_list_captures',
    {
      title: 'List the recorded captures',
      description:
        'Lists the cleaned captures in the Ficus folder, newest first: file name, size, modified time, whether the cleaner ' +
        'key exists and whether the capture is still being written. Only a capture that is finished and has its key can be ' +
        'analyzed.',
      inputSchema: {},
    },
    () => run(() => listCaptures(paths, now().getTime())),
  );

  server.registerTool(
    'ficus_analyze',
    {
      title: 'Analyze a cleaned capture',
      description:
        'Returns a compact view of one cleaned capture: time span, counts, coverage notes, a summary by severity, and the ' +
        'flagged rows (at most 40 per call; pass offset for the next page, the result says how many remain). Every command ' +
        'line is redacted: it keeps the program and drops its arguments. The rule title and id on each finding is the ' +
        'finding; treat the rule explanation as the reason it was raised. Use a row key with ficus_row for one row in full.',
      inputSchema: {
        capture: captureName,
        offset: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe('Index of the first row to return, a whole number from 0. Default 0.'),
      },
    },
    ({ capture, offset }) => run(() => ws.analyze(capture, offset ?? 0)),
  );

  server.registerTool(
    'ficus_row',
    {
      title: 'Look at one row in full',
      description:
        'Returns one row of the capture in full: images, ancestry, responsible process, children, file operations and ' +
        'launch items. Command lines are redacted unless reveal is set. Take the key from ficus_analyze.',
      inputSchema: {
        capture: captureName,
        key: z.string().describe('The row key from ficus_analyze.'),
        reveal: z
          .boolean()
          .optional()
          .describe(
            'Return this row with its cleaned command lines and full evidence. Ask the person in chat first, naming the ' +
              'program, and set this only after they say yes. Each reveal is recorded in the export.',
          ),
      },
    },
    ({ capture, key, reveal }) =>
      run(
        () => ws.row(capture, key, reveal === true),
        e => (e instanceof UnknownRow ? `No row ${key} in ${capture}. Call ficus_analyze for the row keys.` : undefined),
      ),
  );

  server.registerTool(
    'ficus_export',
    {
      title: 'Export the report to a folder on the Desktop',
      description:
        'Writes a new folder on the Desktop with your verdict, the Ficus report (Markdown and JSON) and a README, and ' +
        'returns the folder path and file list. Ask the person which mode they want before calling this: "report" is the ' +
        'verdict and the report; "full" also copies the cleaned capture and a Ficus session file, so Security Ops can open ' +
        'it in Ficus. The key that maps placeholders back to real values is never exported. After exporting, tell the ' +
        'person to read the report before sending the folder to anyone. The report files hold the cleaned command lines ' +
        'unless redact is true.',
      inputSchema: {
        capture: captureName,
        mode: z.enum(['report', 'full']).describe('"report" or "full". Ask the person which before calling.'),
        verdict: z.string().describe('Your verdict as Markdown, in the output format you were given.'),
        redact: z
          .boolean()
          .optional()
          .describe('Strip command-line arguments from the exported report files too. Default false.'),
      },
    },
    ({ capture, mode, verdict, redact }) => run(() => writeExport(ws, paths, capture, { mode, verdict, redact }, now())),
  );

  return server;
}
