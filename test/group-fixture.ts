import type { CaptureModel, Image, PersistenceItem, Process } from '../src/model/types';
import { capture, img, proc } from './synth';

// A crash loop: one parent that starts the same unsigned helper from Downloads many times. `odd-location-exec` fires
// high for each pass, so every pass is queued, and identical passes group into one row.
export const HELPER = '/Users/u/Downloads/sample/helper';

/** An unsigned program run from Downloads: `odd-location-exec` fires high for it. */
export const helper = (args: string[], seq: number): Image => img({ path: HELPER, signingId: null, args: [HELPER, ...args], seq });
export const parent = (): Process => proc('100:1', [img({ path: '/Users/u/Downloads/sample/main', signingId: null, args: ['main'], seq: 1 })]);
/** `n` children of the parent, each running `args`; ids `200:1`, `201:1`, … */
export const children = (n: number, args: string[] = ['--dialog'], first = 200): Process[] =>
  Array.from({ length: n }, (_, i) => proc(`${first + i}:1`, [helper(args, 10 + i)], { originalParent: '100:1', ppid: 100, originalPpid: 100 }));
export const world = (procs: Process[], persistence: PersistenceItem[] = []): CaptureModel => capture([parent(), ...procs], persistence);
