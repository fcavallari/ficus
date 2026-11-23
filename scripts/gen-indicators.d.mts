// Types for gen-indicators.mjs, so test/plugin-sync.test.ts type-checks. Keep it in step with the exports there.
export const DEFAULT_TARGET: string;
export const BEGIN: string;
export const END: string;
export function targetDir(argv?: string[]): string;
export function stampOf(text: string): string;
export function renderPage(data: unknown, stamp: string): string;
export function scriptEntries(data: unknown): { ids: string[]; paths: string[]; anywhere: string[] };
export function renderBlock(data: unknown, stamp: string): string;
export function replaceBlock(script: string, block: string): string;
export function toolingDirs(source: string): string[];
export function replaceTooling(script: string, dirs: string[]): string;
export const INDICATORS_FILE: string;
export const SIGNATURES_FILE: string;
export const PAGE_FILE: string;
export class TargetError extends Error {}
export function build(target: string): Record<string, { path: string; next: string; now: string }>;
