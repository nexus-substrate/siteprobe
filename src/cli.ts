#!/usr/bin/env node
/**
 * siteprobe CLI.
 *
 * Usage:
 *   siteprobe check https://example.com https://api.example.com
 *   siteprobe check --config siteprobe.yaml
 *   siteprobe check --json https://example.com
 *   siteprobe check --timeout 10000 --concurrency 20 [urls...]
 *
 * @module cli
 */

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { runBatch } from './batch.js';
import { renderBatch, renderJson } from './render.js';

const HELP = `siteprobe — fast, concurrent endpoint health checker

Usage:
  siteprobe check [options] <url|host>...
  siteprobe --version
  siteprobe --help

Options:
  --config <path>       Path to YAML/JSON config file with a 'targets' array.
  --timeout <ms>        Per-probe timeout in milliseconds (default: 5000).
  --concurrency <n>     Maximum concurrent probes (default: 10).
  --tls-warn-days <n>   Warn if TLS cert expires within N days (default: 30).
  --method <GET|HEAD>   HTTP method (default: GET).
  --expect <code>       Expected HTTP status code (default: 200-399).
  --json                Output results as JSON.
  --no-color            Disable ANSI color codes.
  --version, -v         Show version.
  --help, -h            Show this help.

Examples:
  siteprobe check https://example.com
  siteprobe check https://api.example.com:8080/health --expect 204
  siteprobe check --json --timeout 10000 https://a.com https://b.com
  siteprobe check --config ./siteprobe.json

Exit codes:
  0 = all probes succeeded
  1 = one or more probes failed
  2 = usage error
`;

export interface CliOptions {
  readonly targets: readonly string[];
  readonly timeoutMs: number;
  readonly concurrency: number;
  readonly tlsWarnDays: number;
  readonly method: 'GET' | 'HEAD';
  readonly expectedStatus: number | undefined;
  readonly json: boolean;
  readonly noColor: boolean;
}

async function main(argv: readonly string[]): Promise<number> {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }
  if (args.includes('--version') || args.includes('-v')) {
    process.stdout.write('siteprobe 1.0.0\n');
    return 0;
  }

  const command = args[0];
  if (command !== 'check') {
    process.stderr.write(`Unknown command: ${String(command)}\nRun 'siteprobe --help' for usage.\n`);
    return 2;
  }

  let parsed;
  try {
    parsed = parseArgs({
      args: args.slice(1),
      options: {
        config: { type: 'string' },
        timeout: { type: 'string', default: '5000' },
        concurrency: { type: 'string', default: '10' },
        'tls-warn-days': { type: 'string', default: '30' },
        method: { type: 'string', default: 'GET' },
        expect: { type: 'string' },
        json: { type: 'boolean', default: false },
        'no-color': { type: 'boolean', default: false },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`Error: ${msg}\n`);
    return 2;
  }

  const opts = buildOptions(parsed);
  if (opts instanceof Error) {
    process.stderr.write(`Error: ${opts.message}\n`);
    return 2;
  }

  if (opts.targets.length === 0) {
    process.stderr.write("Error: no targets provided. Run 'siteprobe --help' for usage.\n");
    return 2;
  }

  const batch = await runBatch(opts.targets, {
    timeoutMs: opts.timeoutMs,
    concurrency: opts.concurrency,
    tlsWarnDays: opts.tlsWarnDays,
    method: opts.method,
    ...(opts.expectedStatus !== undefined ? { expectedStatus: opts.expectedStatus } : {}),
  });

  if (opts.json) {
    process.stdout.write(renderJson(batch) + '\n');
  } else {
    process.stdout.write(renderBatch(batch, { noColor: opts.noColor }) + '\n');
  }
  return batch.failCount > 0 ? 1 : 0;
}

export interface ParsedArgs {
  values: {
    config?: string;
    timeout?: string;
    concurrency?: string;
    'tls-warn-days'?: string;
    method?: string;
    expect?: string;
    json?: boolean;
    'no-color'?: boolean;
  };
  positionals: string[];
}

export function buildOptions(parsed: ParsedArgs): CliOptions | Error {
  const timeoutMs = parseIntOption(parsed.values.timeout, 'timeout', 1);
  if (timeoutMs instanceof Error) return timeoutMs;
  const concurrency = parseIntOption(parsed.values.concurrency, 'concurrency', 1);
  if (concurrency instanceof Error) return concurrency;
  const tlsWarnDays = parseIntOption(parsed.values['tls-warn-days'], 'tls-warn-days', 1);
  if (tlsWarnDays instanceof Error) return tlsWarnDays;

  const method = parsed.values.method ?? 'GET';
  if (method !== 'GET' && method !== 'HEAD') {
    return new Error(`--method must be GET or HEAD (got: ${method})`);
  }

  const expected = parsed.values.expect;
  let expectedStatus: number | undefined;
  if (expected !== undefined) {
    const n = Number(expected);
    if (!Number.isFinite(n) || n < 100 || n > 599) {
      return new Error(`--expect must be a valid HTTP status code (got: ${expected})`);
    }
    expectedStatus = n;
  }

  const configTargets = parsed.values.config !== undefined ? loadConfigTargets(parsed.values.config) : [];
  if (configTargets instanceof Error) return configTargets;

  return {
    targets: [...configTargets, ...parsed.positionals],
    timeoutMs,
    concurrency,
    tlsWarnDays,
    method,
    expectedStatus,
    json: parsed.values.json ?? false,
    noColor: parsed.values['no-color'] ?? false,
  };
}

export function parseIntOption(
  value: string | undefined,
  name: string,
  min = 0
): number | Error {
  if (value === undefined) return min;
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || !Number.isInteger(n)) {
    return new Error(`--${name} must be an integer greater than or equal to ${min} (got: ${value})`);
  }
  return n;
}

/** Load targets from a JSON config file. Accepts `{ targets: string[] }`. */
function loadConfigTargets(path: string): readonly string[] | Error {
  try {
    const content = readFileSync(path, 'utf-8');
    const parsed: unknown = JSON.parse(content);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('targets' in parsed) ||
      !Array.isArray((parsed as { targets: unknown }).targets)
    ) {
      return new Error(`Config file ${path} must have a 'targets' array`);
    }
    const targets = (parsed as { targets: unknown[] }).targets.filter(
      (t): t is string => typeof t === 'string'
    );
    return targets;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return new Error(`Failed to load config ${path}: ${msg}`);
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv)
    .then((code) => {
      process.exit(code);
    })
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Fatal: ${msg}\n`);
      process.exit(1);
    });
}
