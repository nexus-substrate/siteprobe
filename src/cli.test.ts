/**
 * Tests for CLI option parsing (#9) and config loading — JSON and YAML (#14).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildOptions, parseIntOption, loadConfigTargets, type ParsedArgs } from './cli.js';

function parsed(values: ParsedArgs['values']): ParsedArgs {
  return {
    values,
    positionals: ['https://example.com'],
  };
}

const dirs: string[] = [];
function tmpFile(name: string, content: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'siteprobe-'));
  dirs.push(dir);
  const p = join(dir, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

afterEach(() => {
  while (dirs.length > 0) {
    const d = dirs.pop();
    if (d !== undefined) rmSync(d, { recursive: true, force: true });
  }
});

describe('parseIntOption', () => {
  it('rejects values below the configured minimum', () => {
    const result = parseIntOption('0', 'timeout', 1);
    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toBe(
      '--timeout must be an integer greater than or equal to 1 (got: 0)'
    );
  });

  it('accepts the configured minimum value', () => {
    expect(parseIntOption('1', 'timeout', 1)).toBe(1);
  });
});

describe('buildOptions', () => {
  it.each([
    ['timeout', { timeout: '0' }],
    ['concurrency', { concurrency: '0' }],
    ['tls-warn-days', { 'tls-warn-days': '0' }],
  ] as const)('rejects --%s below 1', (name, values) => {
    const result = buildOptions(parsed(values));
    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toBe(
      `--${name} must be an integer greater than or equal to 1 (got: 0)`
    );
  });

  it('accepts positive numeric boundaries', () => {
    const result = buildOptions(parsed({
      timeout: '1',
      concurrency: '1',
      'tls-warn-days': '1',
    }));
    expect(result).not.toBeInstanceOf(Error);
    expect(result).toMatchObject({
      timeoutMs: 1,
      concurrency: 1,
      tlsWarnDays: 1,
    });
  });
});

describe('loadConfigTargets', () => {
  it('parses a JSON config with a targets array', () => {
    const p = tmpFile('siteprobe.json', JSON.stringify({ targets: ['https://a.com', 'https://b.com'] }));
    const result = loadConfigTargets(p);
    expect(result).toEqual(['https://a.com', 'https://b.com']);
  });

  it('parses a YAML config (.yaml) with a targets array', () => {
    const p = tmpFile('siteprobe.yaml', 'targets:\n  - https://a.com\n  - https://b.com\n');
    const result = loadConfigTargets(p);
    expect(result).toEqual(['https://a.com', 'https://b.com']);
  });

  it('parses a YAML config (.yml) with a targets array', () => {
    const p = tmpFile('siteprobe.yml', 'targets:\n  - https://x.com\n');
    const result = loadConfigTargets(p);
    expect(result).toEqual(['https://x.com']);
  });

  it('falls back to YAML/JSON content sniffing for non-standard extensions', () => {
    // A .conf file containing YAML should still parse.
    const p = tmpFile('config.conf', 'targets:\n  - https://y.com\n');
    const result = loadConfigTargets(p);
    expect(result).toEqual(['https://y.com']);
  });

  it('returns an Error when targets is missing', () => {
    const p = tmpFile('bad.json', JSON.stringify({ nope: true }));
    const result = loadConfigTargets(p);
    expect(result).toBeInstanceOf(Error);
  });

  it('returns an Error on malformed content', () => {
    const p = tmpFile('bad.yaml', 'targets: [unclosed');
    const result = loadConfigTargets(p);
    expect(result).toBeInstanceOf(Error);
  });
});
