/**
 * Tests for CLI option parsing.
 */
import { describe, expect, it } from 'vitest';
import { buildOptions, parseIntOption, type ParsedArgs } from './cli.js';

function parsed(values: ParsedArgs['values']): ParsedArgs {
  return {
    values,
    positionals: ['https://example.com'],
  };
}

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
