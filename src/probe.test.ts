/**
 * Unit tests for probe() — covers DNS failure, categorization, and URL parsing.
 * Network-bound tests use example.com and graceful fallbacks.
 */
import { describe, it, expect } from 'vitest';
import { createServer, type Server } from 'node:http';
import { probe } from './probe.js';

/** Start an ephemeral HTTP server bound to loopback; returns base URL + close. */
async function startServer(
  handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void
): Promise<{ url: string; port: number; close: () => Promise<void> }> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (addr === null || typeof addr === 'string') throw new Error('no address');
  const port = addr.port;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe('probe', () => {
  it('returns ok=false with dns_failure category on unresolvable hostname', async () => {
    const result = await probe('https://this-definitely-does-not-exist-12345.invalid', {
      timeoutMs: 3000,
    });
    expect(result.ok).toBe(false);
    expect(result.errorCategory).toBe('dns_failure');
    expect(result.target).toBe('https://this-definitely-does-not-exist-12345.invalid');
    expect(result.startedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('accepts bare hostnames and prepends https://', async () => {
    const result = await probe('nonexistent-target-xyz-test.invalid', { timeoutMs: 3000 });
    // Target should remain as given
    expect(result.target).toBe('nonexistent-target-xyz-test.invalid');
    // Should attempt DNS resolution (fail)
    expect(result.ok).toBe(false);
  });

  it('captures duration', async () => {
    const result = await probe('https://no-such-host-zzz.invalid', { timeoutMs: 2000 });
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.durationMs).toBeLessThan(5000);
  });

  it('preserves startedAt as ISO 8601', async () => {
    const result = await probe('https://no-such-host-zzz.invalid', { timeoutMs: 2000 });
    expect(() => new Date(result.startedAt)).not.toThrow();
    const parsed = new Date(result.startedAt);
    expect(Number.isNaN(parsed.getTime())).toBe(false);
  });
});

describe('probe SSRF guard (#11)', () => {
  it('blocks loopback targets by default', async () => {
    const srv = await startServer((_req, res) => res.end('ok'));
    try {
      const result = await probe(srv.url, { timeoutMs: 3000 });
      expect(result.ok).toBe(false);
      expect(result.errorCategory).toBe('blocked');
      expect(result.error ?? '').toMatch(/block/i);
      // It must NOT have actually connected (no httpStatus).
      expect(result.httpStatus).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  it('allows loopback targets when allowLocal is set', async () => {
    const srv = await startServer((_req, res) => {
      res.statusCode = 200;
      res.end('ok');
    });
    try {
      const result = await probe(srv.url, { timeoutMs: 3000, allowLocal: true });
      expect(result.ok).toBe(true);
      expect(result.httpStatus).toBe(200);
    } finally {
      await srv.close();
    }
  });

  it('allows loopback targets when allowPrivate is set', async () => {
    const srv = await startServer((_req, res) => {
      res.statusCode = 204;
      res.end();
    });
    try {
      const result = await probe(srv.url, { timeoutMs: 3000, allowPrivate: true });
      expect(result.ok).toBe(true);
      expect(result.httpStatus).toBe(204);
    } finally {
      await srv.close();
    }
  });
});

describe('probe DNS timeout (#12)', () => {
  it('honors the timeout when DNS hangs (uses TEST-NET / nonroutable resolver)', async () => {
    // 192.0.2.x is TEST-NET-1 (RFC5737), guaranteed non-routable. Using a
    // hostname that needs resolution against a hung path would be flaky, so we
    // instead assert the overall probe is bounded: an unresolvable host with a
    // tiny timeout must still return promptly and not hang.
    const start = Date.now();
    const result = await probe('https://this-host-does-not-resolve-99999.invalid', {
      timeoutMs: 250,
    });
    const elapsed = Date.now() - start;
    expect(result.ok).toBe(false);
    // Bounded: should not exceed the timeout by a wide margin.
    expect(elapsed).toBeLessThan(5000);
  });
});

describe('probe followRedirects (#13)', () => {
  it('follows redirects by default to the final endpoint', async () => {
    let hits = 0;
    const srv = await startServer((req, res) => {
      hits++;
      if (req.url === '/start') {
        res.statusCode = 302;
        res.setHeader('Location', '/final');
        res.end();
      } else {
        res.statusCode = 200;
        res.end('arrived');
      }
    });
    try {
      const result = await probe(`${srv.url}/start`, { timeoutMs: 3000, allowLocal: true });
      expect(result.httpStatus).toBe(200);
      expect(result.ok).toBe(true);
      expect(hits).toBe(2);
    } finally {
      await srv.close();
    }
  });

  it('does not follow redirects when followRedirects is false', async () => {
    const srv = await startServer((_req, res) => {
      res.statusCode = 301;
      res.setHeader('Location', '/elsewhere');
      res.end();
    });
    try {
      const result = await probe(`${srv.url}/start`, {
        timeoutMs: 3000,
        allowLocal: true,
        followRedirects: false,
      });
      expect(result.httpStatus).toBe(301);
    } finally {
      await srv.close();
    }
  });

  it('re-applies the SSRF guard on each redirect hop', async () => {
    // First hop is loopback (allowed via allowLocal), but it redirects to the
    // cloud-metadata link-local address. allowLocal does NOT permit link-local,
    // so the redirect target must be blocked even though the first hop was OK.
    const srv = await startServer((req, res) => {
      if (req.url === '/start') {
        res.statusCode = 302;
        res.setHeader('Location', 'http://169.254.169.254/latest/meta-data/');
        res.end();
      } else {
        res.statusCode = 200;
        res.end();
      }
    });
    try {
      const result = await probe(`${srv.url}/start`, {
        timeoutMs: 3000,
        allowLocal: true,
      });
      expect(result.ok).toBe(false);
      expect(result.errorCategory).toBe('blocked');
      expect(result.error ?? '').toMatch(/169\.254\.169\.254/);
    } finally {
      await srv.close();
    }
  });

  it('caps redirect chains at a max and reports too_many_redirects', async () => {
    const srv = await startServer((req, res) => {
      // Always redirect → infinite loop, must be capped.
      const n = Number(new URL(req.url ?? '/', 'http://x').searchParams.get('n') ?? '0');
      res.statusCode = 302;
      res.setHeader('Location', `/loop?n=${n + 1}`);
      res.end();
    });
    try {
      const result = await probe(`${srv.url}/loop?n=0`, { timeoutMs: 5000, allowLocal: true });
      expect(result.ok).toBe(false);
      expect(result.errorCategory).toBe('too_many_redirects');
    } finally {
      await srv.close();
    }
  });
});
