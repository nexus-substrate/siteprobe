/**
 * Core probe logic.
 *
 * Resolves DNS, issues an HTTP request, and extracts TLS certificate info
 * for a single endpoint. All probes are bounded by a per-probe timeout and
 * return a structured `ProbeResult` — no exceptions thrown to callers.
 *
 * @module probe
 */

import { lookup } from 'node:dns/promises';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import { request as httpRequest } from 'node:http';
import type { TLSSocket } from 'node:tls';
import type { ProbeOptions, ProbeResult } from './types.js';
import { isBlockedAddress, type SsrfPolicy } from './net.js';

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_TLS_WARN_DAYS = 30;
const DEFAULT_USER_AGENT = 'siteprobe/1.0';
const DEFAULT_MAX_REDIRECTS = 5;

/** Error thrown internally when a target is blocked by the SSRF guard. */
class BlockedTargetError extends Error {
  override readonly name = 'BlockedTargetError';
}

/** Error thrown internally when a redirect chain exceeds the cap. */
class TooManyRedirectsError extends Error {
  override readonly name = 'TooManyRedirectsError';
}

/**
 * Probe a single HTTP(S) endpoint.
 *
 * Returns a `ProbeResult` capturing DNS resolution, HTTP status, TLS
 * certificate details, and timing. Never throws.
 */
export async function probe(target: string, options: ProbeOptions = {}): Promise<ProbeResult> {
  const startedAt = new Date().toISOString();
  const startTime = performance.now();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const policy: SsrfPolicy = {
    ...(options.allowLocal !== undefined ? { allowLocal: options.allowLocal } : {}),
    ...(options.allowPrivate !== undefined ? { allowPrivate: options.allowPrivate } : {}),
  };
  const followRedirects = options.followRedirects ?? true;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  let url = parseTarget(target);
  let firstDns: DnsInfo | undefined;
  let redirects = 0;

  try {
    // Follow redirects iteratively, re-resolving DNS and re-applying the SSRF
    // guard on every hop (defends against redirect-driven SSRF). The probe
    // connects to the validated, pinned IP to defeat DNS rebinding.
    for (;;) {
      const dnsResult = await resolveDns(url.hostname, timeoutMs);
      if (firstDns === undefined) firstDns = dnsResult;

      if (!dnsResult.resolved) {
        return {
          target,
          ok: false,
          dns: firstDns,
          durationMs: Math.round(performance.now() - startTime),
          error: `DNS resolution failed for ${url.hostname}`,
          errorCategory: 'dns_failure',
          startedAt,
        };
      }

      // Validate the RESOLVED addresses, not just the hostname string.
      const pinned = selectPinnedAddress(dnsResult.addresses, policy);
      if (pinned === undefined) {
        throw new BlockedTargetError(
          `Blocked target ${url.hostname} — resolved address(es) [${dnsResult.addresses.join(', ')}] ` +
            `fall in a blocked range (loopback/private/link-local/reserved). ` +
            `Use --allow-local or --allow-private to override.`
        );
      }

      const httpResult = await httpProbe(url, options, timeoutMs, pinned);

      // Follow 3xx with a Location header if enabled and under the cap.
      if (
        followRedirects &&
        httpResult.status >= 300 &&
        httpResult.status < 400 &&
        httpResult.location !== undefined
      ) {
        if (redirects >= maxRedirects) {
          throw new TooManyRedirectsError(
            `Exceeded maximum of ${maxRedirects} redirects starting from ${target}`
          );
        }
        redirects++;
        url = new URL(httpResult.location, url);
        continue;
      }

      const durationMs = Math.round(performance.now() - startTime);
      return {
        target,
        ok: isOkStatus(httpResult.status, options.expectedStatus),
        httpStatus: httpResult.status,
        dns: firstDns,
        ...(httpResult.tls !== undefined ? { tls: httpResult.tls } : {}),
        durationMs,
        startedAt,
      };
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const errorCategory =
      err instanceof BlockedTargetError
        ? ('blocked' as const)
        : err instanceof TooManyRedirectsError
          ? ('too_many_redirects' as const)
          : categorizeError(msg);
    return {
      target,
      ok: false,
      ...(firstDns !== undefined ? { dns: firstDns } : {}),
      durationMs: Math.round(performance.now() - startTime),
      error: msg,
      errorCategory,
      startedAt,
    };
  }
}

/**
 * Pick the first resolved address permitted by the SSRF policy. Returns the
 * address to connect to (pinned, defeating DNS rebinding) or undefined if all
 * resolved addresses are blocked.
 */
function selectPinnedAddress(
  addresses: readonly string[],
  policy: SsrfPolicy
): string | undefined {
  for (const addr of addresses) {
    if (!isBlockedAddress(addr, policy)) return addr;
  }
  return undefined;
}

/** Parse a target string into a URL. Accepts bare hostnames (defaults to https). */
function parseTarget(target: string): URL {
  if (/^https?:\/\//.test(target)) return new URL(target);
  // Bare hostname → prepend https://
  return new URL(`https://${target}`);
}

interface DnsInfo {
  readonly resolved: boolean;
  readonly addresses: readonly string[];
  readonly durationMs: number;
}

/** Sentinel used to distinguish a DNS timeout from a normal resolution failure. */
const DNS_TIMEOUT = Symbol('dns-timeout');

/**
 * Resolve DNS with timing, bounded by a real timeout.
 *
 * `dns.lookup()` does not honor an AbortSignal, so we race it against a timer.
 * A hung resolver therefore still resolves to `{ resolved: false }` within
 * `timeoutMs` rather than hanging the whole probe.
 */
async function resolveDns(hostname: string, timeoutMs: number): Promise<DnsInfo> {
  const start = performance.now();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<typeof DNS_TIMEOUT>((resolve) => {
    timer = setTimeout(() => resolve(DNS_TIMEOUT), timeoutMs);
    // Don't keep the event loop alive solely for this timer.
    timer.unref?.();
  });
  try {
    const outcome = await Promise.race([lookup(hostname, { all: true }), timeout]);
    if (outcome === DNS_TIMEOUT) {
      return { resolved: false, addresses: [], durationMs: Math.round(performance.now() - start) };
    }
    return {
      resolved: true,
      addresses: outcome.map((r) => r.address),
      durationMs: Math.round(performance.now() - start),
    };
  } catch {
    return {
      resolved: false,
      addresses: [],
      durationMs: Math.round(performance.now() - start),
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

interface HttpProbeResult {
  readonly status: number;
  readonly tls?: ProbeResult['tls'];
  /** Redirect `Location` header (resolved by caller against the request URL). */
  readonly location?: string;
}

/**
 * Issue an HTTP(S) request and extract TLS cert if available.
 *
 * `pinnedAddress` is the SSRF-validated resolved IP. The socket connects to
 * that exact address (via a custom `lookup`) so the host cannot rebind to a
 * different (blocked) IP between validation and connect, while the original
 * hostname is preserved for SNI / Host / certificate validation.
 */
function httpProbe(
  url: URL,
  options: ProbeOptions,
  timeoutMs: number,
  pinnedAddress: string
): Promise<HttpProbeResult> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const reqFn = isHttps ? httpsRequest : httpRequest;
    const reqOptions: RequestOptions = {
      method: options.method ?? 'GET',
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      timeout: timeoutMs,
      headers: { 'User-Agent': options.userAgent ?? DEFAULT_USER_AGENT },
      // Pin the connection to the validated address (defeats DNS rebinding).
      lookup: (_hostname, _opts, cb) => {
        const ipVersion = pinnedAddress.includes(':') ? 6 : 4;
        // Signature matches dns.lookup callback: (err, address, family).
        (cb as (err: NodeJS.ErrnoException | null, address: string, family: number) => void)(
          null,
          pinnedAddress,
          ipVersion
        );
      },
    };

    const req = reqFn(reqOptions, (res) => {
      res.resume(); // discard body
      const status = res.statusCode ?? 0;
      const tls = isHttps
        ? extractTlsInfo(res.socket as TLSSocket, options.tlsWarnDays ?? DEFAULT_TLS_WARN_DAYS)
        : undefined;
      const locationHeader = res.headers.location;
      const location = typeof locationHeader === 'string' ? locationHeader : undefined;
      const result: HttpProbeResult = {
        status,
        ...(tls !== undefined ? { tls } : {}),
        ...(location !== undefined ? { location } : {}),
      };
      resolve(result);
    });

    req.on('timeout', () => {
      req.destroy(new Error('Request timeout'));
    });
    req.on('error', (e) => {
      reject(e);
    });
    req.end();
  });
}

/** Extract TLS certificate info from a TLS socket. */
function extractTlsInfo(
  socket: TLSSocket,
  warnDays: number
): NonNullable<ProbeResult['tls']> | undefined {
  try {
    const cert = socket.getPeerCertificate();
    if (cert === undefined || Object.keys(cert).length === 0) return undefined;

    const validTo = new Date(cert.valid_to);
    const now = new Date();
    const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

    const base = {
      valid: socket.authorized && daysUntilExpiry > 0,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      daysUntilExpiry,
    };
    const issuer = typeof cert.issuer?.CN === 'string' ? cert.issuer.CN : undefined;
    const subject = typeof cert.subject?.CN === 'string' ? cert.subject.CN : undefined;
    // Soft warn by not marking valid when expiry is within warnDays
    if (daysUntilExpiry <= warnDays && daysUntilExpiry > 0) {
      return {
        ...base,
        valid: false,
        ...(issuer !== undefined ? { issuer } : {}),
        ...(subject !== undefined ? { subject } : {}),
      };
    }
    return {
      ...base,
      ...(issuer !== undefined ? { issuer } : {}),
      ...(subject !== undefined ? { subject } : {}),
    };
  } catch {
    return undefined;
  }
}

/** Check if HTTP status code matches expected. */
function isOkStatus(
  status: number,
  expected: ProbeOptions['expectedStatus']
): boolean {
  if (expected === undefined) return status >= 200 && status < 400;
  if (typeof expected === 'number') return status === expected;
  return expected.includes(status);
}

/** Categorize an error message into a structured category. */
function categorizeError(msg: string): NonNullable<ProbeResult['errorCategory']> {
  const m = msg.toLowerCase();
  if (m.includes('timeout') || m.includes('timed out')) return 'timeout';
  if (m.includes('enotfound') || m.includes('eai_again')) return 'dns_failure';
  if (m.includes('econnrefused')) return 'connection_refused';
  if (m.includes('cert') && (m.includes('expired') || m.includes('has expired'))) return 'tls_expired';
  if (m.includes('http')) return 'http_error';
  return 'unknown';
}
