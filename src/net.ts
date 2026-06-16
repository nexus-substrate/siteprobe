/**
 * Address-class classification for the SSRF guard.
 *
 * siteprobe is a deliberate site-prober, so it does not hard-block private
 * targets. Instead it is secure-by-default: loopback, private (RFC1918 /
 * unique-local), link-local (including the `169.254.169.254` cloud-metadata
 * endpoint), and other reserved ranges are blocked unless the caller opts in
 * via `allowLocal` / `allowPrivate`.
 *
 * Classification is performed on the *resolved* IP address (not the hostname
 * string) so that DNS-rebinding cannot bypass the guard.
 *
 * @module net
 */

import { isIP } from 'node:net';

/** Coarse address class. */
export type AddressClass = 'loopback' | 'private' | 'link-local' | 'reserved' | 'public';

/** Options governing which address classes are permitted. */
export interface SsrfPolicy {
  /** Allow loopback addresses (127.0.0.0/8, ::1). */
  readonly allowLocal?: boolean;
  /** Allow private/link-local/loopback addresses (implies allowLocal). */
  readonly allowPrivate?: boolean;
}

/** Parse a dotted-quad IPv4 string into its four octets, or undefined. */
function ipv4Octets(addr: string): readonly number[] | undefined {
  const parts = addr.split('.');
  if (parts.length !== 4) return undefined;
  const octets = parts.map((p) => Number(p));
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return undefined;
  return octets;
}

/** Classify an IPv4 address string. Assumes a syntactically valid IPv4. */
function classifyIpv4(addr: string): AddressClass {
  const o = ipv4Octets(addr);
  if (o === undefined) return 'reserved';
  const [a, b] = o as [number, number, number, number];

  // 0.0.0.0/8 — "this network" / unspecified
  if (a === 0) return 'reserved';
  // 127.0.0.0/8 — loopback
  if (a === 127) return 'loopback';
  // 10.0.0.0/8 — private
  if (a === 10) return 'private';
  // 172.16.0.0/12 — private
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  // 192.168.0.0/16 — private
  if (a === 192 && b === 168) return 'private';
  // 169.254.0.0/16 — link-local (incl. cloud metadata 169.254.169.254)
  if (a === 169 && b === 254) return 'link-local';
  // 100.64.0.0/10 — carrier-grade NAT (RFC6598), treat as private
  if (a === 100 && b >= 64 && b <= 127) return 'private';
  // 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24 — special-use
  if (a === 192 && b === 0 && (o[2] === 0 || o[2] === 2)) return 'reserved';
  if (a === 198 && (b === 18 || b === 19)) return 'reserved';
  if (a === 198 && b === 51 && o[2] === 100) return 'reserved';
  if (a === 203 && b === 0 && o[2] === 113) return 'reserved';
  // 224.0.0.0/4 — multicast, 240.0.0.0/4 — reserved, 255.255.255.255 — broadcast
  if (a >= 224) return 'reserved';
  return 'public';
}

/** Classify an IPv6 address string. Assumes a syntactically valid IPv6. */
function classifyIpv6(addr: string): AddressClass {
  const lower = addr.toLowerCase();

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible — classify by embedded v4.
  const mapped = lower.match(/^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped?.[1] !== undefined) return classifyIpv4(mapped[1]);

  // Loopback ::1 and unspecified ::
  if (lower === '::1') return 'loopback';
  if (lower === '::') return 'reserved';

  // Link-local fe80::/10
  if (/^fe[89ab]/.test(lower)) return 'link-local';
  // Unique-local fc00::/7
  if (/^f[cd]/.test(lower)) return 'private';
  // Multicast ff00::/8
  if (lower.startsWith('ff')) return 'reserved';

  return 'public';
}

/**
 * Classify an IP address into a coarse address class. Non-IP strings (e.g. an
 * unresolved hostname) are treated as `reserved` so callers fail closed.
 */
export function classifyAddress(addr: string): AddressClass {
  const version = isIP(addr);
  if (version === 4) return classifyIpv4(addr);
  if (version === 6) return classifyIpv6(addr);
  return 'reserved';
}

/**
 * Decide whether a resolved address is blocked under the given policy.
 *
 * By default every non-public class is blocked. `allowLocal` re-enables only
 * loopback; `allowPrivate` re-enables loopback, private, and link-local.
 * `reserved` (0.0.0.0, multicast, broadcast, special-use, unparseable) is
 * never re-enabled.
 */
export function isBlockedAddress(addr: string, policy: SsrfPolicy): boolean {
  const cls = classifyAddress(addr);
  switch (cls) {
    case 'public':
      return false;
    case 'loopback':
      return !(policy.allowLocal === true || policy.allowPrivate === true);
    case 'private':
    case 'link-local':
      return policy.allowPrivate !== true;
    case 'reserved':
    default:
      return true;
  }
}
