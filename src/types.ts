/**
 * Core types for siteprobe.
 *
 * @module types
 */

/** Result of a single endpoint probe. */
export interface ProbeResult {
  /** The probed URL or host:port. */
  readonly target: string;
  /** Was the probe successful? */
  readonly ok: boolean;
  /** HTTP status code (if HTTP/HTTPS probe). */
  readonly httpStatus?: number;
  /** DNS resolution result. */
  readonly dns?: {
    readonly resolved: boolean;
    readonly addresses: readonly string[];
    readonly durationMs: number;
  };
  /** TLS certificate info (if HTTPS). */
  readonly tls?: {
    readonly valid: boolean;
    readonly issuer?: string;
    readonly subject?: string;
    readonly validFrom?: string;
    readonly validTo?: string;
    readonly daysUntilExpiry?: number;
  };
  /** Total probe duration in ms. */
  readonly durationMs: number;
  /** Error message if probe failed. */
  readonly error?: string;
  /** Error category for classification. */
  readonly errorCategory?:
    | 'timeout'
    | 'dns_failure'
    | 'connection_refused'
    | 'tls_expired'
    | 'http_error'
    | 'blocked'
    | 'too_many_redirects'
    | 'unknown';
  /** Timestamp when probe started (ISO 8601). */
  readonly startedAt: string;
}

/** Options controlling probe behavior. */
export interface ProbeOptions {
  /** Timeout in milliseconds (default: 5000). */
  readonly timeoutMs?: number;
  /** Follow HTTP redirects (default: true). */
  readonly followRedirects?: boolean;
  /** Maximum number of redirect hops to follow (default: 5). */
  readonly maxRedirects?: number;
  /**
   * Allow probing loopback addresses (127.0.0.0/8, ::1). Off by default:
   * siteprobe blocks loopback/private/link-local/reserved targets unless
   * explicitly opted in (SSRF guard).
   */
  readonly allowLocal?: boolean;
  /**
   * Allow probing private, link-local (incl. cloud-metadata 169.254.169.254),
   * and loopback addresses. Off by default. Implies `allowLocal`.
   */
  readonly allowPrivate?: boolean;
  /** Expected HTTP status code for ok=true (default: 200-399). */
  readonly expectedStatus?: number | ReadonlyArray<number>;
  /** Warn if TLS cert expires within this many days (default: 30). */
  readonly tlsWarnDays?: number;
  /** HTTP method (default: GET). */
  readonly method?: 'GET' | 'HEAD';
  /** Custom User-Agent string. */
  readonly userAgent?: string;
}

/** Result of a batch probe run. */
export interface BatchResult {
  /** Individual probe results. */
  readonly results: readonly ProbeResult[];
  /** Total runtime in ms. */
  readonly totalDurationMs: number;
  /** Count of successful probes. */
  readonly okCount: number;
  /** Count of failed probes. */
  readonly failCount: number;
  /** Timestamp of batch start (ISO 8601). */
  readonly startedAt: string;
}
