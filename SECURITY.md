# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✓         |

## Reporting a Vulnerability

If you discover a security vulnerability in siteprobe:

- **GitHub Security Advisory** (preferred): https://github.com/nexus-substrate/siteprobe/security/advisories/new
- **Email**: williamzujkowski@gmail.com

Please do NOT open a public GitHub issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- CWE identifier (if known)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Resolution**: depends on severity (critical = 24-48h, high = 7d, medium = 30d)

## Security considerations

siteprobe is a read-only probe tool. It:

- Issues HTTP(S) GET/HEAD requests to targets you specify
- Resolves DNS
- Inspects TLS certificate metadata

It does NOT:

- Write to any network target
- Authenticate or accept user credentials
- Execute arbitrary input
- Modify local files (except writing output to stdout)

The primary attack surface is the URL parsing and response handling. External
input (CLI args, config files) is parsed and validated before use.

### SSRF guard

Because targets can come from config files that may be influenced by untrusted
input, siteprobe defends against being used as an SSRF primitive:

- After DNS resolution, the **resolved IP address** (not just the hostname
  string) is classified. Loopback (`127.0.0.0/8`, `::1`), private
  (`10/8`, `172.16/12`, `192.168/16`, RFC4193 `fc00::/7`, RFC6598 CGNAT),
  link-local (`169.254.0.0/16` incl. the `169.254.169.254` cloud-metadata
  endpoint, `fe80::/10`), and other reserved ranges are **blocked by default**.
- siteprobe is a deliberate site-prober, so this is **secure-by-default with an
  explicit opt-in** rather than a hard block: `--allow-local` re-enables
  loopback, and `--allow-private` re-enables private/link-local/loopback.
- The connection is **pinned to the validated IP** (via a custom `lookup`), so a
  hostname cannot rebind to a different (blocked) address between validation and
  connect (DNS rebinding).
- Redirects are followed up to a bounded maximum, and the SSRF guard is
  **re-applied to every redirect hop**, so a public target cannot redirect into
  an internal address.

When a target is blocked, the probe returns `ok: false` with
`errorCategory: 'blocked'` and a message explaining the override flags.
