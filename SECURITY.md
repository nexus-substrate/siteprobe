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

The primary attack surface is the URL parsing and response handling. All external input (CLI args, config files) is validated before use.
