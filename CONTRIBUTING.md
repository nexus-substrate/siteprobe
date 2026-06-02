# Contributing to siteprobe

Thanks for your interest. Bug reports, improvements, and new probe checks are welcome.

## Development

```sh
git clone https://github.com/nexus-substrate/siteprobe
cd siteprobe
npm install
npm run build
npm test
```

## Project layout

```
src/
  types.ts      # Shared types (ProbeResult, ProbeOptions, BatchResult)
  probe.ts      # Single-target probe logic
  batch.ts      # Concurrent batch runner
  render.ts     # Terminal/JSON output
  cli.ts        # CLI entry point
  index.ts      # Library entry point
  *.test.ts     # Tests (vitest)
```

## Guidelines

- **Zero runtime dependencies.** siteprobe is deliberately small. Use Node.js stdlib (`dns`, `https`, `util`) — no new npm deps.
- **Structured results.** All probe outputs use `ProbeResult` with categorized errors. Never throw from probe functions — return `{ ok: false, errorCategory, error }`.
- **Concurrency-safe.** The batch runner uses a bounded worker pool. New probe types must respect per-probe timeouts.
- **Tests first.** Every new code path needs a test. Vitest.
- **`exactOptionalPropertyTypes` is on.** Use conditional spreads (`...(x !== undefined ? { x } : {})`) for optional fields.

## Pull request process

1. Fork and branch from `main`.
2. Write code + tests.
3. Ensure `npm test`, `npm run typecheck`, and `npm run build` all pass.
4. Open a PR with a clear description of what changed and why.

## Reporting bugs

File an issue with:

- What you ran (command and flags)
- What you expected
- What you got (copy the output)
- Node.js version (`node --version`)

## Security

For security vulnerabilities, do not open a public issue. Email williamzujkowski@gmail.com or use [GitHub Security Advisories](https://github.com/nexus-substrate/siteprobe/security/advisories/new).
