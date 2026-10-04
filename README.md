# dep-vuln-check

[![MCPize](https://mcpize.com/badge/@mcpize/mcpize?type=hosted)](https://mcpize.com)

Check any package version for known vulnerabilities — or scan a full SBOM in one call —
using the [OSV.dev](https://osv.dev) vulnerability database. No API key required.

## Tools

| Tool | Description |
|------|-------------|
| `check_package` | Check a single package version for known vulnerabilities. Inputs: `ecosystem` (npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems, Hex, pub), `name`, `version`. Returns `vulnerable`, plus per-vuln `id`, `summary`, `severity`, `cvss_score`, `fixed_versions`, `published`. Results cached 10 min (`cached: true` when served from cache). |
| `check_sbom` | Scan a software bill of materials (1–50 packages, each with `ecosystem`, `name`, `version`) in one call. Returns `scanned`, `vulnerable_count`, `cached_results`, and per-package results. Unknown packages return empty vulnerability lists (not errors). Results cached 10 min. |

Both tools return structured JSON in `content` and typed `structuredContent`.

## Data source

**OSV.dev** — https://osv.dev — free, no API key, queried live. This server
performs live lookups (plus a 10-minute in-memory cache), so results reflect the
OSV database at query time. Attribution: vulnerability data © the OSV project
and its upstream sources (GitHub Security Advisories, NVD, and ecosystem
advisories). CVSS v3 scores are computed from the vector strings OSV provides.

## Pricing

- **Free:** 100 checks/day (a `check_sbom` call consumes one check per package)
- **Pro:** $12/month, unlimited
- **x402:** $0.02 USDC per call on both tools

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP port |
| `FREE_DAILY_LIMIT` | `100` | Free-tier checks per UTC day |

## LIMITATIONS

- OSV coverage varies by ecosystem: npm/PyPI/Go/Maven/NuGet/crates.io are
  well covered; Hex, pub, and Packagist have thinner coverage. A `vulnerable:
  false` result means "no known vulnerability in OSV for this version", not
  "proven safe".
- Results reflect the OSV database at query time; advisories are added
  continuously. Cached results are up to 10 minutes old (`cached: true`).
- CVSS scores are computed only from CVSS v3.x vectors; records that carry
  only CVSS v4 severity get `cvss_score: null` and `severity: "unknown"`.
- Detail fetching is capped at 25 vulnerability records per package
  (`vulns_truncated: true` when truncated).
- This is a data lookup, not a security audit: it does not analyze your code,
  transitive dependencies, reachability, or exploitability in your environment.
  Treat findings as a triage starting point for a proper security review.

## Development

```bash
npm install
npm run dev     # Start with hot reload
npm test        # Run unit tests
bash test-mcp.sh  # MCP protocol smoke test (server must be running)
```

## Deployment

```bash
mcpize deploy
```

## License

MIT
