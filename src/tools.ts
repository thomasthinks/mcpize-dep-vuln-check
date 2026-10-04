// Pure tool logic for dep-vuln-check (no MCP dependency — easy to unit test).
import {
  cacheGet,
  cacheSet,
  fetchVulnRecords,
  queryVulnIds,
  type OsvVulnRecord,
  type PackageQuery,
} from "./lib/osv.js";
import { bestScore } from "./lib/cvss.js";
import { consumeChecks, getDailyLimit } from "./lib/quota.js";

// ============================================================================
// Ecosystem validation
// ============================================================================

export const SUPPORTED_ECOSYSTEMS = [
  "npm",
  "PyPI",
  "Go",
  "crates.io",
  "Maven",
  "NuGet",
  "Packagist",
  "RubyGems",
  "Hex",
  "pub",
] as const;

export type Ecosystem = (typeof SUPPORTED_ECOSYSTEMS)[number];

/** Validate an ecosystem string (case-insensitive, trimmed). Returns normalized or an error string. */
export function normalizeEcosystem(raw: string): { ok: true; value: Ecosystem } | { ok: false; error: string } {
  const trimmed = (raw ?? "").trim();
  const found = SUPPORTED_ECOSYSTEMS.find(
    (e) => e.toLowerCase() === trimmed.toLowerCase()
  );
  if (!found) {
    return {
      ok: false,
      error: `Unsupported ecosystem "${trimmed}". Supported ecosystems: ${SUPPORTED_ECOSYSTEMS.join(", ")}. Check spelling (e.g. "PyPI" not "pypi2", "crates.io" not "rust") and try again.`,
    };
  }
  return { ok: true, value: found };
}

// ============================================================================
// Parsing
// ============================================================================

export interface VulnSummary {
  [key: string]: unknown;
  id: string;
  summary: string;
  severity: string;
  cvss_score: number | null;
  fixed_versions: string[];
  published: string | null;
}

export function parseVulnRecord(rec: OsvVulnRecord, packageName: string): VulnSummary {
  const { score, severity } = bestScore(rec.severity, rec.database_specific);

  // Collect "fixed" versions from affected ranges. Prefer ranges that name the
  // queried package; fall back to all ranges if none match by name.
  const affected = rec.affected ?? [];
  const nameLower = packageName.toLowerCase();
  const named = affected.filter(
    (a) => (a.package?.name ?? "").toLowerCase() === nameLower
  );
  const sources = named.length > 0 ? named : affected;
  const fixed = new Set<string>();
  for (const a of sources) {
    for (const r of a.ranges ?? []) {
      for (const ev of r.events ?? []) {
        if (typeof ev.fixed === "string" && ev.fixed.length > 0) {
          fixed.add(ev.fixed);
        }
      }
    }
  }

  return {
    id: rec.id ?? "unknown",
    summary: rec.summary || rec.details?.slice(0, 300) || "No summary available",
    severity,
    cvss_score: score,
    fixed_versions: [...fixed].sort(),
    published: rec.published || rec.modified || null,
  };
}

// ============================================================================
// Results
// ============================================================================

export interface PackageResult {
  [key: string]: unknown;
  package: string;
  ecosystem: string;
  version: string;
  vulnerable: boolean;
  cached: boolean;
  vulns: VulnSummary[];
  vulns_truncated: boolean;
}

export interface CheckPackageResult {
  [key: string]: unknown;
  package: string;
  ecosystem: string;
  version: string;
  vulnerable: boolean;
  cached: boolean;
  vulns: VulnSummary[];
}

export interface CheckSbomResult {
  [key: string]: unknown;
  scanned: number;
  vulnerable_count: number;
  cached_results: number;
  results: PackageResult[];
}

export interface ToolError {
  [key: string]: unknown;
  error: string;
  suggestion: string;
}

function cacheKey(p: { ecosystem: string; name: string; version: string }): string {
  return `${p.ecosystem}|${p.name}|${p.version}`;
}

function errorPayload(error: string, suggestion: string) {
  const structuredContent: ToolError = { error, suggestion };
  return {
    content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }],
    isError: true as const,
    structuredContent,
  };
}

export { errorPayload };

async function checkOne(p: PackageQuery): Promise<PackageResult> {
  const key = cacheKey(p);
  const cached = cacheGet<PackageResult>(key);
  if (cached) {
    return { ...cached, cached: true };
  }
  const idsByKey = await queryVulnIds([p]);
  const ids = idsByKey.get(key) ?? [];
  let vulns: VulnSummary[] = [];
  let truncated = false;
  if (ids.length > 0) {
    const records = await fetchVulnRecords(ids);
    vulns = records.map((r) => parseVulnRecord(r, p.name));
    truncated = ids.length > records.length || ids.length > 25;
  }
  const result: PackageResult = {
    package: p.name,
    ecosystem: p.ecosystem,
    version: p.version,
    vulnerable: vulns.length > 0 || ids.length > 0,
    cached: false,
    vulns,
    vulns_truncated: truncated,
  };
  cacheSet(key, result);
  return result;
}

// ============================================================================
// Tool entry points (return MCP-ready {content, structuredContent[, isError]})
// ============================================================================

export async function runCheckPackage(args: {
  ecosystem: string;
  name: string;
  version: string;
}) {
  try {
    const eco = normalizeEcosystem(args.ecosystem);
    if (!eco.ok) {
      return errorPayload(eco.error, "Use one of the supported ecosystem names listed in the error message.");
    }
    const name = (args.name ?? "").trim();
    const version = (args.version ?? "").trim();
    if (!name || !version) {
      return errorPayload(
        "Package name and version are both required and cannot be empty.",
        "Provide the exact package name and version string, e.g. name='lodash', version='4.17.20'."
      );
    }
    const quotaErr = consumeChecks(1);
    if (quotaErr) {
      return errorPayload(quotaErr.message, "Wait until tomorrow (UTC) for the free quota to reset, or subscribe to Pro for unlimited access.");
    }
    const r = await checkOne({ ecosystem: eco.value, name, version });
    const output: CheckPackageResult = {
      package: r.package,
      ecosystem: r.ecosystem,
      version: r.version,
      vulnerable: r.vulnerable,
      cached: r.cached,
      vulns: r.vulns,
    };
    return {
      content: [{ type: "text" as const, text: JSON.stringify(output) }],
      structuredContent: output,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorPayload(
      `Vulnerability check failed: ${msg}`,
      "OSV.dev may be temporarily unavailable — retry in a few seconds. If the problem persists, verify the package name, ecosystem, and version are correct."
    );
  }
}

export async function runCheckSbom(args: {
  packages: Array<{ ecosystem: string; name: string; version: string }>;
}) {
  try {
    const pkgs = args.packages ?? [];
    if (pkgs.length === 0) {
      return errorPayload(
        "No packages provided.",
        "Pass at least one package object with ecosystem, name, and version."
      );
    }
    // Validate + normalize all ecosystems first (fail fast on the first bad one).
    const normalized: PackageQuery[] = [];
    for (let i = 0; i < pkgs.length; i++) {
      const p = pkgs[i];
      const eco = normalizeEcosystem(p.ecosystem ?? "");
      if (!eco.ok) {
        return errorPayload(
          `Package #${i + 1} ("${p.name ?? "?"}"): ${eco.error}`,
          "Fix the ecosystem for the flagged package and retry."
        );
      }
      const name = (p.name ?? "").trim();
      const version = (p.version ?? "").trim();
      if (!name || !version) {
        return errorPayload(
          `Package #${i + 1}: name and version are both required.`,
          "Fill in the missing name/version for the flagged package and retry."
        );
      }
      normalized.push({ ecosystem: eco.value, name, version });
    }
    const quotaErr = consumeChecks(normalized.length);
    if (quotaErr) {
      return errorPayload(
        `${quotaErr.message} This SBOM scan needs ${normalized.length} checks.`,
        "Scan fewer packages, wait until tomorrow (UTC) for the free quota to reset, or subscribe to Pro for unlimited access."
      );
    }

    // Cached packages skip the network; the rest go in ONE batched querybatch
    // call, with detail fetches only for packages that have vuln IDs.
    const results: PackageResult[] = [];
    const toQuery: PackageQuery[] = [];
    for (const p of normalized) {
      const key = cacheKey(p);
      const cached = cacheGet<PackageResult>(key);
      if (cached) {
        results.push({ ...cached, cached: true });
      } else {
        toQuery.push(p);
      }
    }
    const cachedCount = results.length;
    if (toQuery.length > 0) {
      const idsByKey = await queryVulnIds(toQuery);
      for (const p of toQuery) {
        const key = cacheKey(p);
        const ids = idsByKey.get(key) ?? [];
        let vulns: VulnSummary[] = [];
        let truncated = false;
        if (ids.length > 0) {
          const records = await fetchVulnRecords(ids);
          vulns = records.map((r) => parseVulnRecord(r, p.name));
          truncated = ids.length > records.length || ids.length > 25;
        }
        const r: PackageResult = {
          package: p.name,
          ecosystem: p.ecosystem,
          version: p.version,
          vulnerable: vulns.length > 0 || ids.length > 0,
          cached: false,
          vulns,
          vulns_truncated: truncated,
        };
        cacheSet(key, r);
        results.push(r);
      }
    }
    // Preserve input order.
    const order = new Map(normalized.map((p, i) => [cacheKey(p), i]));
    results.sort((a, b) => {
      const ka = `${a.ecosystem}|${a.package}|${a.version}`;
      const kb = `${b.ecosystem}|${b.package}|${b.version}`;
      return (order.get(ka) ?? 0) - (order.get(kb) ?? 0);
    });

    const output: CheckSbomResult = {
      scanned: normalized.length,
      vulnerable_count: results.filter((r) => r.vulnerable).length,
      cached_results: cachedCount,
      results,
    };
    return {
      content: [{ type: "text" as const, text: JSON.stringify(output) }],
      structuredContent: output,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorPayload(
      `SBOM scan failed: ${msg}`,
      "OSV.dev may be temporarily unavailable — retry in a few seconds. For large SBOMs, try splitting into smaller batches."
    );
  }
}

export { getDailyLimit };
