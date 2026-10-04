// OSV.dev API client — keyless, free. Two-step lookup:
//  1. POST /v1/querybatch  -> list of vuln IDs (current OSV returns {id, modified} only)
//  2. GET  /v1/vulns/{id}  -> full record (summary, severity, affected, published)
//
// All network calls have a 10s timeout and results are cached 10 min in memory.

export interface OsvVulnRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  modified?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type: string; events: Array<Record<string, string>> }>;
  }>;
  database_specific?: Record<string, unknown>;
}

const OSV_BASE = "https://api.osv.dev/v1";
const TIMEOUT_MS = 10_000;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_DETAIL_FETCHES_PER_PACKAGE = 25;

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry<unknown>>();

export function __clearCacheForTests(): void {
  cache.clear();
}

function cacheGet<T>(key: string): T | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return entry.value as T;
}

function cacheSet<T>(key: string, value: T): void {
  cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    return res;
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`OSV.dev request timed out after ${TIMEOUT_MS / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export interface PackageQuery {
  ecosystem: string;
  name: string;
  version: string;
}

/** Step 1: batch query -> vuln IDs per package. Returns map key -> vuln IDs. */
export async function queryVulnIds(
  packages: PackageQuery[]
): Promise<Map<string, string[]>> {
  const body = {
    queries: packages.map((p) => ({
      package: { name: p.name, ecosystem: p.ecosystem },
      version: p.version,
    })),
  };
  const res = await fetchWithTimeout(`${OSV_BASE}/querybatch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`OSV.dev querybatch failed: HTTP ${res.status} ${res.statusText}`);
  }
  const data = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
  const out = new Map<string, string[]>();
  (data.results ?? []).forEach((r, i) => {
    const key = `${packages[i].ecosystem}|${packages[i].name}|${packages[i].version}`;
    out.set(
      key,
      (r.vulns ?? []).map((v) => v.id).filter((id) => typeof id === "string")
    );
  });
  return out;
}

/** Step 2: fetch full records for vuln IDs, with bounded concurrency. */
export async function fetchVulnRecords(ids: string[]): Promise<OsvVulnRecord[]> {
  const unique = [...new Set(ids)];
  const limited = unique.slice(0, MAX_DETAIL_FETCHES_PER_PACKAGE);
  const records: OsvVulnRecord[] = [];
  const CONCURRENCY = 8;
  for (let i = 0; i < limited.length; i += CONCURRENCY) {
    const batch = limited.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async (id) => {
        const res = await fetchWithTimeout(`${OSV_BASE}/vulns/${encodeURIComponent(id)}`, {
          method: "GET",
        });
        if (!res.ok) {
          throw new Error(`OSV.dev vuln lookup failed: HTTP ${res.status}`);
        }
        return (await res.json()) as OsvVulnRecord;
      })
    );
    for (const r of results) {
      if (r.status === "fulfilled") records.push(r.value);
      // Individual detail failures are tolerated: the package is still flagged
      // vulnerable from querybatch; we just have fewer details.
    }
  }
  return records;
}

export { cacheGet, cacheSet, MAX_DETAIL_FETCHES_PER_PACKAGE };
