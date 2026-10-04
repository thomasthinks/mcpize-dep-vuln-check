import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  normalizeEcosystem,
  parseVulnRecord,
  runCheckPackage,
  runCheckSbom,
  type OsvVulnRecord,
} from "../src/tools.js";
import { cvssV3BaseScore, qualitativeSeverity, bestScore } from "../src/lib/cvss.js";
import { __clearCacheForTests } from "../src/lib/osv.js";
import { __resetQuotaForTests } from "../src/lib/quota.js";

// ---------------------------------------------------------------------------
// Ecosystem validation
// ---------------------------------------------------------------------------
describe("normalizeEcosystem", () => {
  it("accepts supported ecosystems case-insensitively", () => {
    expect(normalizeEcosystem("npm")).toEqual({ ok: true, value: "npm" });
    expect(normalizeEcosystem("pypi")).toEqual({ ok: true, value: "PyPI" });
    expect(normalizeEcosystem("  Go  ")).toEqual({ ok: true, value: "Go" });
    expect(normalizeEcosystem("crates.io")).toEqual({ ok: true, value: "crates.io" });
  });

  it("rejects unknown ecosystems with a helpful error", () => {
    const r = normalizeEcosystem("pypi2");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain("Unsupported ecosystem");
      expect(r.error).toContain("npm");
      expect(r.error).toContain("PyPI");
    }
  });
});

// ---------------------------------------------------------------------------
// CVSS v3 parsing
// ---------------------------------------------------------------------------
describe("cvssV3BaseScore", () => {
  it("scores a known vector correctly (7.5)", () => {
    // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H -> 7.5
    expect(cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")).toBe(7.5);
  });

  it("scores a scope-changed vector (lodash ReDoS style)", () => {
    const s = cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
    expect(s).toBeGreaterThan(0);
    expect(s).toBeLessThanOrEqual(10);
  });

  it("returns null for garbage", () => {
    expect(cvssV3BaseScore("not-a-vector")).toBeNull();
    expect(cvssV3BaseScore("CVSS:3.1/AV:X/AC:L")).toBeNull();
  });
});

describe("qualitativeSeverity", () => {
  it("maps score bands", () => {
    expect(qualitativeSeverity(null)).toBe("unknown");
    expect(qualitativeSeverity(0)).toBe("none");
    expect(qualitativeSeverity(3.9)).toBe("low");
    expect(qualitativeSeverity(5.0)).toBe("medium");
    expect(qualitativeSeverity(8.9)).toBe("high");
    expect(qualitativeSeverity(9.8)).toBe("critical");
  });
});

describe("bestScore", () => {
  it("prefers numeric database_specific scores", () => {
    const r = bestScore([{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" }], {
      "cvss-score": 9.1,
    });
    expect(r.score).toBe(9.1);
    expect(r.severity).toBe("critical");
  });

  it("parses v3 vectors, ignores v4 vectors", () => {
    const r = bestScore(
      [
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N" },
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
      ],
      undefined
    );
    expect(r.score).toBe(7.5);
    expect(r.severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// Record parsing
// ---------------------------------------------------------------------------
const mockRecord: OsvVulnRecord = {
  id: "GHSA-29mw-wpgm-hmr9",
  summary: "Regular Expression Denial of Service (ReDoS) in lodash",
  published: "2022-01-06T20:30:46Z",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" }],
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] }],
    },
    {
      package: { name: "lodash-es", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] }],
    },
  ],
};

describe("parseVulnRecord", () => {
  it("extracts id, summary, cvss, fixed versions, published", () => {
    const v = parseVulnRecord(mockRecord, "lodash");
    expect(v.id).toBe("GHSA-29mw-wpgm-hmr9");
    expect(v.summary).toContain("ReDoS");
    expect(typeof v.cvss_score).toBe("number");
    expect(v.severity).toMatch(/low|medium|high|critical/);
    expect(v.fixed_versions).toEqual(["4.17.21"]);
    expect(v.published).toBe("2022-01-06T20:30:46Z");
  });

  it("handles missing severity gracefully (severity=unknown, cvss_score=null)", () => {
    const rec: OsvVulnRecord = { id: "GHSA-x", affected: [] };
    const v = parseVulnRecord(rec, "foo");
    expect(v.severity).toBe("unknown");
    expect(v.cvss_score).toBeNull();
    expect(v.summary).toBe("No summary available");
    expect(v.fixed_versions).toEqual([]);
    expect(v.published).toBeNull();
  });

  it("collects fixed versions across multiple ranges", () => {
    const rec: OsvVulnRecord = {
      id: "GHSA-multi",
      affected: [
        {
          package: { name: "foo", ecosystem: "npm" },
          ranges: [
            { type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.3" }] },
            { type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.0.5" }] },
            { type: "ECOSYSTEM", events: [{ introduced: "0" }, { last_affected: "0.9" }] },
          ],
        },
      ],
    };
    const v = parseVulnRecord(rec, "foo");
    expect(v.fixed_versions).toEqual(["1.2.3", "2.0.5"]);
  });

  it("falls back to all ranges when package name does not match any affected entry", () => {
    const v = parseVulnRecord(mockRecord, "some-other-pkg");
    expect(v.fixed_versions).toEqual(["4.17.21"]);
  });
});

// ---------------------------------------------------------------------------
// Tools with mocked OSV (network-free)
// ---------------------------------------------------------------------------

function mockFetchFor(opts: {
  vulnIds: string[];
  records: Record<string, OsvVulnRecord>;
  failDetailIds?: string[];
}) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    if (url.includes("/v1/querybatch")) {
      return {
        ok: true,
        json: () =>
          Promise.resolve({
            results: [
              { vulns: opts.vulnIds.map((id) => ({ id, modified: "2024-01-01T00:00:00Z" })) },
            ],
          }),
      };
    }
    const m = url.match(/\/v1\/vulns\/(.+)$/);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (opts.failDetailIds?.includes(id)) {
        return { ok: false, status: 500, statusText: "Server Error" };
      }
      return { ok: true, json: () => Promise.resolve(opts.records[id] ?? { id }) };
    }
    return { ok: false, status: 404, statusText: "Not Found" };
  });
}

describe("runCheckPackage (mocked OSV)", () => {
  beforeEach(() => {
    __clearCacheForTests();
    __resetQuotaForTests();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns structured vulns for a vulnerable package", async () => {
    vi.stubGlobal("fetch", mockFetchFor({ vulnIds: ["GHSA-29mw-wpgm-hmr9"], records: { "GHSA-29mw-wpgm-hmr9": mockRecord } }));
    const r = await runCheckPackage({ ecosystem: "npm", name: "lodash", version: "4.17.20" });
    expect(r.isError).toBeUndefined();
    const out = r.structuredContent as any;
    expect(out.package).toBe("lodash");
    expect(out.ecosystem).toBe("npm");
    expect(out.version).toBe("4.17.20");
    expect(out.vulnerable).toBe(true);
    expect(out.cached).toBe(false);
    expect(out.vulns).toHaveLength(1);
    expect(out.vulns[0].id).toBe("GHSA-29mw-wpgm-hmr9");
    expect(out.vulns[0].fixed_versions).toContain("4.17.21");
    // content is structured JSON, not a blob
    const text = JSON.parse((r.content[0] as any).text);
    expect(text.package).toBe("lodash");
  });

  it("returns vulnerable:false (not an error) for an unknown package", async () => {
    vi.stubGlobal("fetch", mockFetchFor({ vulnIds: [], records: {} }));
    const r = await runCheckPackage({
      ecosystem: "npm",
      name: "this-package-definitely-does-not-exist-xyz-999",
      version: "1.0.0",
    });
    expect(r.isError).toBeUndefined();
    const out = r.structuredContent as any;
    expect(out.vulnerable).toBe(false);
    expect(out.vulns).toEqual([]);
  });

  it("serves the second identical call from cache (cached:true)", async () => {
    const fetchMock = mockFetchFor({ vulnIds: [], records: {} });
    vi.stubGlobal("fetch", fetchMock);
    const first = await runCheckPackage({ ecosystem: "PyPI", name: "requests", version: "2.31.0" });
    const second = await runCheckPackage({ ecosystem: "PyPI", name: "requests", version: "2.31.0" });
    expect((first.structuredContent as any).cached).toBe(false);
    expect((second.structuredContent as any).cached).toBe(true);
    // querybatch called once only (second call never hit network)
    const batchCalls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("querybatch"));
    expect(batchCalls).toHaveLength(1);
  });

  it("flags vulnerable even when a detail fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetchFor({
        vulnIds: ["GHSA-29mw-wpgm-hmr9"],
        records: {},
        failDetailIds: ["GHSA-29mw-wpgm-hmr9"],
      })
    );
    const r = await runCheckPackage({ ecosystem: "npm", name: "lodash", version: "4.17.20" });
    expect(r.isError).toBeUndefined();
    const out = r.structuredContent as any;
    expect(out.vulnerable).toBe(true);
    expect(out.vulns).toEqual([]);
  });

  it("returns isError for a bad ecosystem", async () => {
    const r = await runCheckPackage({ ecosystem: "pypi2", name: "lodash", version: "4.17.20" });
    expect(r.isError).toBe(true);
    expect((r.structuredContent as any).error).toContain("Unsupported ecosystem");
  });

  it("returns isError for empty name/version", async () => {
    const r = await runCheckPackage({ ecosystem: "npm", name: "", version: "1.0.0" });
    expect(r.isError).toBe(true);
  });

  it("returns isError when OSV is down, without crashing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("boom"); }));
    const r = await runCheckPackage({ ecosystem: "npm", name: "lodash", version: "4.17.20" });
    expect(r.isError).toBe(true);
    expect((r.structuredContent as any).suggestion).toContain("retry");
  });

  it("enforces the free daily quota", async () => {
    vi.resetModules();
    process.env.FREE_DAILY_LIMIT = "1";
    const { runCheckPackage: check } = await import("../src/tools.js");
    vi.stubGlobal("fetch", mockFetchFor({ vulnIds: [], records: {} }));
    const first = await check({ ecosystem: "npm", name: "lodash", version: "4.17.21" });
    expect(first.isError).toBeUndefined();
    const second = await check({ ecosystem: "npm", name: "express", version: "4.19.0" });
    expect(second.isError).toBe(true);
    expect((second.structuredContent as any).error).toContain("Free quota exceeded (1/day)");
    delete process.env.FREE_DAILY_LIMIT;
  });
});

describe("runCheckSbom (mocked OSV)", () => {
  beforeEach(() => {
    __clearCacheForTests();
    __resetQuotaForTests();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("scans mixed packages, preserves order, counts vulnerable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/v1/querybatch")) {
          return {
            ok: true,
            json: () =>
              Promise.resolve({
                results: [
                  { vulns: [{ id: "GHSA-29mw-wpgm-hmr9", modified: "2024-01-01T00:00:00Z" }] },
                  {},
                ],
              }),
          };
        }
        return { ok: true, json: () => Promise.resolve(mockRecord) };
      })
    );
    const r = await runCheckSbom({
      packages: [
        { ecosystem: "npm", name: "lodash", version: "4.17.20" },
        { ecosystem: "npm", name: "safe-pkg", version: "9.9.9" },
      ],
    });
    expect(r.isError).toBeUndefined();
    const out = r.structuredContent as any;
    expect(out.scanned).toBe(2);
    expect(out.vulnerable_count).toBe(1);
    expect(out.results).toHaveLength(2);
    expect(out.results[0].package).toBe("lodash");
    expect(out.results[0].vulnerable).toBe(true);
    expect(out.results[1].package).toBe("safe-pkg");
    expect(out.results[1].vulnerable).toBe(false);
  });

  it("returns isError for empty package list and bad ecosystem", async () => {
    const empty = await runCheckSbom({ packages: [] });
    expect(empty.isError).toBe(true);
    const bad = await runCheckSbom({
      packages: [{ ecosystem: "nope", name: "x", version: "1" }],
    });
    expect(bad.isError).toBe(true);
    expect((bad.structuredContent as any).error).toContain("Package #1");
  });
});

// ---------------------------------------------------------------------------
// Live OSV integration (real network)
// ---------------------------------------------------------------------------
describe("live OSV integration", () => {
  beforeEach(() => {
    __clearCacheForTests();
    __resetQuotaForTests();
  });

  it("lodash@4.17.20 (npm) MUST return CVEs", async () => {
    const r = await runCheckPackage({ ecosystem: "npm", name: "lodash", version: "4.17.20" });
    expect(r.isError).toBeUndefined();
    const out = r.structuredContent as any;
    expect(out.vulnerable).toBe(true);
    expect(out.vulns.length).toBeGreaterThan(0);
    const ids = out.vulns.map((v: any) => v.id).join(" ");
    expect(ids).toContain("GHSA-29mw-wpgm-hmr9");
    for (const v of out.vulns) {
      expect(v.id).toBeTruthy();
      expect(v.summary).toBeTruthy();
      expect(Array.isArray(v.fixed_versions)).toBe(true);
    }
  }, 60_000);

  it("chalk@5.3.0 (npm) is clean (vulnerable:false)", async () => {
    const r = await runCheckPackage({ ecosystem: "npm", name: "chalk", version: "5.3.0" });
    expect(r.isError).toBeUndefined();
    const out = r.structuredContent as any;
    expect(out.vulnerable).toBe(false);
    expect(out.vulns).toEqual([]);
  }, 60_000);
});
