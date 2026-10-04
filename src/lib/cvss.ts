// Minimal, spec-faithful CVSS v3.x base-score calculator (FIRST CVSS v3.1 spec).
// OSV severity entries carry a *vector string* (e.g. "CVSS:3.1/AV:N/AC:L/..."),
// not a number, so we compute the numeric base score ourselves.
//
// CVSS v4 vectors are NOT scored numerically here (the v4.0 macro-vector/lookup
// algorithm is too long to embed safely); those records get cvss_score: null
// and severity "unknown". CVSS v3.x covers the vast majority of OSV records.

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PRU: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }; // scope unchanged
const PRC: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }; // scope changed
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

/** Round up to 1 decimal place per the CVSS v3.1 spec. */
function roundUp(x: number): number {
  return Math.ceil((x - 1e-9) * 10) / 10;
}

/** Compute CVSS v3.0/v3.1 base score from a vector string. Returns null if unparseable. */
export function cvssV3BaseScore(vector: string): number | null {
  try {
    const parts = vector.trim().split("/");
    if (parts.length < 2 || !/^CVSS:3\.[01]$/.test(parts[0])) return null;
    const m: Record<string, string> = {};
    for (const p of parts.slice(1)) {
      const [k, v] = p.split(":");
      if (k && v) m[k] = v;
    }
    const av = AV[m.AV], ac = AC[m.AC], ui = UI[m.UI];
    const c = CIA[m.C], i = CIA[m.I], a = CIA[m.A];
    const scopeChanged = m.S === "C";
    const pr = (scopeChanged ? PRC : PRU)[m.PR];
    if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined)) return null;

    const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
    let impact: number;
    if (!scopeChanged) {
      impact = 6.42 * iss;
    } else {
      impact =
        7.52 * (iss - 0.029) - 3.25 * Math.pow(Math.max(iss - 0.02, 0), 15);
    }
    const exploitability = 8.22 * av! * ac! * pr! * ui!;
    if (impact <= 0) return 0.0;
    const score = scopeChanged
      ? roundUp(Math.min(1.08 * (impact + exploitability), 10))
      : roundUp(Math.min(impact + exploitability, 10));
    return Math.min(Math.max(score, 0), 10);
  } catch {
    return null;
  }
}

/** Qualitative label per CVSS v3.1 spec rating scale. */
export function qualitativeSeverity(score: number | null): string {
  if (score === null || Number.isNaN(score)) return "unknown";
  if (score === 0) return "none";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

/**
 * Pick the best (highest) score from an OSV severity array.
 * Prefers a numeric database_specific score, then CVSS_V3/V3.1 vectors.
 * Returns {score, severity}.
 */
export function bestScore(
  severity: Array<{ type: string; score: string }> | undefined,
  databaseSpecific: Record<string, unknown> | undefined
): { score: number | null; severity: string } {
  // 1. Numeric score stashed by some sources in database_specific.
  if (databaseSpecific) {
    for (const key of ["cvss-score", "cvss_score", "severity_score"]) {
      const v = databaseSpecific[key];
      if (typeof v === "number" && v >= 0 && v <= 10) {
        return { score: v, severity: qualitativeSeverity(v) };
      }
    }
  }
  // 2. Parse CVSS v3 vectors, keep the highest.
  let best: number | null = null;
  for (const s of severity ?? []) {
    if (/^CVSS_V3/i.test(s.type) && typeof s.score === "string") {
      const n = cvssV3BaseScore(s.score);
      if (n !== null && (best === null || n > best)) best = n;
    }
  }
  return { score: best, severity: qualitativeSeverity(best) };
}
