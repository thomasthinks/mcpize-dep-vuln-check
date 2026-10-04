// Freemium enforcement: Free plan = FREE_DAILY_LIMIT checks per UTC day (default 100).
// Pro/x402 subscribers bypass this in production via MCPize billing; the in-code
// gate only protects the free tier from abuse on the shared deployment.

const DAILY_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT || "100", 10) || 100;

interface DayBucket {
  date: string; // UTC YYYY-MM-DD
  used: number;
}

let bucket: DayBucket = { date: todayUtc(), used: 0 };

function todayUtc(): string {
  return new Date().toISOString().slice(0, 10);
}

function currentBucket(): DayBucket {
  const today = todayUtc();
  if (bucket.date !== today) {
    bucket = { date: today, used: 0 };
  }
  return bucket;
}

export function getDailyLimit(): number {
  return DAILY_LIMIT;
}

export function getDailyUsage(): { used: number; limit: number; remaining: number } {
  const b = currentBucket();
  return { used: b.used, limit: DAILY_LIMIT, remaining: Math.max(DAILY_LIMIT - b.used, 0) };
}

/**
 * Try to consume `n` checks. Returns null when allowed, or the quota-exceeded
 * error payload when the free daily limit would be exceeded.
 */
export function consumeChecks(n: number): { isError: true; message: string } | null {
  const b = currentBucket();
  if (b.used + n > DAILY_LIMIT) {
    return {
      isError: true,
      message: `Free quota exceeded (${DAILY_LIMIT}/day). Subscribe to Pro for unlimited access.`,
    };
  }
  b.used += n;
  return null;
}

export function __resetQuotaForTests(): void {
  bucket = { date: todayUtc(), used: 0 };
}
