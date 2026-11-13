// A fixed-window attempt budget per key, held in memory by the process that
// serves the route. It bounds a credentialed caller's rate; it is not a
// security boundary on its own and resets on restart. The clock is injected
// so tests can move it.

export interface FixedWindowLimit {
  max: number;
  windowMs: number;
}

export class FixedWindowBudget {
  private readonly windows = new Map<string, { startedAt: number; used: number }>();

  constructor(
    private readonly limit: FixedWindowLimit,
    private readonly now: () => number = Date.now,
    private readonly maxKeys = 4096,
  ) {}

  /**
   * Spend one attempt for `key`. `n` counts attempts in the window, denied ones
   * included, so a caller can act on the first denial (`n === max + 1`) and not
   * on the flood behind it. `retryAfterSeconds` is 0 when allowed.
   */
  spend(key: string): { n: number; retryAfterSeconds: number } {
    const at = this.now();
    let current = this.windows.get(key);
    if (!current || at - current.startedAt >= this.limit.windowMs) {
      this.sweep(at);
      current = { startedAt: at, used: 0 };
      this.windows.set(key, current);
    }
    current.used += 1;
    if (current.used <= this.limit.max) return { n: current.used, retryAfterSeconds: 0 };
    return { n: current.used, retryAfterSeconds: Math.max(1, Math.ceil((current.startedAt + this.limit.windowMs - at) / 1000)) };
  }

  /** Drop turned-over windows once the table is full; if it is still full, the oldest key goes. */
  private sweep(at: number): void {
    if (this.windows.size < this.maxKeys) return;
    for (const [key, window] of this.windows) {
      if (at - window.startedAt >= this.limit.windowMs) this.windows.delete(key);
    }
    if (this.windows.size >= this.maxKeys) {
      const oldest = this.windows.keys().next().value;
      if (oldest !== undefined) this.windows.delete(oldest);
    }
  }
}
