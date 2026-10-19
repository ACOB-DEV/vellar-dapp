interface CacheEntry<Value> {
  value: Value;
  expiresAt: number;
}

export interface OriginPermissionCacheOptions {
  ttlMs: number;
  now?: () => number;
}

export class OriginPermissionCache<Value> {
  private readonly entries = new Map<string, CacheEntry<Value>>();
  private readonly now: () => number;

  constructor({ ttlMs, now = Date.now }: OriginPermissionCacheOptions) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new RangeError("Origin permission cache TTL must be greater than zero");
    }
    this.ttlMs = ttlMs;
    this.now = now;
  }

  private readonly ttlMs: number;

  get(origin: string): Value | undefined {
    const entry = this.entries.get(origin);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(origin);
      return undefined;
    }
    return entry.value;
  }

  set(origin: string, value: Value): void {
    this.entries.set(origin, { value, expiresAt: this.now() + this.ttlMs });
  }

  // Call this when the extension revokes a permission so stale reads cannot survive the TTL.
  invalidate(origin: string): boolean {
    return this.entries.delete(origin);
  }

  delete(origin: string): boolean {
    return this.invalidate(origin);
  }
}
