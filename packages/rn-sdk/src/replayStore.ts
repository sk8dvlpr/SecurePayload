/**
 * Adapter replay store.
 *
 * Catatan v1 CLIENT-ONLY: pemeriksaan replay dilakukan di SERVER. Interface ini
 * disediakan agar aplikasi mobile yang sekalian menjalankan mini-server
 * (mis. local HTTP debug bridge) punya adapter siap pakai dengan kontrak sama
 * seperti SDK lain: `(cacheKey, ttlSeconds) => boolean` — true = belum pernah
 * dilihat (diterima), false = replay (ditolak).
 */

export type ReplayStoreFn = (cacheKey: string, ttlSeconds: number) => boolean;

export interface InMemoryReplayStoreOptions {
  /** Sumber waktu (ms). Default Date.now — inject untuk determinisme di test. */
  now?: () => number;
  /** Batas jumlah entri sebelum purge agresif. Default 10_000. */
  maxEntries?: number;
}

/**
 * Replay store in-memory berbasis Map + expiry.
 * Cocok untuk single-process; TIDAK shared antar device/proses (jujur soal batas ini).
 */
export function createInMemoryReplayStore(options: InMemoryReplayStoreOptions = {}): ReplayStoreFn {
  const now = options.now ?? (() => Date.now());
  const maxEntries = options.maxEntries ?? 10_000;
  const seen = new Map<string, number>();

  return (cacheKey: string, ttlSeconds: number): boolean => {
    const ts = now();
    // Purge entri kadaluarsa agar Map tidak tumbuh tanpa batas.
    for (const [key, expiresAt] of seen) {
      if (expiresAt <= ts) seen.delete(key);
    }
    if (seen.has(cacheKey)) return false;

    seen.set(cacheKey, ts + Math.max(0, ttlSeconds) * 1000);
    if (seen.size > maxEntries) {
      // Fallback terburuk: buang entri tertua (Map mempertahankan urutan insert).
      const oldest = seen.keys().next();
      if (!oldest.done) seen.delete(oldest.value);
    }
    return true;
  };
}
