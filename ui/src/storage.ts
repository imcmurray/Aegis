/**
 * Storage that works inside Freenet web-container sandboxes.
 *
 * The container iframe is often sandboxed without `allow-same-origin`, so
 * `localStorage` / `sessionStorage` throw SecurityError. We fall back to an
 * in-memory map for the page lifetime (keys still come from hash.json / URL).
 */

const memory = new Map<string, string>();

let storageBackend: Storage | "memory" | null = null;
let storageWarned = false;

function probeStorage(): Storage | "memory" {
  if (storageBackend) return storageBackend;
  for (const name of ["localStorage", "sessionStorage"] as const) {
    try {
      const s = globalThis[name];
      if (!s) continue;
      const k = "__aegis_storage_probe__";
      s.setItem(k, "1");
      s.removeItem(k);
      storageBackend = s;
      return s;
    } catch {
      /* sandboxed / disabled */
    }
  }
  storageBackend = "memory";
  if (!storageWarned) {
    storageWarned = true;
    console.warn(
      "[aegis] localStorage unavailable (Freenet sandbox without allow-same-origin). " +
        "Using in-memory storage for this tab — re-register after reload if needed, " +
        "or open via ?mode=freenet on a non-sandboxed host (Vite/serve).",
    );
  }
  return "memory";
}

/** True when only in-memory fallback is available (typical Freenet web container). */
export function isEphemeralStorage(): boolean {
  return probeStorage() === "memory";
}

export function storageGet(key: string): string | null {
  const b = probeStorage();
  if (b === "memory") return memory.get(key) ?? null;
  try {
    return b.getItem(key);
  } catch {
    return memory.get(key) ?? null;
  }
}

export function storageSet(key: string, value: string): void {
  const b = probeStorage();
  if (b === "memory") {
    memory.set(key, value);
    return;
  }
  try {
    b.setItem(key, value);
  } catch {
    memory.set(key, value);
  }
}

export function storageRemove(key: string): void {
  const b = probeStorage();
  if (b === "memory") {
    memory.delete(key);
    return;
  }
  try {
    b.removeItem(key);
  } catch {
    memory.delete(key);
  }
}
