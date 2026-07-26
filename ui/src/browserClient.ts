/**
 * Browser vault — real Aegis crypto (Argon2id + XChaCha20) via WASM.
 * No Freenet peer and no local Rust server required.
 * Secrets (except unlocked session) persist in IndexedDB.
 */

import { decodeResponse, encodeRequest } from "./cbor";
import type { VaultRequest, VaultResponse } from "./messages";
import type { VaultClient } from "./freenet";

const IDB_NAME = "aegis-browser-vault";
const IDB_STORE = "secrets";
const IDB_KEY = "v1";

type WasmMod = {
  default: (module_or_path?: unknown) => Promise<unknown>;
  BrowserVault: new () => {
    request(req: Uint8Array): Uint8Array;
    export_store(): Uint8Array;
    import_store(bytes: Uint8Array): void;
    free(): void;
  };
};

let wasmMod: WasmMod | null = null;

async function loadWasm(): Promise<WasmMod> {
  if (wasmMod) return wasmMod;
  // Resolve against the page URL so GitHub Pages subpaths and Freenet web
  // containers both work (`base: "./"` in vite).
  const jsUrl = new URL("browser-wasm/aegis_browser_wasm.js", location.href).href;
  const wasmUrl = new URL(
    "browser-wasm/aegis_browser_wasm_bg.wasm",
    location.href,
  ).href;
  const mod = (await import(/* @vite-ignore */ jsUrl)) as WasmMod;
  await mod.default({ module_or_path: wasmUrl });
  wasmMod = mod;
  return mod;
}

function idbOpen(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("idb open failed"));
  });
}

async function idbGet(): Promise<Uint8Array | null> {
  try {
    const db = await idbOpen();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const store = tx.objectStore(IDB_STORE);
      const g = store.get(IDB_KEY);
      g.onsuccess = () => {
        const v = g.result;
        if (!v) resolve(null);
        else if (v instanceof Uint8Array) resolve(v);
        else if (v instanceof ArrayBuffer) resolve(new Uint8Array(v));
        else resolve(new Uint8Array(v as ArrayLike<number>));
      };
      g.onerror = () => reject(g.error);
    });
  } catch (e) {
    console.warn("[aegis/browser] IndexedDB get failed:", e);
    return null;
  }
}

async function idbSet(bytes: Uint8Array): Promise<void> {
  try {
    const db = await idbOpen();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readwrite");
      tx.objectStore(IDB_STORE).put(bytes, IDB_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    console.warn("[aegis/browser] IndexedDB set failed:", e);
  }
}

export class BrowserVaultClient implements VaultClient {
  readonly label = "browser vault";
  private vault: InstanceType<WasmMod["BrowserVault"]> | null = null;

  static async create(): Promise<BrowserVaultClient> {
    const client = new BrowserVaultClient();
    await client.init();
    return client;
  }

  private async init(): Promise<void> {
    const mod = await loadWasm();
    this.vault = new mod.BrowserVault();
    const snap = await idbGet();
    if (snap && snap.length > 0) {
      this.vault.import_store(snap);
      console.log("[aegis/browser] restored sealed vault from IndexedDB");
    }
  }

  async request(req: VaultRequest): Promise<VaultResponse> {
    if (!this.vault) {
      return {
        type: "error",
        code: "internal",
        message: "browser vault not initialized",
      };
    }
    try {
      const body = encodeRequest(req);
      const out = this.vault.request(body);
      // Persist after every request so create/unlock/upsert survive refresh.
      const snap = this.vault.export_store();
      await idbSet(snap);
      return decodeResponse(out);
    } catch (e) {
      return {
        type: "error",
        code: "internal",
        message: e instanceof Error ? e.message : String(e),
      };
    }
  }
}
