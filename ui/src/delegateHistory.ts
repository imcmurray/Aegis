/**
 * Delegate history manifest (D20). Pure helpers: no DOM, no network.
 *
 * `delegates/vault-delegate/history.json` lists previously released vault
 * delegates (newest first). Freenet keys a delegate's secret store by
 * blake3(code_hash || params), so each entry names a store the UI may find the
 * user's vault in after a delegate WASM change.
 */

import { contractInstanceId, instanceIdB58 } from "./vaultSync";

export type DelegateCapability = "session_token" | "export_for_upgrade";

export interface DelegateHistoryEntry {
  version: string;
  code_hash_b58: string;
  capabilities: string[];
}

export interface DelegateTarget {
  keyBytes: number[];
  hashBytes: number[];
  keyB58: string;
  hashB58: string;
}

export function bs58Decode(str: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) map.set(ALPHABET[i]!, i);

  let zeros = 0;
  for (const c of str) {
    if (c === "1") zeros++;
    else break;
  }

  const bytes: number[] = [0];
  for (const c of str) {
    const val = map.get(c);
    if (val === undefined) throw new Error(`invalid base58: ${c}`);
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < zeros; i++) bytes.push(0);
  bytes.reverse();
  return new Uint8Array(bytes);
}

/** blake3(code_hash || empty params): the delegate instance key. */
export function delegateInstanceKey(codeHash: Uint8Array): Uint8Array {
  return contractInstanceId(codeHash, new Uint8Array(0));
}

/** Target for a history entry; null if the hash is not valid base58 / not 32 bytes. */
export function historyEntryTarget(e: DelegateHistoryEntry): DelegateTarget | null {
  let hash: Uint8Array;
  try {
    hash = bs58Decode(e.code_hash_b58);
  } catch {
    return null;
  }
  if (hash.length !== 32) return null;
  const key = delegateInstanceKey(hash);
  return {
    keyBytes: [...key],
    hashBytes: [...hash],
    keyB58: instanceIdB58(key),
    hashB58: e.code_hash_b58,
  };
}

/** Non-array -> []; drops malformed entries; keeps order. */
export function parseDelegateHistory(json: unknown): DelegateHistoryEntry[] {
  if (!Array.isArray(json)) return [];
  const out: DelegateHistoryEntry[] = [];
  for (const item of json) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    if (typeof o.version !== "string" || typeof o.code_hash_b58 !== "string") continue;
    if (o.code_hash_b58 === "") continue;
    if (!Array.isArray(o.capabilities)) continue;
    if (!o.capabilities.every((c) => typeof c === "string")) continue;
    out.push({
      version: o.version,
      code_hash_b58: o.code_hash_b58,
      capabilities: [...(o.capabilities as string[])],
    });
  }
  return out;
}

export function supportsExportForUpgrade(e: DelegateHistoryEntry): boolean {
  return e.capabilities.includes("export_for_upgrade");
}
