/**
 * VaultSync contract client (Freenet mesh multi-device).
 *
 * Identity = vault owner verifying key (from MasterSecret). Only an unlocked
 * session that holds that key can produce valid signed revisions.
 *
 * Contract instance id = blake3(code_hash || VaultSyncParams_cbor)
 * (matches freenet-stdlib ContractInstanceId::from_params_and_code).
 */

import { blake3 } from "@noble/hashes/blake3";
import { bytesToHex } from "@noble/hashes/utils";

export type FreenetContractApi = {
  put: (req: unknown) => Promise<unknown>;
  get: (req: unknown) => Promise<{ state?: number[] | Uint8Array }>;
  update: (req: unknown) => Promise<unknown>;
};

export type VaultSyncArtifacts = {
  codeHash: Uint8Array;
  wasm: Uint8Array;
  codeHashB58: string;
};

let artifactsCache: VaultSyncArtifacts | null = null;

/** Load staged vault-sync WASM + hash (from release / public/). */
export async function loadVaultSyncArtifacts(): Promise<VaultSyncArtifacts> {
  if (artifactsCache) return artifactsCache;
  const hashUrl = new URL("aegis_vault_sync.hash.json", location.href).href;
  const wasmUrl = new URL("aegis_vault_sync.wasm", location.href).href;

  // Prefer dedicated sync hash file; fall back to hashing WASM if missing.
  let codeHash: Uint8Array;
  let codeHashB58: string;
  try {
    const hj = await (await fetch(hashUrl)).json();
    if (Array.isArray(hj.code_hash_bytes) && hj.code_hash_bytes.length === 32) {
      codeHash = new Uint8Array(hj.code_hash_bytes);
      codeHashB58 = String(hj.code_hash_b58 ?? "");
    } else {
      throw new Error("bad hash json");
    }
  } catch {
    const wasmRes = await fetch(wasmUrl);
    if (!wasmRes.ok) throw new Error(`vault-sync wasm missing (${wasmRes.status})`);
    const wasm = new Uint8Array(await wasmRes.arrayBuffer());
    codeHash = blake3(wasm);
    codeHashB58 = "";
    artifactsCache = { codeHash, wasm, codeHashB58 };
    return artifactsCache;
  }

  const wasmRes = await fetch(wasmUrl);
  if (!wasmRes.ok) throw new Error(`vault-sync wasm missing (${wasmRes.status})`);
  const wasm = new Uint8Array(await wasmRes.arrayBuffer());
  artifactsCache = { codeHash, wasm, codeHashB58 };
  return artifactsCache;
}

/** blake3(code_hash || params) → 32-byte instance id. */
export function contractInstanceId(
  codeHash: Uint8Array,
  paramsCbor: Uint8Array,
): Uint8Array {
  const cat = new Uint8Array(codeHash.length + paramsCbor.length);
  cat.set(codeHash, 0);
  cat.set(paramsCbor, codeHash.length);
  return blake3(cat);
}

export function shortOwnerId(ownerVk: Uint8Array): string {
  if (ownerVk.length < 4) return "(none)";
  return bytesToHex(ownerVk.slice(0, 4));
}

export function instanceIdB58(instance: Uint8Array): string {
  // bitcoin base58
  const ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let zeros = 0;
  for (const b of instance) {
    if (b === 0) zeros++;
    else break;
  }
  const digits = [0];
  for (const b of instance) {
    let carry = b;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]!];
  return out;
}

function toNumArr(u: Uint8Array): number[] {
  return Array.from(u);
}

/**
 * Get remote VaultSync state for this owner, or empty if not on the peer yet.
 */
export async function getRemoteVaultSyncState(
  api: FreenetContractApi,
  paramsCbor: Uint8Array,
): Promise<Uint8Array> {
  const art = await loadVaultSyncArtifacts();
  const instance = contractInstanceId(art.codeHash, paramsCbor);
  const stdlib = await import("@freenetorg/freenet-stdlib");
  const { ContractKey, GetRequest } = stdlib as {
    ContractKey: new (instance: Uint8Array, code?: Uint8Array) => {
      get_contract_key: () => unknown;
      encode: () => string;
    };
    GetRequest: new (
      key: unknown,
      fetchContract?: boolean,
      subscribe?: boolean,
      blockingSubscribe?: boolean,
    ) => unknown;
  };
  const key = new ContractKey(instance, art.codeHash);
  try {
    const resp = await api.get(new GetRequest(key, false, false, false));
    const st = resp.state;
    if (!st || (Array.isArray(st) && st.length === 0)) return new Uint8Array(0);
    return st instanceof Uint8Array ? st : new Uint8Array(st);
  } catch (e) {
    console.log("[aegis/vault-sync] get miss/empty:", e);
    return new Uint8Array(0);
  }
}

/**
 * Put or update VaultSync state for this owner.
 * First publish uses Put (with WASM); later updates use Update(State).
 */
export async function publishVaultSyncState(
  api: FreenetContractApi,
  paramsCbor: Uint8Array,
  stateCbor: Uint8Array,
  opts?: { forcePut?: boolean },
): Promise<{ instanceB58: string; didPut: boolean }> {
  const art = await loadVaultSyncArtifacts();
  const instance = contractInstanceId(art.codeHash, paramsCbor);
  const instanceB58 = instanceIdB58(instance);

  const stdlib = await import("@freenetorg/freenet-stdlib");
  const {
    ContractKey,
    ContractContainer,
    ContractType,
    WasmContractV1,
    PutRequest,
    UpdateRequest,
    UpdateData,
    UpdateDataType,
    StateUpdate,
    GetRequest,
  } = stdlib as {
    ContractKey: new (instance: Uint8Array, code?: Uint8Array) => {
      get_contract_key: () => unknown;
      encode: () => string;
    };
    ContractContainer: new (t: unknown, c: unknown) => unknown;
    ContractType: { WasmContractV1: unknown };
    WasmContractV1: new (
      data: unknown,
      parameters: number[],
      key: unknown,
    ) => unknown;
    PutRequest: new (
      container: unknown,
      state: number[],
      related: null,
      subscribe?: boolean,
      blocking?: boolean,
    ) => unknown;
    UpdateRequest: new (key: unknown, update: unknown) => unknown;
    UpdateData: new (t: unknown, body: unknown) => unknown;
    UpdateDataType: { StateUpdate: unknown };
    StateUpdate: new (state: number[]) => unknown;
    GetRequest: new (
      key: unknown,
      fetchContract?: boolean,
      subscribe?: boolean,
      blockingSubscribe?: boolean,
    ) => unknown;
  };

  // ContractCode shape used by WasmContractV1
  const common = await import("@freenetorg/freenet-stdlib/common");
  const { ContractCodeT } = common as {
    ContractCodeT: new (data: number[], codeHash: number[]) => unknown;
  };

  const key = new ContractKey(instance, art.codeHash);
  const stateArr = toNumArr(stateCbor);
  const paramsArr = toNumArr(paramsCbor);

  let exists = false;
  if (!opts?.forcePut) {
    try {
      await api.get(new GetRequest(key, false, false, false));
      exists = true;
    } catch {
      exists = false;
    }
  }

  if (exists) {
    const update = new UpdateData(
      UpdateDataType.StateUpdate,
      new StateUpdate(stateArr),
    );
    await api.update(new UpdateRequest(key, update));
    console.log("[aegis/vault-sync] updated", instanceB58.slice(0, 12) + "…");
    return { instanceB58, didPut: false };
  }

  const code = new ContractCodeT(toNumArr(art.wasm), toNumArr(art.codeHash));
  const wasmContract = new WasmContractV1(code, paramsArr, key);
  const container = new ContractContainer(
    ContractType.WasmContractV1,
    wasmContract,
  );
  await api.put(new PutRequest(container, stateArr, null, true, false));
  console.log("[aegis/vault-sync] put", instanceB58.slice(0, 12) + "…");
  return { instanceB58, didPut: true };
}

/**
 * Full network sync round-trip for Freenet mode.
 * Caller supplies unlocked-session SyncWithRemote via `syncFn`.
 */
export async function freenetVaultSyncRoundTrip(
  api: FreenetContractApi,
  syncFn: (remoteState: Uint8Array) => Promise<{
    type: string;
    action?: string;
    detail?: string;
    remote_revisions?: number;
    contract_state?: number[] | Uint8Array;
    owner_verifying_key?: number[] | Uint8Array;
    sync_params?: number[] | Uint8Array;
    message?: string;
  }>,
): Promise<string> {
  // Probe with empty remote to get params (requires unlocked vault)
  const probe = await syncFn(new Uint8Array(0));
  if (probe.type === "error") {
    throw new Error(probe.message ?? "sync failed");
  }
  if (probe.type !== "synced") {
    throw new Error(`unexpected sync response: ${probe.type}`);
  }

  const params = toBytes(probe.sync_params);
  const ownerVk = toBytes(probe.owner_verifying_key);
  if (params.length === 0 || ownerVk.length !== 32) {
    // Local-only path produced no identity (shouldn't happen on freenet dispatch)
    return `local ${probe.action}: ${probe.detail} (${probe.remote_revisions ?? 0} rev) — no owner key for mesh`;
  }

  const remote = await getRemoteVaultSyncState(api, params);
  // Re-sync merging real remote (if any)
  const merged =
    remote.length > 0 ? await syncFn(remote) : probe;
  if (merged.type === "error") {
    throw new Error(merged.message ?? "sync merge failed");
  }
  if (merged.type !== "synced") {
    throw new Error(`unexpected merge response: ${merged.type}`);
  }

  const state = toBytes(merged.contract_state);
  const paramsFinal = toBytes(merged.sync_params);
  if (state.length === 0 || paramsFinal.length === 0) {
    return `${merged.action}: ${merged.detail} (${merged.remote_revisions} rev) — nothing to publish`;
  }

  const { instanceB58, didPut } = await publishVaultSyncState(
    api,
    paramsFinal,
    state,
  );
  const ownerShort = shortOwnerId(ownerVk);
  return (
    `${merged.action}: ${merged.detail} (${merged.remote_revisions} rev) · ` +
    `mesh ${didPut ? "put" : "update"} · owner ${ownerShort}… · id ${instanceB58.slice(0, 10)}…`
  );
}

function toBytes(raw: number[] | Uint8Array | undefined | null): Uint8Array {
  if (!raw) return new Uint8Array(0);
  if (raw instanceof Uint8Array) return raw;
  return new Uint8Array(raw);
}
