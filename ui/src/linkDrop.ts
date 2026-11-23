/**
 * Link-drop contract client (D21, Freenet only).
 *
 * A one-time mailbox located by a link code: the contract parameters are
 * derived from the code by the delegate (`link_locate`), so both devices
 * compute the same instance id = blake3(code_hash || params).
 *
 * Nothing here logs, stores or throws the link code, the contract params or
 * any state bytes.
 */

import { blake3 } from "@noble/hashes/blake3";
import {
  bytesEqual,
  contractInstanceId,
  instanceIdB58,
  type FreenetContractApi,
} from "./vaultSync";

export type LinkDropArtifacts = {
  codeHash: Uint8Array;
  wasm: Uint8Array;
  codeHashB58: string;
};

let artifactsCache: LinkDropArtifacts | null = null;

/** Load the staged link-drop WASM + hash (`aegis_link_drop.hash.json` / `.wasm`). */
export async function loadLinkDropArtifacts(): Promise<LinkDropArtifacts> {
  if (artifactsCache) return artifactsCache;
  const hashUrl = new URL("aegis_link_drop.hash.json", location.href).href;
  const wasmUrl = new URL("aegis_link_drop.wasm", location.href).href;

  let hashed: { codeHash: Uint8Array; codeHashB58: string } | null = null;
  try {
    const hj = await (await fetch(hashUrl)).json();
    if (Array.isArray(hj.code_hash_bytes) && hj.code_hash_bytes.length === 32) {
      hashed = {
        codeHash: new Uint8Array(hj.code_hash_bytes),
        codeHashB58: String(hj.code_hash_b58 ?? ""),
      };
    }
  } catch {
    hashed = null;
  }

  const wasmRes = await fetch(wasmUrl);
  if (!wasmRes.ok) throw new Error(`link-drop wasm missing (${wasmRes.status})`);
  const wasm = new Uint8Array(await wasmRes.arrayBuffer());
  artifactsCache = hashed
    ? { codeHash: hashed.codeHash, wasm, codeHashB58: hashed.codeHashB58 }
    : { codeHash: blake3(wasm), wasm, codeHashB58: "" };
  return artifactsCache;
}

type GetRequestCtor = new (
  key: unknown,
  fetchContract?: boolean,
  subscribe?: boolean,
  blockingSubscribe?: boolean,
) => unknown;

type ContractKeyCtor = new (instance: Uint8Array, code?: Uint8Array) => unknown;

/**
 * Read the link-drop state for `paramsCbor`. A miss (contract not on the node
 * or network yet) is `{ state: empty, found: false }`; an existing contract with
 * no state is `found: true`.
 */
export async function getLinkDropState(
  api: FreenetContractApi,
  paramsCbor: Uint8Array,
): Promise<{ state: Uint8Array; found: boolean }> {
  const art = await loadLinkDropArtifacts();
  const instance = contractInstanceId(art.codeHash, paramsCbor);
  const stdlib = await import("@freenetorg/freenet-stdlib");
  const { ContractKey, GetRequest } = stdlib as unknown as {
    ContractKey: ContractKeyCtor;
    GetRequest: GetRequestCtor;
  };
  const key = new ContractKey(instance, art.codeHash);
  try {
    const resp = await api.get(new GetRequest(key, false, false, false));
    const st = resp.state;
    if (!st || (Array.isArray(st) && st.length === 0)) {
      return { state: new Uint8Array(0), found: true };
    }
    return { state: st instanceof Uint8Array ? st : new Uint8Array(st), found: true };
  } catch {
    return { state: new Uint8Array(0), found: false };
  }
}

/**
 * Publish a link-drop state. `exists=false` Puts the contract (with WASM);
 * `exists=true` sends Update(State). The node answers only after network
 * routing and freenet-stdlib gives up after 30 s with "Request timeout": on that
 * timeout read the contract back and accept it if the node holds exactly
 * `stateCbor` (`pending: true`, as in vault-sync).
 */
export async function publishLinkDropState(
  api: FreenetContractApi,
  paramsCbor: Uint8Array,
  stateCbor: Uint8Array,
  opts: { exists: boolean },
): Promise<{ pending: boolean }> {
  const art = await loadLinkDropArtifacts();
  const instance = contractInstanceId(art.codeHash, paramsCbor);
  // Computed for parity with vault-sync; never logged.
  void instanceIdB58(instance);

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
  } = stdlib as unknown as {
    ContractKey: ContractKeyCtor;
    ContractContainer: new (t: unknown, c: unknown) => unknown;
    ContractType: { WasmContractV1: unknown };
    WasmContractV1: new (data: unknown, parameters: number[], key: unknown) => unknown;
    PutRequest: new (
      container: unknown,
      state: number[],
      related: unknown,
      subscribe?: boolean,
      blocking?: boolean,
    ) => unknown;
    UpdateRequest: new (key: unknown, update: unknown) => unknown;
    UpdateData: new (t: unknown, body: unknown) => unknown;
    UpdateDataType: { StateUpdate: unknown };
    StateUpdate: new (state: number[]) => unknown;
    GetRequest: GetRequestCtor;
  };

  const key = new ContractKey(instance, art.codeHash);
  const stateArr = Array.from(stateCbor);

  const confirmLocal = async (e: unknown): Promise<void> => {
    if (!(e instanceof Error) || e.message !== "Request timeout") throw e;
    let held: Uint8Array;
    try {
      const resp = await api.get(new GetRequest(key, false, false, false));
      const st = resp.state ?? [];
      held = st instanceof Uint8Array ? st : new Uint8Array(st);
    } catch {
      throw e;
    }
    if (!bytesEqual(held, stateCbor)) throw e;
  };

  let pending = false;
  if (opts.exists) {
    const update = new UpdateData(UpdateDataType.StateUpdate, new StateUpdate(stateArr));
    await api.update(new UpdateRequest(key, update)).catch(async (e: unknown) => {
      await confirmLocal(e);
      pending = true;
    });
    return { pending };
  }

  const common = await import("@freenetorg/freenet-stdlib/common");
  const { ContractCodeT } = common as unknown as {
    ContractCodeT: new (data: number[], codeHash: number[]) => unknown;
  };
  const clientRequest = await import("@freenetorg/freenet-stdlib/client-request");
  const { RelatedContractsT } = clientRequest as unknown as {
    RelatedContractsT: new (contracts?: unknown[]) => unknown;
  };
  const code = new ContractCodeT(Array.from(art.wasm), Array.from(art.codeHash));
  const wasmContract = new WasmContractV1(code, Array.from(paramsCbor), key);
  const container = new ContractContainer(ContractType.WasmContractV1, wasmContract);
  await api
    .put(new PutRequest(container, stateArr, new RelatedContractsT([]), true, false))
    .catch(async (e: unknown) => {
      await confirmLocal(e);
      pending = true;
    });
  return { pending };
}
