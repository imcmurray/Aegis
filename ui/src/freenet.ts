/**
 * Freenet vault-delegate client.
 *
 * Connects to a local Freenet peer, optionally registers the staged WASM
 * delegate, and sends CBOR VaultRequest / VaultResponse as ApplicationMessages.
 *
 * Keys (in priority order):
 *   1. ?delegateKey=&codeHash=
 *   2. localStorage aegis.delegateKey / aegis.codeHash
 *   3. ui/public/aegis_vault_delegate.hash.json (instance key + code hash)
 *
 * Auto-register only when `?register=1` — large WASM can drop the WS (1006);
 * after register we open a fresh connection.
 */

import { BRIDGE_BLOCKED_DETAIL, freenetBridgeBlocked } from "./freenetBridge";
import { decodeEnvelopeResponse, encodeEnvelopeRequest } from "./cbor";
import type { VaultRequest, VaultResponse } from "./messages";
import { isEphemeralStorage, storageGet, storageSet } from "./storage";
import {
  bs58Decode,
  historyEntryTarget,
  parseDelegateHistory,
  type DelegateHistoryEntry,
  type DelegateTarget,
} from "./delegateHistory";

/** A previously released delegate that holds a vault the user can move (D20). */
export type UpgradeSource = {
  entry: DelegateHistoryEntry;
  target: DelegateTarget;
  identityPreserving: boolean;
};

export type UpgradeResult =
  | { ok: true; identityPreserved: boolean; vault_id: string }
  | { ok: false; message: string };

/** Contract Put/Get/Update surface (Freenet mesh only). */
export type FreenetMeshApi = {
  put: (req: unknown) => Promise<unknown>;
  get: (req: unknown) => Promise<{ state?: number[] | Uint8Array }>;
  update: (req: unknown) => Promise<unknown>;
};

export type VaultClient = {
  request(req: VaultRequest): Promise<VaultResponse>;
  readonly label: string;
  /** Present when connected to a Freenet peer (for VaultSync). */
  readonly freenetApi?: FreenetMeshApi;
  /** Freenet only: find a vault under a previously released delegate. */
  findUpgradeSource?(): Promise<UpgradeSource | null>;
  /** Freenet only: move that vault into the current delegate. */
  upgradeFrom?(source: UpgradeSource, passphrase: string): Promise<UpgradeResult>;
};

export type ClientMode = "browser" | "mock" | "dev" | "freenet";

/**
 * Mode selection:
 *   ?mode=browser  — WASM vault + IndexedDB (default; no Freenet required)
 *   ?mode=freenet  — vault-delegate on local Freenet peer
 *   ?mode=dev      — local Rust HTTP server
 *   ?mode=mock     — UI-only mock (legacy)
 *
 * Auto freenet when served from Freenet web container path / :7509.
 */
export function resolveMode(): ClientMode {
  const params = new URLSearchParams(location.search);
  const m = params.get("mode") ?? params.get("vault");
  if (m === "dev" || m === "freenet" || m === "mock" || m === "browser") {
    return m;
  }
  if (location.port === "7509" || location.pathname.includes("/v1/contract/web/")) {
    return "freenet";
  }
  return "browser";
}

/**
 * Delegate-sealed session tokens (D19), one slot per delegate target keyed by
 * the target's instance key (base58). Tab memory only: never persisted, never
 * logged, never put in an Error message, not exported. A reload starts locked.
 */
const tokenSlots = new Map<string, Uint8Array | null>();

type DelegateKeys = DelegateTarget;

async function loadDelegateHistory(): Promise<DelegateHistoryEntry[]> {
  try {
    const res = await fetch(new URL("aegis_vault_delegate.history.json", location.href));
    if (!res.ok) return [];
    return parseDelegateHistory(await res.json());
  } catch (e) {
    console.warn("[aegis/freenet] delegate history unavailable:", e);
    return [];
  }
}

type Pending = {
  resolve: (r: VaultResponse) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  /** Token slot (target instance key) this request belongs to. */
  slot: string;
};

type FreenetWsApiLike = {
  sendRequest?: (req: unknown) => void;
  put?: (req: unknown) => Promise<unknown>;
  get?: (req: unknown) => Promise<{ state?: number[] | Uint8Array }>;
  update?: (req: unknown) => Promise<unknown>;
};

type ApiHandle = {
  api: FreenetWsApiLike;
  pending: Pending[];
  alive: boolean;
};

export async function tryCreateFreenetClient(): Promise<VaultClient | null> {
  try {
    if (freenetBridgeBlocked()) {
      console.error(`[aegis/freenet] ${BRIDGE_BLOCKED_DETAIL}`);
      return null;
    }
    const stdlib = await import("@freenetorg/freenet-stdlib");
    const { FreenetWsApi } = stdlib;

    const params = new URLSearchParams(location.search);
    // Web container docs: derive WS from location.host (shell injects auth).
    // Vite dev (5173/4173) proxies to the peer on 7509.
    const inWebContainer =
      location.pathname.includes("/v1/contract/web/") ||
      location.port === "7509";
    const defaultHost =
      location.port === "5173" || location.port === "4173"
        ? "127.0.0.1:7509"
        : location.host;
    const wsHost = params.get("ws") ?? defaultHost;
    const protocol =
      location.protocol === "https:" && !/^127\.|localhost/i.test(wsHost)
        ? "wss:"
        : "ws:";
    // IMPORTANT: FreenetWsApi mutates the URL object by appending
    // encodingProtocol=flatbuffers. Always pass a *fresh* URL on each connect.
    const wsUrlString = `${protocol}//${wsHost}/v1/contract/command`;
    if (inWebContainer) {
      console.log(
        "[aegis/freenet] web-container mode",
        isEphemeralStorage() ? "(ephemeral storage)" : "(persistent storage)",
      );
    }

    const connect = (): Promise<ApiHandle> =>
      new Promise((resolve, reject) => {
        const pending: Pending[] = [];
        let opened = false;
        const openTimer = setTimeout(() => {
          if (!opened) {
            reject(new Error(`Freenet peer not reachable at ${wsUrlString}`));
          }
        }, 5000);

        const handle: ApiHandle = {
          api: { sendRequest: undefined },
          pending,
          alive: false,
        };

        const handler = {
          onOpen: () => {
            opened = true;
            handle.alive = true;
            clearTimeout(openTimer);
            console.log("[aegis/freenet] connected", wsUrlString);
            resolve(handle);
          },
          onContractPut: () => {},
          onContractGet: () => {},
          onContractUpdate: () => {},
          onContractUpdateNotification: () => {},
          onContractNotFound: () => {},
          onDelegateResponse: (response: {
            values?: Array<{
              inboundType?: number;
              inbound?: { payload?: number[] } | null;
            }>;
          }) => {
            for (const bytes of extractAppPayloads(response)) {
              const waiter = pending.shift();
              if (!waiter) {
                console.warn("[aegis/freenet] orphan delegate response");
                continue;
              }
              clearTimeout(waiter.timer);
              try {
                const reply = decodeEnvelopeResponse(bytes);
                tokenSlots.set(waiter.slot, reply.token);
                waiter.resolve(reply.resp);
              } catch (e) {
                waiter.reject(e instanceof Error ? e : new Error(String(e)));
              }
            }
          },
          onErr: (e: { cause?: string }) => {
            console.error("[aegis/freenet] host error:", e.cause);
            failPending(pending, new Error(e.cause ?? "freenet host error"));
          },
          onClose: (code: number, reason: string) => {
            console.warn("[aegis/freenet] ws closed", code, reason || "(empty)");
            handle.alive = false;
            failPending(
              pending,
              new Error(
                `Freenet connection closed (${code}${reason ? `: ${reason}` : ""}). Is the peer still running?`,
              ),
            );
            if (!opened) {
              clearTimeout(openTimer);
              reject(
                new Error(
                  `WebSocket closed before open (${code}). Is \`freenet local\` running?`,
                ),
              );
            }
          },
        };

        // Fresh URL every time — stdlib appends encodingProtocol to the object.
        const api = new FreenetWsApi(new URL(wsUrlString), handler as never, "");
        handle.api = api as unknown as FreenetWsApiLike;
      });

    let handle = await connect().catch((e) => {
      console.warn("[aegis/freenet]", e);
      return null;
    });
    if (!handle) return null;

    // Load keys from URL / localStorage / staged hash file — do NOT register yet.
    let keys = await resolveDelegateKeys();

    // Only register when explicitly requested. Large WASM can drop the WS (1006).
    if (params.get("register") === "1") {
      console.log("[aegis/freenet] register=1 — sending RegisterDelegate…");
      try {
        const registered = await tryRegisterDelegate(handle.api);
        if (registered) {
          keys = registered;
          // Peer may drop the socket after a large register; open a fresh one.
          if (!handle.alive) {
            console.log("[aegis/freenet] reconnecting after register…");
            handle = await connect();
          } else {
            // Give the runtime a moment, then reconnect anyway for a clean state.
            await sleep(300);
            try {
              handle = await connect();
            } catch {
              /* keep existing if still alive */
            }
          }
        }
      } catch (e) {
        console.warn("[aegis/freenet] register failed:", e);
        // Reconnect if register killed the socket
        if (!handle.alive) {
          handle = await connect().catch(() => null);
          if (!handle) return null;
        }
      }
    }

    if (!keys) {
      console.warn(
        "[aegis/freenet] no delegate keys. Run ./scripts/build-wasm.sh then either:\n" +
          "  • open ?mode=freenet&register=1  (experimental), or\n" +
          "  • register via fdev and set localStorage aegis.delegateKey / aegis.codeHash\n" +
          "See docs/FREENET.md",
      );
    } else {
      console.log(
        "[aegis/freenet] instanceKey",
        keys.keyB58.slice(0, 16) + "…",
        "codeHash",
        keys.hashB58.slice(0, 16) + "…",
      );
    }

    let chain: Promise<unknown> = Promise.resolve();
    let current = handle;

    const meshApi: FreenetMeshApi = {
      put: (req) => {
        if (!current.api.put) return Promise.reject(new Error("put missing"));
        return current.api.put(req);
      },
      get: (req) => {
        if (!current.api.get) return Promise.reject(new Error("get missing"));
        return current.api.get(req);
      },
      update: (req) => {
        if (!current.api.update) return Promise.reject(new Error("update missing"));
        return current.api.update(req);
      },
    };

    const requestTo = (
      target: DelegateTarget,
      req: VaultRequest,
      opts?: { timeoutMs?: number },
    ): Promise<VaultResponse> => {
      const slot = target.keyB58;
      const timeoutMs = opts?.timeoutMs ?? 15_000;
      const isCurrent = !!keys && target.keyB58 === keys.keyB58;
      const run = async (): Promise<VaultResponse> => {
        try {
          return await runOnce();
        } finally {
          // Lock always drops the local token, whatever the outcome.
          if (req.op === "lock") tokenSlots.delete(slot);
        }
      };
      const runOnce = async (): Promise<VaultResponse> => {
        if (!current.alive) {
          console.log("[aegis/freenet] reconnecting…");
          current = await connect();
        }
        const h = current;
        const payload = encodeEnvelopeRequest(req, tokenSlots.get(slot) ?? null);
        return new Promise<VaultResponse>((resolve, reject) => {
          const timer = setTimeout(() => {
            const idx = h.pending.findIndex((p) => p.resolve === resolve);
            if (idx >= 0) h.pending.splice(idx, 1);
            // A late reply must not reach a later waiter: reopen next time.
            if (!isCurrent) h.alive = false;
            reject(
              new Error(
                "Delegate request timed out. The vault-delegate may not be registered on this peer.",
              ),
            );
          }, timeoutMs);
          h.pending.push({ resolve, reject, timer, slot });
          void sendDelegateApplicationMessage(h.api, payload, target).catch((err) => {
            const idx = h.pending.findIndex((p) => p.resolve === resolve);
            if (idx >= 0) {
              clearTimeout(h.pending[idx]!.timer);
              h.pending.splice(idx, 1);
            }
            reject(err instanceof Error ? err : new Error(String(err)));
          });
        });
      };
      const p = chain.then(run, run);
      chain = p.then(
        () => undefined,
        () => undefined,
      );
      return p;
    };

    const noKeys: VaultResponse = {
      type: "error",
      code: "internal",
      message:
        "Freenet connected but delegate keys missing. Run ./scripts/build-wasm.sh and open with &register=1, or set keys (docs/FREENET.md).",
    };

    let upgradeCache: { value: UpgradeSource | null } | null = null;

    const errText = (r: VaultResponse, fallback: string): string =>
      r.type === "error" && r.message ? r.message : fallback;

    const client: VaultClient = {
      label: keys ? "freenet delegate" : "freenet (no keys)",
      freenetApi: meshApi,
      request(req: VaultRequest): Promise<VaultResponse> {
        if (!keys) return Promise.resolve(noKeys);
        return requestTo(keys, req);
      },
      async findUpgradeSource(): Promise<UpgradeSource | null> {
        if (!keys) return null;
        if (upgradeCache) return upgradeCache.value;
        const history = await loadDelegateHistory();
        let found: UpgradeSource | null = null;
        for (const entry of history) {
          if (entry.code_hash_b58 === keys.hashB58) continue;
          const target = historyEntryTarget(entry);
          if (!target) continue;
          try {
            const r = await requestTo(target, { op: "status" }, { timeoutMs: 5_000 });
            if (r.type === "status" && r.has_vault) {
              found = {
                entry,
                target,
                identityPreserving: entry.capabilities.includes("export_for_upgrade"),
              };
              break;
            }
          } catch {
            /* skipped silently */
          }
        }
        upgradeCache = { value: found };
        return found;
      },
      async upgradeFrom(source: UpgradeSource, passphrase: string): Promise<UpgradeResult> {
        const cur = keys;
        if (!cur) return { ok: false, message: noKeys.type === "error" ? noKeys.message : "" };
        const src = source.target;
        let sourceUnlocked = false;
        try {
          const u = await requestTo(src, { op: "unlock", passphrase });
          if (u.type !== "unlocked") {
            return { ok: false, message: errText(u, "Could not unlock the previous vault.") };
          }
          sourceUnlocked = true;

          let vaultId: string;
          let identityPreserved: boolean;
          if (source.identityPreserving) {
            const ex = await requestTo(src, { op: "export_for_upgrade" });
            if (ex.type !== "upgrade_snapshot") {
              return { ok: false, message: errText(ex, "Could not read the previous vault.") };
            }
            let snapshot: Uint8Array | null =
              ex.snapshot instanceof Uint8Array ? ex.snapshot : new Uint8Array(ex.snapshot);
            const imp = await requestTo(cur, { op: "import_upgrade_snapshot", snapshot });
            snapshot = null;
            if (imp.type !== "ok") {
              return { ok: false, message: errText(imp, "Could not move the vault.") };
            }
            await requestTo(src, { op: "lock" });
            sourceUnlocked = false;
            const un = await requestTo(cur, { op: "unlock", passphrase });
            if (un.type !== "unlocked") {
              return { ok: false, message: errText(un, "Could not unlock the moved vault.") };
            }
            vaultId = un.vault_id;
            identityPreserved = true;
          } else {
            const pwBytes = crypto.getRandomValues(new Uint8Array(32));
            let backupPw: string | null = btoa(String.fromCharCode(...pwBytes));
            pwBytes.fill(0);
            const ex = await requestTo(src, { op: "export_encrypted", passphrase: backupPw });
            if (ex.type !== "export") {
              return { ok: false, message: errText(ex, "Could not read the previous vault.") };
            }
            let blob: Uint8Array | number[] | null = ex.blob;
            await requestTo(src, { op: "lock" });
            sourceUnlocked = false;
            const imp = await requestTo(cur, {
              op: "import_encrypted",
              blob,
              passphrase: backupPw,
              new_passphrase: passphrase,
              replace: false,
            });
            blob = null;
            backupPw = null;
            if (imp.type !== "unlocked") {
              return { ok: false, message: errText(imp, "Could not move the vault.") };
            }
            const un = await requestTo(cur, { op: "unlock", passphrase });
            if (un.type !== "unlocked") {
              return { ok: false, message: errText(un, "Could not unlock the moved vault.") };
            }
            vaultId = un.vault_id;
            identityPreserved = false;
          }
          upgradeCache = null;
          return { ok: true, identityPreserved, vault_id: vaultId };
        } catch (e) {
          return {
            ok: false,
            message: e instanceof Error ? e.message : "Upgrade failed.",
          };
        } finally {
          if (sourceUnlocked) {
            try {
              await requestTo(src, { op: "lock" });
            } catch {
              /* best effort */
            }
          }
          tokenSlots.delete(src.keyB58);
        }
      },
    };

    // Short status probe (non-fatal)
    try {
      const status = await Promise.race([
        client.request({ op: "status" }),
        sleep(6000).then(() => {
          throw new Error("status probe timeout");
        }),
      ]);
      console.log("[aegis/freenet] status", status);
      if (status.type === "error") {
        console.warn("[aegis/freenet] status error:", status.message);
      }
    } catch (e) {
      console.warn(
        "[aegis/freenet] status probe failed (UI still usable if peer recovers):",
        e,
      );
    }

    return client;
  } catch (e) {
    console.warn("[aegis/freenet] setup failed:", e);
    return null;
  }
}

function failPending(pending: Pending[], err: Error) {
  while (pending.length) {
    const w = pending.shift()!;
    clearTimeout(w.timer);
    w.reject(err);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function extractAppPayloads(response: {
  values?: Array<{
    inboundType?: number;
    inbound?: { payload?: number[] } | null;
  }>;
}): Uint8Array[] {
  const out: Uint8Array[] = [];
  if (!response.values) return out;
  for (const outbound of response.values) {
    // Outbound ApplicationMessage is typically type 1
    if (outbound.inboundType !== undefined && outbound.inboundType !== 1) {
      // Still try to extract payload if present
    }
    const msg = outbound.inbound;
    if (!msg?.payload?.length) continue;
    out.push(new Uint8Array(msg.payload));
  }
  return out;
}

async function sendDelegateApplicationMessage(
  api: { sendRequest?: (req: unknown) => void },
  payload: Uint8Array,
  keys: DelegateKeys,
): Promise<void> {
  const common = await import("@freenetorg/freenet-stdlib/common");
  const clientReqModule = await import("@freenetorg/freenet-stdlib/client-request");

  const { ApplicationMessageT } = common as {
    ApplicationMessageT: new (
      payload: number[],
      ctx: number[],
      processed: boolean,
    ) => unknown;
  };
  // Use *T builders only — reader classes have no .pack().
  const {
    ClientRequestT,
    ClientRequestType,
    ApplicationMessagesT,
    DelegateKeyT,
    DelegateRequestT,
    DelegateRequestType,
    InboundDelegateMsgT,
    InboundDelegateMsgType,
  } = clientReqModule as {
    ClientRequestT: new (t: unknown, body: unknown) => unknown;
    ClientRequestType: { DelegateRequest: unknown };
    ApplicationMessagesT: new (
      key: unknown,
      params: number[],
      msgs: unknown[],
    ) => unknown;
    DelegateKeyT: new (key: number[], hash: number[]) => unknown;
    DelegateRequestT: new (t: unknown, body: unknown) => unknown;
    DelegateRequestType: { ApplicationMessages: number };
    InboundDelegateMsgT: new (t: unknown, msg: unknown) => unknown;
    InboundDelegateMsgType: { common_ApplicationMessage: number };
  };

  const appMsg = new ApplicationMessageT(Array.from(payload), [], false);
  const inbound = new InboundDelegateMsgT(
    InboundDelegateMsgType.common_ApplicationMessage,
    appMsg,
  );
  const delegateKey = new DelegateKeyT(
    Array.from(keys.keyBytes),
    Array.from(keys.hashBytes),
  );
  const appMessages = new ApplicationMessagesT(delegateKey, [], [inbound]);
  const delegateReq = new DelegateRequestT(
    DelegateRequestType.ApplicationMessages,
    appMessages,
  );
  const clientReq = new ClientRequestT(
    ClientRequestType.DelegateRequest,
    delegateReq,
  );

  if (typeof api.sendRequest !== "function") {
    throw new Error("FreenetWsApi.sendRequest not available");
  }
  api.sendRequest(clientReq);
}

async function tryRegisterDelegate(
  api: { sendRequest?: (req: unknown) => void },
): Promise<DelegateKeys | null> {
  const wasmUrl = new URL("aegis_vault_delegate.wasm", location.href).href;
  const hashUrl = new URL("aegis_vault_delegate.hash.json", location.href).href;

  const hashRes = await fetch(hashUrl);
  if (!hashRes.ok) {
    console.warn("[aegis/freenet] no hash file — run ./scripts/build-wasm.sh");
    return null;
  }
  const hashJson = (await hashRes.json()) as {
    code_hash_b58: string;
    code_hash_bytes: number[];
    instance_key_b58?: string;
    instance_key_bytes?: number[];
  };

  const wasmRes = await fetch(wasmUrl);
  if (!wasmRes.ok) {
    console.warn("[aegis/freenet] no wasm at", wasmUrl);
    return null;
  }
  const wasm = new Uint8Array(await wasmRes.arrayBuffer());
  const codeHash = hashJson.code_hash_bytes;
  if (codeHash.length !== 32) return null;

  // Instance key = blake3(code_hash || empty params)
  const instanceBytes =
    hashJson.instance_key_bytes && hashJson.instance_key_bytes.length === 32
      ? hashJson.instance_key_bytes
      : codeHash; // fallback (incorrect but better than nothing)

  const keys: DelegateKeys = {
    keyBytes: [...instanceBytes],
    hashBytes: [...codeHash],
    keyB58: hashJson.instance_key_b58 ?? hashJson.code_hash_b58,
    hashB58: hashJson.code_hash_b58,
  };

  const clientReqModule = await import("@freenetorg/freenet-stdlib/client-request");
  const {
    ClientRequestT,
    ClientRequestType,
    DelegateRequestT,
    DelegateRequestType,
    RegisterDelegateT,
    DelegateContainerT,
    DelegateType,
    WasmDelegateV1T,
    DelegateCodeT,
    DelegateKeyT,
  } = clientReqModule as {
    ClientRequestT: new (t: unknown, body: unknown) => unknown;
    ClientRequestType: { DelegateRequest: unknown };
    DelegateRequestT: new (t: unknown, body: unknown) => unknown;
    DelegateRequestType: { RegisterDelegate: number };
    RegisterDelegateT: new (
      container: unknown,
      cipher: number[],
      nonce: number[],
    ) => unknown;
    DelegateContainerT: new (t: unknown, body: unknown) => unknown;
    DelegateType: { WasmDelegateV1: number };
    WasmDelegateV1T: new (
      parameters: number[],
      data: unknown,
      key: unknown,
    ) => unknown;
    DelegateCodeT: new (data: number[], codeHash: number[]) => unknown;
    DelegateKeyT: new (key: number[], hash: number[]) => unknown;
  };

  const code = new DelegateCodeT(Array.from(wasm), Array.from(codeHash));
  const key = new DelegateKeyT(
    Array.from(keys.keyBytes),
    Array.from(keys.hashBytes),
  );
  const wasmDel = new WasmDelegateV1T([], code, key);
  const container = new DelegateContainerT(DelegateType.WasmDelegateV1, wasmDel);
  // freenet-stdlib requires FIXED sizes (panics on wrong length):
  //   cipher: [u8; 32], nonce: [u8; 24]
  // Zeros = no secret-store encryption envelope (local peer plaintext secrets).
  const cipher = new Array(32).fill(0);
  const nonce = new Array(24).fill(0);
  const reg = new RegisterDelegateT(container, cipher, nonce);
  const delReq = new DelegateRequestT(DelegateRequestType.RegisterDelegate, reg);
  const clientReq = new ClientRequestT(ClientRequestType.DelegateRequest, delReq);

  if (typeof api.sendRequest !== "function") {
    throw new Error("sendRequest missing");
  }
  api.sendRequest(clientReq);
  console.log("[aegis/freenet] RegisterDelegate sent (may take a few seconds / reconnect)");

  storageSet("aegis.delegateKey", keys.keyB58);
  storageSet("aegis.codeHash", keys.hashB58);
  return keys;
}

async function resolveDelegateKeys(): Promise<DelegateKeys | null> {
  const params = new URLSearchParams(location.search);
  const keyB58 =
    params.get("delegateKey") ?? storageGet("aegis.delegateKey");
  const hashB58 =
    params.get("codeHash") ?? storageGet("aegis.codeHash");

  if (keyB58 && hashB58) {
    try {
      return {
        keyBytes: Array.from(bs58Decode(keyB58)),
        hashBytes: Array.from(bs58Decode(hashB58)),
        keyB58,
        hashB58,
      };
    } catch (e) {
      console.warn("[aegis/freenet] bad base58 keys", e);
    }
  }

  try {
    const hashUrl = new URL("aegis_vault_delegate.hash.json", location.href).href;
    const res = await fetch(hashUrl);
    if (!res.ok) return null;
    const j = (await res.json()) as {
      code_hash_b58: string;
      code_hash_bytes: number[];
      instance_key_b58?: string;
      instance_key_bytes?: number[];
    };
    if (j.code_hash_bytes.length !== 32) return null;
    const inst =
      j.instance_key_bytes && j.instance_key_bytes.length === 32
        ? j.instance_key_bytes
        : j.code_hash_bytes;
    return {
      keyBytes: [...inst],
      hashBytes: [...j.code_hash_bytes],
      keyB58: j.instance_key_b58 ?? j.code_hash_b58,
      hashB58: j.code_hash_b58,
    };
  } catch {
    return null;
  }
}

