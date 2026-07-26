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

import { decodeResponse, encodeRequest } from "./cbor";
import type { VaultRequest, VaultResponse } from "./messages";
import { isEphemeralStorage, storageGet, storageSet } from "./storage";

export type VaultClient = {
  request(req: VaultRequest): Promise<VaultResponse>;
  readonly label: string;
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

type DelegateKeys = {
  /** Instance id bytes (blake3(code_hash || params)) */
  keyBytes: number[];
  /** Code hash bytes (blake3(wasm)) */
  hashBytes: number[];
  hashB58: string;
  keyB58: string;
};

type Pending = {
  resolve: (r: VaultResponse) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

type ApiHandle = {
  api: { sendRequest?: (req: unknown) => void };
  pending: Pending[];
  alive: boolean;
};

export async function tryCreateFreenetClient(): Promise<VaultClient | null> {
  try {
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
                waiter.resolve(decodeResponse(bytes));
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
        handle.api = api as unknown as { sendRequest?: (req: unknown) => void };
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

    const client: VaultClient = {
      label: keys ? "freenet delegate" : "freenet (no keys)",
      request(req: VaultRequest): Promise<VaultResponse> {
        if (!keys) {
          return Promise.resolve({
            type: "error",
            code: "internal",
            message:
              "Freenet connected but delegate keys missing. Run ./scripts/build-wasm.sh and open with &register=1, or set keys (docs/FREENET.md).",
          });
        }
        const k = keys;
        const run = async (): Promise<VaultResponse> => {
          if (!current.alive) {
            console.log("[aegis/freenet] reconnecting…");
            current = await connect();
          }
          const payload = encodeRequest(req);
          return new Promise<VaultResponse>((resolve, reject) => {
            const timer = setTimeout(() => {
              const idx = current.pending.findIndex((p) => p.resolve === resolve);
              if (idx >= 0) current.pending.splice(idx, 1);
              reject(
                new Error(
                  "Delegate request timed out. The vault-delegate may not be registered on this peer.",
                ),
              );
            }, 15_000);
            current.pending.push({ resolve, reject, timer });
            void sendDelegateApplicationMessage(current.api, payload, k).catch(
              (err) => {
                const idx = current.pending.findIndex((p) => p.resolve === resolve);
                if (idx >= 0) {
                  clearTimeout(current.pending[idx]!.timer);
                  current.pending.splice(idx, 1);
                }
                reject(err instanceof Error ? err : new Error(String(err)));
              },
            );
          });
        };
        const p = chain.then(run, run);
        chain = p.then(
          () => undefined,
          () => undefined,
        );
        return p;
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

function bs58Decode(str: string): Uint8Array {
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
