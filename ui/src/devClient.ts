/**
 * Client for the local `aegis-dev-vault-server` (real Rust crypto over HTTP CBOR).
 */

import { decodeResponse, encodeRequest } from "./cbor";
import type { VaultRequest, VaultResponse } from "./messages";
import type { VaultClient } from "./freenet";

const DEFAULT_BASE = "http://127.0.0.1:8787";

function resolveDevBase(): string {
  const params = new URLSearchParams(location.search);
  return params.get("devUrl") ?? params.get("dev") ?? DEFAULT_BASE;
}

export class DevVaultClient implements VaultClient {
  readonly label = "dev vault (rust)";
  constructor(private baseUrl: string = resolveDevBase()) {}

  async request(req: VaultRequest): Promise<VaultResponse> {
    const body = encodeRequest(req);
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/v1/vault`, {
        method: "POST",
        headers: { "Content-Type": "application/cbor" },
        body: body as BodyInit,
      });
    } catch (e) {
      return {
        type: "error",
        code: "internal",
        message: `dev server unreachable at ${this.baseUrl} (${e instanceof Error ? e.message : String(e)}). Run: cargo run -p aegis-dev-vault-server`,
      };
    }

    const buf = new Uint8Array(await res.arrayBuffer());
    try {
      return decodeResponse(buf);
    } catch (e) {
      const text = new TextDecoder().decode(buf);
      return {
        type: "error",
        code: "internal",
        message: `bad response (${res.status}): ${text || String(e)}`,
      };
    }
  }

  static async probe(baseUrl: string = DEFAULT_BASE): Promise<boolean> {
    try {
      const res = await fetch(`${baseUrl}/health`, { method: "GET" });
      return res.ok;
    } catch {
      return false;
    }
  }
}
