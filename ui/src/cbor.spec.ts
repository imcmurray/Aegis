/**
 * Run with: npm run test:cbor
 *
 * Validates TypeScript can decode Rust ciborium golden vectors, and that
 * TS encode ↔ TS decode round-trips. Byte-for-byte encode equality is NOT
 * required (cbor-x may use longer definite-length map headers than ciborium);
 * both decoders accept both encodings.
 */

import {
  GOLDEN,
  decodeRequest,
  decodeResponse,
  encodeRequest,
  encodeResponse,
  hexToBytes,
  bytesToHex,
} from "./cbor.ts";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

// Decode Rust-produced STATUS request
{
  const req = decodeRequest(hexToBytes(GOLDEN.STATUS_REQ));
  assert(req.op === "status", "status req");
}

// Decode Rust-produced UNLOCK request
{
  const req = decodeRequest(hexToBytes(GOLDEN.UNLOCK_REQ));
  assert(req.op === "unlock", "unlock op");
  assert(req.op === "unlock" && req.passphrase === "secret", "unlock pw");
}

// Decode Rust-produced STATUS response
{
  const resp = decodeResponse(hexToBytes(GOLDEN.STATUS_RESP));
  assert(resp.type === "status", "status resp type");
  if (resp.type === "status") {
    assert(resp.has_vault === true, "has_vault");
    assert(resp.unlocked === false, "unlocked");
    assert(resp.vault_id === "abc", "vault_id");
  }
}

// Decode Rust-produced EXPORT response (byte string)
{
  const resp = decodeResponse(hexToBytes(GOLDEN.EXPORT_RESP));
  assert(resp.type === "export", "export type");
  if (resp.type === "export") {
    const blob = resp.blob instanceof Uint8Array ? [...resp.blob] : resp.blob;
    assert(
      Array.isArray(blob) &&
        blob[0] === 1 &&
        blob[1] === 2 &&
        blob[2] === 3 &&
        blob[3] === 4,
      `export blob got ${JSON.stringify(blob)}`,
    );
  }
}

// TS encode → TS decode round-trips
{
  const cases: Parameters<typeof encodeRequest>[0][] = [
    { op: "status" },
    { op: "lock" },
    { op: "unlock", passphrase: "secret" },
    { op: "create_vault", passphrase: "x", kdf_profile: "test" },
    { op: "list_summaries", query: "git" },
    { op: "get_entry", id: "deadbeef" },
    { op: "delete_entry", id: "deadbeef" },
    {
      op: "generate_password",
      policy: {
        length: 20,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true,
        memorable: false,
        word_count: 5,
      },
    },
    { op: "export_encrypted", passphrase: "pw" },
  ];
  for (const req of cases) {
    const bytes = encodeRequest(req);
    const back = decodeRequest(bytes);
    assert(back.op === req.op, `roundtrip op ${req.op}`);
  }
}

{
  const resp = encodeResponse({
    type: "error",
    code: "locked",
    message: "vault is locked",
  });
  const back = decodeResponse(resp);
  assert(back.type === "error" && back.code === "locked", "error roundtrip");
}

// Log TS encodings so we can feed them through Rust if needed
console.log("TS STATUS_REQ=", bytesToHex(encodeRequest({ op: "status" })));
console.log("cbor.spec.ts: all checks passed (Rust decode + TS roundtrip)");
