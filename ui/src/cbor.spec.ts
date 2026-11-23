/**
 * Run with: npm run test:cbor
 *
 * Validates TypeScript can decode Rust ciborium golden vectors, and that
 * TS encode ↔ TS decode round-trips. Byte-for-byte encode equality is NOT
 * required (cbor-x may use longer definite-length map headers than ciborium);
 * both decoders accept both encodings.
 */

import { Encoder } from "cbor-x";
import {
  GOLDEN,
  decodeEnvelopeRequest,
  decodeEnvelopeResponse,
  decodeRequest,
  decodeResponse,
  encodeEnvelopeRequest,
  encodeEnvelopeResponse,
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
    { op: "migrate_vault", passphrase: "secret" },
    {
      op: "migrate_vault_with_recovery",
      recovery_key: "deadbeef",
      new_v2_passphrase: "correct horse battery staple",
    },
    { op: "rotate_keys", passphrase: "secret" },
    { op: "export_recovery_kit" },
    {
      op: "import_recovery_kit",
      kit: new Uint8Array([1, 2, 3]),
      recovery_secret: "AEGIS2-TEST",
      new_passphrase: "correct horse battery staple",
      backup: new Uint8Array(0),
      backup_passphrase: null,
    },
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

// Delegate IPC envelope: Rust golden vectors
{
  const env = decodeEnvelopeRequest(hexToBytes(GOLDEN.ENVELOPE_STATUS_REQ));
  assert(env.v === 1, "envelope req v");
  assert(env.token === null, "envelope req token null");
  assert(env.req.op === "status", "envelope req op");

  const resp = decodeEnvelopeResponse(hexToBytes(GOLDEN.ENVELOPE_LOCKED_RESP));
  assert(resp.v === 1, "envelope resp v");
  assert(resp.token === null, "envelope resp token null");
  assert(resp.resp.type === "locked", "envelope resp type");
}

// Envelope request round trip: null token and a 57-byte token
{
  const nullBack = decodeEnvelopeRequest(encodeEnvelopeRequest({ op: "status" }, null));
  assert(nullBack.token === null, "env req null token");
  assert(nullBack.req.op === "status", "env req null op");

  const token = new Uint8Array(57).map((_, i) => i + 1);
  const bytes = encodeEnvelopeRequest({ op: "lock" }, token);
  // Token must be a CBOR byte string (major type 2), not an array.
  const hex = bytesToHex(bytes);
  assert(hex.includes("5839" + bytesToHex(token)), "token encoded as byte string");
  const back = decodeEnvelopeRequest(bytes);
  assert(back.token instanceof Uint8Array, "env req token is Uint8Array");
  assert(back.token !== null && bytesToHex(back.token) === bytesToHex(token), "env req token bytes");
  assert(back.req.op === "lock", "env req token op");
}

// Envelope response round trip: with token and null
{
  const token = new Uint8Array(57).map((_, i) => i + 1);
  const withTok = decodeEnvelopeResponse(
    encodeEnvelopeResponse({ type: "unlocked", vault_id: "abc" }, token),
  );
  assert(withTok.token instanceof Uint8Array, "env resp token is Uint8Array");
  assert(
    withTok.token !== null && bytesToHex(withTok.token) === bytesToHex(token),
    "env resp token bytes",
  );
  assert(
    withTok.resp.type === "unlocked" && withTok.resp.vault_id === "abc",
    "env resp with token body",
  );
  const noTok = decodeEnvelopeResponse(encodeEnvelopeResponse({ type: "locked" }, null));
  assert(noTok.token === null && noTok.resp.type === "locked", "env resp null token");
}

// Bare (old delegate) response decodes with token null
{
  const bare = decodeEnvelopeResponse(
    encodeResponse({ type: "error", code: "locked", message: "vault is locked" }),
  );
  assert(bare.token === null, "bare resp token null");
  assert(bare.resp.type === "error" && bare.resp.code === "locked", "bare resp body");
}

// Unsupported envelope version throws
{
  const v2 = new Encoder({ useRecords: false, mapsAsObjects: true }).encode({
    v: 2,
    token: null,
    resp: { type: "locked" },
  });
  let threw = false;
  try {
    decodeEnvelopeResponse(v2 instanceof Uint8Array ? v2 : new Uint8Array(v2));
  } catch (e) {
    threw = e instanceof Error && e.message === "unsupported delegate envelope version";
  }
  assert(threw, "v:2 envelope must throw");
}

// Log TS encodings so we can feed them through Rust if needed
console.log("TS STATUS_REQ=", bytesToHex(encodeRequest({ op: "status" })));
console.log("cbor.spec.ts: all checks passed (Rust decode + TS roundtrip)");
