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
  encodeUpgradeSnapshot,
  decodeUpgradeSnapshot,
  encodeLinkDropState,
  decodeLinkDropState,
} from "./cbor.ts";
import type { LinkDropState, UpgradeSnapshotV1, VaultRequest, VaultResponse } from "./messages.ts";
import {
  describeFieldChange,
  formatRelativeTime,
  remoteChangePillLabel,
  removedNoticeText,
  syncChangedSuffix,
} from "./remoteChanges.ts";
import {
  bs58Decode,
  delegateInstanceKey,
  historyEntryTarget,
  parseDelegateHistory,
  supportsExportForUpgrade,
} from "./delegateHistory.ts";

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

// ---- D20: delegate upgrade path ------------------------------------------------

function eqBytes(a: ArrayLike<number>, b: ArrayLike<number>): boolean {
  return a.length === b.length && [...(a as number[])].every((x, i) => x === b[i]);
}

function toBytes(x: Uint8Array | number[]): Uint8Array {
  return x instanceof Uint8Array ? x : new Uint8Array(x);
}

// AC16: request round trips + golden
{
  const g = decodeRequest(hexToBytes(GOLDEN.EXPORT_FOR_UPGRADE_REQ));
  assert(g.op === "export_for_upgrade", "golden export_for_upgrade");
  assert(
    bytesToHex(encodeRequest({ op: "export_for_upgrade" })) === GOLDEN.EXPORT_FOR_UPGRADE_REQ ||
      decodeRequest(encodeRequest({ op: "export_for_upgrade" })).op === "export_for_upgrade",
    "export_for_upgrade round trip",
  );
  const snapshot = new Uint8Array([0, 1, 2, 250, 251, 255]);
  const back = decodeRequest(encodeRequest({ op: "import_upgrade_snapshot", snapshot }));
  assert(back.op === "import_upgrade_snapshot", "import op");
  if (back.op === "import_upgrade_snapshot") {
    assert(eqBytes(toBytes(back.snapshot), snapshot), "import snapshot bytes");
  }
  // Also inside an envelope.
  const env = decodeEnvelopeRequest(
    encodeEnvelopeRequest({ op: "import_upgrade_snapshot", snapshot }, null),
  );
  assert(env.req.op === "import_upgrade_snapshot", "envelope import op");
}

// AC17: response round trips
{
  const snapshot = new Uint8Array([9, 8, 7, 0, 255]);
  const back = decodeResponse(encodeResponse({ type: "upgrade_snapshot", snapshot }));
  assert(back.type === "upgrade_snapshot", "upgrade_snapshot type");
  if (back.type === "upgrade_snapshot") {
    assert(back.snapshot instanceof Uint8Array, "snapshot decoded as bytes");
    assert(eqBytes(toBytes(back.snapshot), snapshot), "snapshot bytes");
  }
  const token = new Uint8Array(57).map((_, i) => i + 1);
  const env = decodeEnvelopeResponse(
    encodeEnvelopeResponse({ type: "upgrade_snapshot", snapshot }, token),
  );
  assert(env.resp.type === "upgrade_snapshot", "env upgrade_snapshot type");
  if (env.resp.type === "upgrade_snapshot") {
    assert(eqBytes(toBytes(env.resp.snapshot), snapshot), "env snapshot bytes");
  }
}

// AC18: snapshot encode/decode
{
  const vault_id = new Uint8Array(16).map((_, i) => i + 1);
  const snap: UpgradeSnapshotV1 = {
    v: 1,
    vault_id,
    key_epoch: 3,
    records: [
      [new Uint8Array([1, 2]), new Uint8Array([3, 4, 5])],
      [new Uint8Array([6]), new Uint8Array(0)],
    ],
  };
  const back = decodeUpgradeSnapshot(encodeUpgradeSnapshot(snap));
  assert(back.v === 1 && back.key_epoch === 3, "snapshot scalars");
  assert(eqBytes(back.vault_id, vault_id), "snapshot vault_id");
  assert(back.records.length === 2, "snapshot record count");
  for (let i = 0; i < 2; i++) {
    assert(eqBytes(back.records[i][0], snap.records[i][0]), `record ${i} key`);
    assert(eqBytes(back.records[i][1], snap.records[i][1]), `record ${i} value`);
  }
  const throws = (f: () => unknown): boolean => {
    try {
      f();
    } catch (e) {
      return e instanceof Error && e.message === "invalid upgrade snapshot";
    }
    return false;
  };
  assert(
    throws(() => decodeUpgradeSnapshot(encodeUpgradeSnapshot({ ...snap, v: 2 as unknown as 1 }))),
    "v:2 must throw",
  );
  assert(
    throws(() =>
      decodeUpgradeSnapshot(encodeUpgradeSnapshot({ ...snap, vault_id: new Uint8Array(15) })),
    ),
    "15-byte vault_id must throw",
  );
}

// D21 link: the four new requests and four new responses round-trip, bytes intact.
{
  const bytes = (n: number, seed: number) => new Uint8Array(n).map((_, i) => (i * 7 + seed) & 0xff);
  const state = bytes(40, 3);
  const requests: VaultRequest[] = [
    { op: "create_link_offer" },
    { op: "sign_link_state", code: "AEGL-1234", seq: 3, kind: "tombstone" },
    { op: "link_locate", code: "AEGL-1234" },
    { op: "accept_link", code: "AEGL-1234", state, passphrase: "correct horse battery" },
  ];
  for (const req of requests) {
    const back = decodeRequest(encodeRequest(req));
    assert(back.op === req.op, `link request ${req.op} op`);
    if (req.op === "accept_link" && back.op === "accept_link") {
      assert(eqBytes(toBytes(back.state), state), "accept_link state bytes");
      assert(back.code === req.code && back.passphrase === req.passphrase, "accept_link fields");
    }
    if (req.op === "sign_link_state" && back.op === "sign_link_state") {
      assert(back.seq === 3 && back.kind === "tombstone" && back.code === req.code, "sign fields");
    }
    if (req.op === "link_locate" && back.op === "link_locate") {
      assert(back.code === req.code, "link_locate code");
    }
    const env = decodeEnvelopeRequest(encodeEnvelopeRequest(req, null));
    assert(env.req.op === req.op, `link request ${req.op} envelope`);
  }
  const responses: VaultResponse[] = [
    { type: "link_offer", code: "AEGL-1234", params: bytes(20, 1), state, expires_at: 1700000600 },
    { type: "link_state", state },
    { type: "link_location", params: bytes(20, 9) },
    { type: "linked", vault_id: "ab".repeat(16), device_id_hash: bytes(32, 5), ack_state: state },
  ];
  for (const resp of responses) {
    const back = decodeResponse(encodeResponse(resp));
    assert(back.type === resp.type, `link response ${resp.type}`);
    if (resp.type === "link_offer" && back.type === "link_offer") {
      assert(back.code === resp.code && back.expires_at === resp.expires_at, "offer scalars");
      assert(back.params instanceof Uint8Array && eqBytes(toBytes(back.params), toBytes(resp.params)), "offer params");
      assert(eqBytes(toBytes(back.state), state), "offer state");
    }
    if (resp.type === "link_state" && back.type === "link_state") {
      assert(eqBytes(toBytes(back.state), state), "link_state bytes");
    }
    if (resp.type === "link_location" && back.type === "link_location") {
      assert(eqBytes(toBytes(back.params), toBytes(resp.params)), "link_location params");
    }
    if (resp.type === "linked" && back.type === "linked") {
      assert(back.vault_id === resp.vault_id, "linked vault_id");
      assert(eqBytes(toBytes(back.device_id_hash), toBytes(resp.device_id_hash)), "linked hash");
      assert(eqBytes(toBytes(back.ack_state), state), "linked ack_state");
    }
    const token = bytes(57, 2);
    const env = decodeEnvelopeResponse(encodeEnvelopeResponse(resp, token));
    assert(env.resp.type === resp.type, `link response ${resp.type} envelope`);
    assert(env.token !== null && eqBytes(env.token, token), "envelope token");
  }
}

// D21 link: link-drop state codec.
{
  const sig = new Uint8Array(64).map((_, i) => i);
  const kinds: LinkDropState["kind"][] = ["offer", "ack", "tombstone"];
  kinds.forEach((kind, i) => {
    const s: LinkDropState = { seq: i + 1, kind, body: new Uint8Array([i, 9, 8]), sig };
    const back = decodeLinkDropState(encodeLinkDropState(s));
    assert(back.seq === s.seq && back.kind === kind, `state ${kind} scalars`);
    assert(eqBytes(back.body, s.body) && eqBytes(back.sig, sig), `state ${kind} bytes`);
  });
  // A cbor-x map shaped like the Rust struct decodes.
  const rustShaped = new Encoder({ useRecords: false, mapsAsObjects: true, structuredClone: false }).encode({
    seq: 2,
    kind: "ack",
    body: new Uint8Array([1, 2, 3]),
    sig,
  });
  const decoded = decodeLinkDropState(
    rustShaped instanceof Uint8Array ? rustShaped : new Uint8Array(rustShaped),
  );
  assert(decoded.seq === 2 && decoded.kind === "ack", "rust-shaped state scalars");
  assert(eqBytes(decoded.body, new Uint8Array([1, 2, 3])), "rust-shaped body");

  const raw = (o: Record<string, unknown>): Uint8Array => {
    const e = new Encoder({ useRecords: false, mapsAsObjects: true, structuredClone: false }).encode(o);
    return e instanceof Uint8Array ? e : new Uint8Array(e);
  };
  const base = { seq: 1, kind: "offer", body: new Uint8Array(0), sig };
  const throwsLink = (b: Uint8Array): boolean => {
    try {
      decodeLinkDropState(b);
    } catch (e) {
      return e instanceof Error && e.message === "invalid link state";
    }
    return false;
  };
  assert(throwsLink(raw({ ...base, kind: "weird" })), "unknown kind must throw");
  assert(throwsLink(raw({ ...base, sig: new Uint8Array(63) })), "63-byte sig must throw");
  const { sig: _s, ...noSig } = base;
  void _s;
  assert(throwsLink(raw(noSig)), "missing sig must throw");
  assert(throwsLink(raw({ ...base, extra: 1 })), "extra field must throw");
  assert(throwsLink(raw({ ...base, seq: 1.5 })), "non-integer seq must throw");
  assert(throwsLink(raw({ ...base, seq: -1 })), "negative seq must throw");
  assert(throwsLink(new Uint8Array([0xff, 0x00])), "garbage must throw");
}

// AC19: instance key derivation matches the committed hash JSON
{
  const hash = bs58Decode("Br4YLkPvZRsPcfoLLLfgqbANQje11mCSB3ysN2QMLhb1");
  assert(hash.length === 32, "Br4Y hash is 32 bytes");
  const key = delegateInstanceKey(hash);
  const t = historyEntryTarget({
    version: "x",
    code_hash_b58: "Br4YLkPvZRsPcfoLLLfgqbANQje11mCSB3ysN2QMLhb1",
    capabilities: [],
  });
  assert(t !== null, "valid entry has a target");
  assert(t !== null && t.keyB58 === "9qTgvneeRkNXXpkGebd7YFiTzgDy5ePpBheVpEGJhnVw", "keyB58");
  assert(t !== null && eqBytes(t.keyBytes, key), "target keyBytes == delegateInstanceKey");
  assert(t !== null && eqBytes(t.hashBytes, hash), "target hashBytes");
  assert(
    historyEntryTarget({ version: "x", code_hash_b58: "not*base58", capabilities: [] }) === null,
    "invalid base58 -> null",
  );
  assert(
    historyEntryTarget({ version: "x", code_hash_b58: "3yZe7d", capabilities: [] }) === null,
    "short hash -> null",
  );
}

// AC20 (pure part) + AC19/21 (committed files)
{
  const good = { version: "1", code_hash_b58: "abc", capabilities: ["session_token"] };
  const good2 = { version: "2", code_hash_b58: "def", capabilities: [] };
  assert(parseDelegateHistory(null).length === 0, "null -> []");
  assert(parseDelegateHistory({}).length === 0, "object -> []");
  assert(parseDelegateHistory("x").length === 0, "string -> []");
  const parsed = parseDelegateHistory([
    good,
    { version: 1, code_hash_b58: "x", capabilities: [] },
    null,
    { version: "v", capabilities: [] },
    { version: "v", code_hash_b58: "x", capabilities: "nope" },
    good2,
  ]);
  assert(parsed.length === 2, `malformed dropped, got ${parsed.length}`);
  assert(parsed[0].version === "1" && parsed[1].version === "2", "order kept");
  assert(!supportsExportForUpgrade(good), "no export capability");
  assert(
    supportsExportForUpgrade({ ...good, capabilities: ["session_token", "export_for_upgrade"] }),
    "export capability",
  );
}

// Remote change log (D22): CBOR round-trips
{
  for (const req of [
    { op: "ack_remote_change", id: "e1" },
    { op: "list_removed_remote" },
    { op: "ack_removed_remote" },
  ] as VaultRequest[]) {
    const back = decodeRequest(encodeRequest(req));
    assert(JSON.stringify(back) === JSON.stringify(req), `roundtrip ${req.op}`);
  }

  const removed: VaultResponse = {
    type: "removed_remote",
    entries: [
      { entry_id: "e1", kind: "deleted", changed_at: 10, recorded_at: 11, entry_name: "GitHub" },
    ],
  };
  const removedBack = decodeResponse(encodeResponse(removed));
  assert(JSON.stringify(removedBack) === JSON.stringify(removed), "removed_remote roundtrip");

  const summaries = decodeResponse(
    encodeResponse({
      type: "summaries",
      entries: [
        {
          id: "e1",
          folder_id: null,
          name: "GitHub",
          urls: [],
          username: "",
          tags: [],
          updated_at: 1,
          remote_change: { kind: "modified", changed_at: 5 },
        },
      ],
    }),
  );
  assert(
    summaries.type === "summaries" &&
      summaries.entries[0].remote_change?.kind === "modified" &&
      summaries.entries[0].remote_change?.changed_at === 5,
    "summaries remote_change survives",
  );

  const entryResp = decodeResponse(
    encodeResponse({
      type: "entry",
      entry: {
        id: "e1",
        folder_id: null,
        name: "GitHub",
        urls: [],
        username: "",
        password: "",
        notes: "",
        custom_fields: [],
        tags: [],
        created_at: 1,
        updated_at: 1,
      },
      remote_change: {
        entry_id: "e1",
        kind: "modified",
        changed_at: 5,
        recorded_at: 6,
        fields: [
          { field: "urls", old: ["a"], new: ["b", "c"] },
          { field: "password" },
          { field: "username", old: "alice", new: "alice2" },
        ],
      },
    }),
  );
  assert(entryResp.type === "entry", "entry type");
  if (entryResp.type === "entry") {
    const f = entryResp.remote_change?.fields ?? [];
    assert(f.length === 3, "entry remote_change fields");
    assert(Array.isArray(f[0].new) && f[0].new.length === 2, "list values survive");
    assert(f[1].old === undefined && f[1].new === undefined, "valueless field stays valueless");
    assert(f[2].old === "alice" && f[2].new === "alice2", "text values survive");
  }

  const plainEntry = decodeResponse(
    encodeResponse({
      type: "entry",
      entry: {
        id: "e2",
        folder_id: null,
        name: "Plain",
        urls: [],
        username: "",
        password: "",
        notes: "",
        custom_fields: [],
        tags: [],
        created_at: 1,
        updated_at: 1,
      },
    }),
  );
  assert(plainEntry.type === "entry" && plainEntry.remote_change === undefined, "no remote_change");

  const synced = decodeResponse(
    encodeResponse({
      type: "synced",
      action: "pulled",
      remote_revisions: 1,
      detail: "",
      remote_changed: 2,
    }),
  );
  assert(synced.type === "synced" && synced.remote_changed === 2, "synced remote_changed");
}

// Remote change log (D22): pure helpers
{
  assert(
    describeFieldChange({ field: "username", old: "alice", new: "alice2" }) ===
      "Username: alice → alice2",
    "describe username",
  );
  assert(
    describeFieldChange({
      field: "urls",
      old: ["https://old.example.com"],
      new: ["https://example.com"],
    }) === "URLs: added https://example.com, removed https://old.example.com",
    "describe urls",
  );
  assert(
    describeFieldChange({ field: "password" }) ===
      "Password changed (previous password is in Password history)",
    "describe password",
  );
  assert(describeFieldChange({ field: "notes" }) === "Notes changed", "describe notes");
  assert(
    removedNoticeText([
      { entry_id: "1", kind: "deleted", changed_at: 1, entry_name: "GitHub" },
      { entry_id: "2", kind: "deleted", changed_at: 1, entry_name: "Bank" },
    ]) === "Removed on another device: GitHub, Bank",
    "removed notice",
  );
  assert(syncChangedSuffix(2) === " · 2 entries updated from another device", "suffix 2");
  assert(syncChangedSuffix(1) === " · 1 entry updated from another device", "suffix 1");
  assert(syncChangedSuffix(0) === "" && syncChangedSuffix(undefined) === "", "suffix 0");
  assert(remoteChangePillLabel("added") === "New", "pill added");
  assert(remoteChangePillLabel("modified") === "Updated", "pill modified");
  assert(remoteChangePillLabel(undefined) === null, "pill none");
  assert(formatRelativeTime(1000, 1010) === "just now", "relative just now");
  assert(formatRelativeTime(1000, 1300) === "5 min ago", "relative minutes");
  assert(formatRelativeTime(1000, 900) === "just now", "relative negative");
  assert(
    describeFieldChange({ field: "custom:f1", label: "PIN" }) === "Hidden field “PIN” changed",
    "hidden custom field",
  );
}

async function committedFiles(): Promise<void> {
  const spec: string = "node:fs";
  const fs = (await import(/* @vite-ignore */ spec)) as {
    readFileSync(p: URL, enc: "utf8"): string;
  };
  const read = (rel: string): string => fs.readFileSync(new URL(rel, import.meta.url), "utf8");
  const histRaw = read("../../delegates/vault-delegate/history.json");
  const uiRaw = read("../public/aegis_vault_delegate.history.json");
  assert(histRaw === uiRaw, "UI history copy is byte-identical");
  const hist = parseDelegateHistory(JSON.parse(histRaw));
  // Append-only, newest first (D20): every release prepends the outgoing
  // delegate, so the oldest seed entry stays last.
  assert(hist.length >= 1, "history has entries");
  const seed = hist[hist.length - 1];
  assert(seed.version === "2.0.0-rc.2+freenet-session", "seed version");
  assert(seed.code_hash_b58 === "Br4YLkPvZRsPcfoLLLfgqbANQje11mCSB3ysN2QMLhb1", "seed hash");
  assert(
    seed.capabilities.length === 1 && seed.capabilities[0] === "session_token",
    "seed capabilities",
  );
  assert(!supportsExportForUpgrade(seed), "seed lacks export_for_upgrade");
  assert(new Set(hist.map((h) => h.code_hash_b58)).size === hist.length, "no duplicate hashes");
  const currentHash = (JSON.parse(read("../public/aegis_vault_delegate.hash.json")) as { code_hash_b58: string }).code_hash_b58;
  assert(!hist.some((h) => h.code_hash_b58 === currentHash), "current delegate is not in its own history");

  const hashJson = JSON.parse(read("../public/aegis_vault_delegate.hash.json")) as {
    instance_key_bytes: number[];
    instance_key_b58: string;
    code_hash_b58: string;
  };
  const key = delegateInstanceKey(bs58Decode(hashJson.code_hash_b58));
  assert(eqBytes(key, hashJson.instance_key_bytes), "instance key matches hash.json");
  assert(
    delegateInstanceKey(bs58Decode("Br4YLkPvZRsPcfoLLLfgqbANQje11mCSB3ysN2QMLhb1")).length === 32,
    "Br4Y instance key length",
  );
}

committedFiles()
  .then(() => console.log("cbor.spec.ts: delegate upgrade checks passed"))
  .catch((e) => {
    console.error(e);
    (globalThis as unknown as { process: { exit(c: number): void } }).process.exit(1);
  });

// Log TS encodings so we can feed them through Rust if needed
console.log("TS STATUS_REQ=", bytesToHex(encodeRequest({ op: "status" })));
console.log("cbor.spec.ts: all checks passed (Rust decode + TS roundtrip)");
