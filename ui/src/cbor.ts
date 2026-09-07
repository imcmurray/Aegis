/**
 * CBOR codec for VaultRequest / VaultResponse matching Rust ciborium + serde
 * (internally tagged enums with `op` / `type` tags).
 */

import { Decoder, Encoder } from "cbor-x";
import type { VaultRequest, VaultResponse } from "./messages";

const encoder = new Encoder({
  useRecords: false,
  mapsAsObjects: true,
  // Encode Uint8Array as CBOR byte strings (major type 2), matching serde_bytes.
  structuredClone: false,
});

const decoder = new Decoder({
  useRecords: false,
  mapsAsObjects: true,
});

export function encodeRequest(req: VaultRequest): Uint8Array {
  // Build a plain object matching serde's internally-tagged shape.
  const obj = requestToPlain(req);
  const encoded = encoder.encode(obj);
  return encoded instanceof Uint8Array ? encoded : new Uint8Array(encoded);
}

export function decodeResponse(bytes: Uint8Array): VaultResponse {
  const obj = decoder.decode(bytes) as Record<string, unknown>;
  return plainToResponse(obj);
}

export function encodeResponse(resp: VaultResponse): Uint8Array {
  const obj = responseToPlain(resp);
  const encoded = encoder.encode(obj);
  return encoded instanceof Uint8Array ? encoded : new Uint8Array(encoded);
}

export function decodeRequest(bytes: Uint8Array): VaultRequest {
  const obj = decoder.decode(bytes) as Record<string, unknown>;
  return plainToRequest(obj);
}

function requestToPlain(req: VaultRequest): Record<string, unknown> {
  switch (req.op) {
    case "create_vault":
      return {
        op: "create_vault",
        passphrase: req.passphrase,
        kdf_profile: req.kdf_profile ?? "interactive",
      };
    case "unlock":
      return { op: "unlock", passphrase: req.passphrase };
    case "lock":
      return { op: "lock" };
    case "status":
      return { op: "status" };
    case "list_summaries":
      return {
        op: "list_summaries",
        query: req.query ?? null,
      };
    case "get_entry":
      return { op: "get_entry", id: req.id };
    case "upsert_entry":
      return { op: "upsert_entry", entry: req.entry };
    case "delete_entry":
      return { op: "delete_entry", id: req.id };
    case "upsert_folder":
      return { op: "upsert_folder", folder: req.folder };
    case "delete_folder":
      return { op: "delete_folder", id: req.id };
    case "list_folders":
      return { op: "list_folders" };
    case "generate_password":
      return {
        op: "generate_password",
        policy: req.policy ?? {
          length: 20,
          uppercase: true,
          lowercase: true,
          digits: true,
          symbols: true,
          memorable: false,
          word_count: 5,
        },
      };
    case "generate_totp":
      return {
        op: "generate_totp",
        secret: req.secret,
        period: req.period ?? null,
        digits: req.digits ?? null,
      };
    case "export_encrypted":
      return { op: "export_encrypted", passphrase: req.passphrase };
    case "import_encrypted": {
      const blob =
        req.blob instanceof Uint8Array ? req.blob : new Uint8Array(req.blob);
      return {
        op: "import_encrypted",
        blob,
        passphrase: req.passphrase,
        new_passphrase: req.new_passphrase ?? null,
        replace: req.replace ?? false,
      };
    }
    case "preview_import": {
      const blob =
        req.blob instanceof Uint8Array ? req.blob : new Uint8Array(req.blob);
      return {
        op: "preview_import",
        blob,
        passphrase: req.passphrase,
        local_passphrase: req.local_passphrase ?? null,
      };
    }
    case "get_audit_log":
      return { op: "get_audit_log", limit: req.limit ?? null };
    case "sync_now":
      return { op: "sync_now" };
    case "sync_with_remote": {
      const raw = req.remote_state;
      let remote_state: Uint8Array;
      if (!raw) remote_state = new Uint8Array(0);
      else if (raw instanceof Uint8Array) remote_state = raw;
      else remote_state = new Uint8Array(raw);
      return { op: "sync_with_remote", remote_state };
    }
    case "change_passphrase":
      return {
        op: "change_passphrase",
        current_passphrase: req.current_passphrase,
        new_passphrase: req.new_passphrase,
        kdf_profile: req.kdf_profile ?? null,
      };
    case "password_health":
      return { op: "password_health" };
    case "generate_recovery_key":
      return {
        op: "generate_recovery_key",
        kdf_profile: req.kdf_profile ?? null,
      };
    case "export_recovery_kit":
      return { op: "export_recovery_kit" };
    case "import_recovery_kit": {
      const kit =
        req.kit instanceof Uint8Array ? req.kit : new Uint8Array(req.kit);
      const backup = req.backup
        ? req.backup instanceof Uint8Array
          ? req.backup
          : new Uint8Array(req.backup)
        : new Uint8Array(0);
      return {
        op: "import_recovery_kit",
        kit,
        recovery_secret: req.recovery_secret,
        new_passphrase: req.new_passphrase,
        backup,
        backup_passphrase: req.backup_passphrase ?? null,
      };
    }
    case "unlock_with_recovery":
      return { op: "unlock_with_recovery", recovery_key: req.recovery_key };
    case "revoke_recovery_key":
      return { op: "revoke_recovery_key" };
    case "migrate_vault":
      return { op: "migrate_vault", passphrase: req.passphrase };
    case "migrate_vault_with_recovery":
      return {
        op: "migrate_vault_with_recovery",
        recovery_key: req.recovery_key,
        new_v2_passphrase: req.new_v2_passphrase,
      };
    case "rotate_keys":
      return {
        op: "rotate_keys",
        passphrase: req.passphrase,
        recovery_key: req.recovery_key ?? null,
      };
    case "export_share_identity":
      return { op: "export_share_identity" };
    case "create_share":
      return {
        op: "create_share",
        entry_id: req.entry_id,
        recipient_identity: req.recipient_identity,
      };
    case "open_share":
      return {
        op: "open_share",
        envelope: req.envelope,
        expected_sender_identity: req.expected_sender_identity ?? new Uint8Array(0),
      };
    default: {
      const _exhaustive: never = req;
      throw new Error(`unknown request: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

function plainToRequest(obj: Record<string, unknown>): VaultRequest {
  const op = obj.op as string;
  switch (op) {
    case "status":
      return { op: "status" };
    case "lock":
      return { op: "lock" };
    case "unlock":
      return { op: "unlock", passphrase: String(obj.passphrase ?? "") };
    case "create_vault":
      return {
        op: "create_vault",
        passphrase: String(obj.passphrase ?? ""),
        kdf_profile: (obj.kdf_profile as "test") ?? "interactive",
      };
    case "list_summaries":
      return {
        op: "list_summaries",
        query: (obj.query as string | null | undefined) ?? null,
      };
    case "get_entry":
      return { op: "get_entry", id: String(obj.id) };
    case "upsert_entry":
      return { op: "upsert_entry", entry: obj.entry as never };
    case "delete_entry":
      return { op: "delete_entry", id: String(obj.id) };
    case "upsert_folder":
      return { op: "upsert_folder", folder: obj.folder as never };
    case "delete_folder":
      return { op: "delete_folder", id: String(obj.id) };
    case "list_folders":
      return { op: "list_folders" };
    case "generate_password":
      return { op: "generate_password", policy: obj.policy as never };
    case "generate_totp":
      return {
        op: "generate_totp",
        secret: String(obj.secret ?? ""),
        period: obj.period as number | undefined,
        digits: obj.digits as number | undefined,
      };
    case "export_encrypted":
      return {
        op: "export_encrypted",
        passphrase: String(obj.passphrase ?? ""),
      };
    case "import_encrypted": {
      const raw = obj.blob;
      let blob: number[];
      if (raw instanceof Uint8Array) blob = [...raw];
      else if (Array.isArray(raw)) blob = raw as number[];
      else blob = [];
      return {
        op: "import_encrypted",
        blob,
        passphrase: String(obj.passphrase ?? ""),
        new_passphrase:
          obj.new_passphrase == null || obj.new_passphrase === ""
            ? null
            : String(obj.new_passphrase),
        replace: Boolean(obj.replace),
      };
    }
    case "preview_import": {
      const raw = obj.blob;
      let blob: number[];
      if (raw instanceof Uint8Array) blob = [...raw];
      else if (Array.isArray(raw)) blob = raw as number[];
      else blob = [];
      return {
        op: "preview_import",
        blob,
        passphrase: String(obj.passphrase ?? ""),
        local_passphrase:
          obj.local_passphrase == null || obj.local_passphrase === ""
            ? null
            : String(obj.local_passphrase),
      };
    }
    case "get_audit_log":
      return { op: "get_audit_log", limit: obj.limit as number | undefined };
    case "sync_now":
      return { op: "sync_now" };
    case "sync_with_remote": {
      const raw = obj.remote_state;
      let remote_state: number[] | Uint8Array = [];
      if (raw instanceof Uint8Array) remote_state = raw;
      else if (Array.isArray(raw)) remote_state = raw as number[];
      return { op: "sync_with_remote", remote_state };
    }
    case "change_passphrase":
      return {
        op: "change_passphrase",
        current_passphrase: String(obj.current_passphrase ?? ""),
        new_passphrase: String(obj.new_passphrase ?? ""),
        kdf_profile: obj.kdf_profile as never,
      };
    case "password_health":
      return { op: "password_health" };
    case "generate_recovery_key":
      return {
        op: "generate_recovery_key",
        kdf_profile: obj.kdf_profile as never,
      };
    case "export_recovery_kit":
      return { op: "export_recovery_kit" };
    case "import_recovery_kit":
      return {
        op: "import_recovery_kit",
        kit: bytesField(obj.kit),
        recovery_secret: String(obj.recovery_secret ?? ""),
        new_passphrase: String(obj.new_passphrase ?? ""),
        backup: bytesField(obj.backup),
        backup_passphrase:
          obj.backup_passphrase == null || obj.backup_passphrase === ""
            ? null
            : String(obj.backup_passphrase),
      };
    case "unlock_with_recovery":
      return {
        op: "unlock_with_recovery",
        recovery_key: String(obj.recovery_key ?? ""),
      };
    case "revoke_recovery_key":
      return { op: "revoke_recovery_key" };
    case "migrate_vault":
      return { op: "migrate_vault", passphrase: String(obj.passphrase ?? "") };
    case "migrate_vault_with_recovery":
      return {
        op: "migrate_vault_with_recovery",
        recovery_key: String(obj.recovery_key ?? ""),
        new_v2_passphrase: String(obj.new_v2_passphrase ?? ""),
      };
    case "rotate_keys":
      return {
        op: "rotate_keys",
        passphrase: String(obj.passphrase ?? ""),
        recovery_key:
          obj.recovery_key == null || obj.recovery_key === ""
            ? null
            : String(obj.recovery_key),
      };
    case "export_share_identity":
      return { op: "export_share_identity" };
    case "create_share":
      return {
        op: "create_share",
        entry_id: String(obj.entry_id ?? ""),
        recipient_identity: bytesField(obj.recipient_identity),
      };
    case "open_share":
      return {
        op: "open_share",
        envelope: bytesField(obj.envelope),
        expected_sender_identity: bytesField(obj.expected_sender_identity),
      };
    default:
      throw new Error(`unknown request op: ${op}`);
  }
}

function responseToPlain(resp: VaultResponse): Record<string, unknown> {
  switch (resp.type) {
    case "ok":
      return { type: "ok" };
    case "locked":
      return { type: "locked" };
    case "unlocked":
      return { type: "unlocked", vault_id: resp.vault_id };
    case "status":
      return {
        type: "status",
        has_vault: resp.has_vault,
        unlocked: resp.unlocked,
        vault_id: resp.vault_id,
        has_recovery: resp.has_recovery ?? false,
        vault_format: resp.vault_format ?? null,
        needs_migration: resp.needs_migration ?? false,
      };
    case "summaries":
      return { type: "summaries", entries: resp.entries };
    case "entry":
      return { type: "entry", entry: resp.entry };
    case "password":
      return { type: "password", password: resp.password };
    case "totp":
      return {
        type: "totp",
        code: resp.code,
        seconds_remaining: resp.seconds_remaining,
        period: resp.period,
      };
    case "folders":
      return { type: "folders", folders: resp.folders };
    case "export": {
      const blob =
        resp.blob instanceof Uint8Array
          ? resp.blob
          : new Uint8Array(resp.blob as number[]);
      return { type: "export", blob };
    }
    case "audit":
      return { type: "audit", events: resp.events };
    case "error":
      return { type: "error", code: resp.code, message: resp.message };
    case "synced":
      return {
        type: "synced",
        action: resp.action,
        remote_revisions: resp.remote_revisions,
        detail: resp.detail,
        contract_state: resp.contract_state ?? new Uint8Array(0),
        owner_verifying_key: resp.owner_verifying_key ?? new Uint8Array(0),
        sync_params: resp.sync_params ?? new Uint8Array(0),
      };
    case "health":
      return { type: "health", report: resp.report };
    case "recovery_key":
      return {
        type: "recovery_key",
        recovery_key: resp.recovery_key,
        kit: resp.kit ?? new Uint8Array(0),
      };
    case "migrated":
      return {
        type: "migrated",
        vault_id: resp.vault_id,
        recovery_secret: resp.recovery_secret,
      };
    case "rotated":
      return {
        type: "rotated",
        vault_id: resp.vault_id,
        key_epoch: resp.key_epoch,
        recovery_secret: resp.recovery_secret ?? null,
      };
    case "share_identity": {
      const blob =
        resp.blob instanceof Uint8Array
          ? resp.blob
          : new Uint8Array(resp.blob as number[]);
      return { type: "share_identity", blob };
    }
    case "share_envelope": {
      const blob =
        resp.blob instanceof Uint8Array
          ? resp.blob
          : new Uint8Array(resp.blob as number[]);
      return { type: "share_envelope", blob };
    }
    case "import_preview":
      return {
        type: "import_preview",
        local_available: resp.local_available,
        same_vault_id: resp.same_vault_id,
        local_vault_id: resp.local_vault_id,
        backup_vault_id: resp.backup_vault_id,
        local_entry_count: resp.local_entry_count,
        backup_entry_count: resp.backup_entry_count,
        local_updated_at: resp.local_updated_at,
        backup_updated_at: resp.backup_updated_at,
        only_local: resp.only_local ?? [],
        only_backup: resp.only_backup ?? [],
        changed: resp.changed ?? [],
        unchanged_count: resp.unchanged_count,
        folders_only_local: resp.folders_only_local ?? [],
        folders_only_backup: resp.folders_only_backup ?? [],
        note: resp.note ?? "",
      };
    default: {
      const _exhaustive: never = resp;
      throw new Error(`unknown response: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

function bytesField(raw: unknown): number[] {
  if (!raw) return [];
  if (raw instanceof Uint8Array) return [...raw];
  if (Array.isArray(raw)) return raw as number[];
  return [];
}

function plainToResponse(obj: Record<string, unknown>): VaultResponse {
  const type = obj.type as string;
  switch (type) {
    case "ok":
      return { type: "ok" };
    case "locked":
      return { type: "locked" };
    case "unlocked":
      return { type: "unlocked", vault_id: String(obj.vault_id) };
    case "status":
      return {
        type: "status",
        has_vault: Boolean(obj.has_vault),
        unlocked: Boolean(obj.unlocked),
        vault_id: (obj.vault_id as string | null) ?? null,
        has_recovery: Boolean(obj.has_recovery),
        vault_format: (obj.vault_format as string | null | undefined) ?? null,
        needs_migration: Boolean(obj.needs_migration),
      };
    case "summaries":
      return { type: "summaries", entries: (obj.entries as never) ?? [] };
    case "entry":
      return { type: "entry", entry: obj.entry as never };
    case "password":
      return { type: "password", password: String(obj.password) };
    case "totp":
      return {
        type: "totp",
        code: String(obj.code ?? ""),
        seconds_remaining: Number(obj.seconds_remaining ?? 0),
        period: Number(obj.period ?? 30),
      };
    case "folders":
      return { type: "folders", folders: (obj.folders as never) ?? [] };
    case "export": {
      const raw = obj.blob;
      let blob: number[];
      if (raw instanceof Uint8Array) {
        blob = [...raw];
      } else if (Array.isArray(raw)) {
        blob = raw as number[];
      } else if (raw && typeof raw === "object" && "data" in (raw as object)) {
        // some decoders wrap bytes
        blob = [...new Uint8Array((raw as { data: ArrayBuffer }).data)];
      } else {
        blob = [];
      }
      return { type: "export", blob };
    }
    case "audit":
      return { type: "audit", events: (obj.events as never) ?? [] };
    case "error":
      return {
        type: "error",
        code: String(obj.code),
        message: String(obj.message),
      };
    case "synced":
      return {
        type: "synced",
        action: String(obj.action ?? ""),
        remote_revisions: Number(obj.remote_revisions ?? 0),
        detail: String(obj.detail ?? ""),
        contract_state: bytesField(obj.contract_state),
        owner_verifying_key: bytesField(obj.owner_verifying_key),
        sync_params: bytesField(obj.sync_params),
      };
    case "health":
      return { type: "health", report: obj.report as never };
    case "recovery_key":
      return {
        type: "recovery_key",
        recovery_key: String(obj.recovery_key ?? ""),
        kit: bytesField(obj.kit),
      };
    case "migrated":
      return {
        type: "migrated",
        vault_id: String(obj.vault_id ?? ""),
        recovery_secret: String(obj.recovery_secret ?? ""),
      };
    case "rotated":
      return {
        type: "rotated",
        vault_id: String(obj.vault_id ?? ""),
        key_epoch: Number(obj.key_epoch ?? 0),
        recovery_secret:
          obj.recovery_secret == null || obj.recovery_secret === ""
            ? null
            : String(obj.recovery_secret),
      };
    case "share_identity":
      return { type: "share_identity", blob: bytesField(obj.blob) };
    case "share_envelope":
      return { type: "share_envelope", blob: bytesField(obj.blob) };
    case "import_preview":
      return {
        type: "import_preview",
        local_available: Boolean(obj.local_available),
        same_vault_id: Boolean(obj.same_vault_id),
        local_vault_id: (obj.local_vault_id as string | null) ?? null,
        backup_vault_id: String(obj.backup_vault_id ?? ""),
        local_entry_count: Number(obj.local_entry_count ?? 0),
        backup_entry_count: Number(obj.backup_entry_count ?? 0),
        local_updated_at:
          obj.local_updated_at == null ? null : Number(obj.local_updated_at),
        backup_updated_at: Number(obj.backup_updated_at ?? 0),
        only_local: (obj.only_local as never) ?? [],
        only_backup: (obj.only_backup as never) ?? [],
        changed: (obj.changed as never) ?? [],
        unchanged_count: Number(obj.unchanged_count ?? 0),
        folders_only_local: (obj.folders_only_local as string[]) ?? [],
        folders_only_backup: (obj.folders_only_backup as string[]) ?? [],
        note: String(obj.note ?? ""),
      };
    default:
      throw new Error(`unknown response type: ${type}`);
  }
}

/** Decode hex string to bytes (for golden-vector tests). */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Golden vectors from `cargo test -p aegis-common print_golden_hex -- --nocapture`
 */
export const GOLDEN = {
  STATUS_REQ: "a1626f7066737461747573",
  UNLOCK_REQ: "a2626f7066756e6c6f636b6a7061737370687261736566736563726574",
  STATUS_RESP:
    "a4647479706566737461747573696861735f7661756c74f568756e6c6f636b6564f4687661756c745f696463616263",
  EXPORT_RESP: "a26474797065666578706f727464626c6f624401020304",
} as const;
