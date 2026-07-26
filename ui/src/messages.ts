/**
 * Mirror of aegis-common VaultRequest / VaultResponse.
 */

import { storageGet, storageSet } from "./storage";
export type KdfProfile = "interactive" | "mobile" | "high" | "test";

export interface GeneratorPolicy {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  memorable: boolean;
  word_count: number;
}

export interface Folder {
  id: string;
  name: string;
  parent: string | null;
  created_at: number;
  updated_at: number;
}

export interface PasswordHistoryItem {
  password: string;
  changed_at: number;
}

export interface Entry {
  id: string;
  folder_id: string | null;
  name: string;
  urls: string[];
  username: string;
  password: string;
  notes: string;
  custom_fields: { id: string; name: string; value: string; kind: string }[];
  tags: string[];
  /** Base32 TOTP secret (optional). */
  totp_secret?: string | null;
  /** Previous passwords (newest first). */
  password_history?: PasswordHistoryItem[];
  created_at: number;
  updated_at: number;
}

export interface EntrySummary {
  id: string;
  folder_id: string | null;
  name: string;
  urls: string[];
  username: string;
  tags: string[];
  updated_at: number;
  /** Feature flags for list pills (no secret values). */
  has_password?: boolean;
  has_username?: boolean;
  has_totp?: boolean;
  has_notes?: boolean;
  has_url?: boolean;
  custom_field_count?: number;
  has_history?: boolean;
}

export type VaultRequest =
  | { op: "create_vault"; passphrase: string; kdf_profile?: KdfProfile }
  | { op: "unlock"; passphrase: string }
  | { op: "lock" }
  | { op: "status" }
  | { op: "list_summaries"; query?: string | null }
  | { op: "get_entry"; id: string }
  | { op: "upsert_entry"; entry: Entry }
  | { op: "delete_entry"; id: string }
  | { op: "upsert_folder"; folder: Folder }
  | { op: "delete_folder"; id: string }
  | { op: "list_folders" }
  | { op: "generate_password"; policy?: GeneratorPolicy }
  | { op: "generate_totp"; secret: string; period?: number; digits?: number }
  | { op: "export_encrypted"; passphrase: string }
  | { op: "import_encrypted"; blob: number[] | Uint8Array; passphrase: string }
  | { op: "get_audit_log"; limit?: number }
  | { op: "sync_now" }
  /** Merge remote VaultSyncState CBOR then sync; returns contract blob to publish. */
  | { op: "sync_with_remote"; remote_state?: number[] | Uint8Array }
  | {
      op: "change_passphrase";
      current_passphrase: string;
      new_passphrase: string;
      kdf_profile?: KdfProfile;
    }
  | { op: "password_health" }
  | { op: "generate_recovery_key"; kdf_profile?: KdfProfile }
  | { op: "unlock_with_recovery"; recovery_key: string }
  | { op: "revoke_recovery_key" };

export type HealthKind =
  | "empty"
  | "too_short"
  | "weak_charset"
  | "reused"
  | "common_password";

export interface HealthIssue {
  kind: HealthKind;
  entry_id: string;
  entry_name: string;
  detail: string;
}

export interface HealthReport {
  total_entries: number;
  issue_count: number;
  score: number;
  issues: HealthIssue[];
  reused_groups: number;
  empty_count: number;
  weak_count: number;
}

export type VaultResponse =
  | { type: "ok" }
  | {
      type: "status";
      has_vault: boolean;
      unlocked: boolean;
      vault_id: string | null;
      has_recovery?: boolean;
    }
  | { type: "unlocked"; vault_id: string }
  | { type: "locked" }
  | { type: "summaries"; entries: EntrySummary[] }
  | { type: "entry"; entry: Entry }
  | { type: "folders"; folders: Folder[] }
  | { type: "password"; password: string }
  | { type: "totp"; code: string; seconds_remaining: number; period: number }
  | { type: "export"; blob: Uint8Array | number[] }
  | {
      type: "audit";
      events: { ts: number; kind: string; entry_id?: string; detail: string }[];
    }
  | {
      type: "synced";
      action: string;
      remote_revisions: number;
      detail: string;
      /** VaultSyncState CBOR for contract Put (may be empty). */
      contract_state?: number[] | Uint8Array;
      /** Owner Ed25519 verifying key (32) for VaultSyncParams. */
      owner_verifying_key?: number[] | Uint8Array;
    }
  | { type: "health"; report: HealthReport }
  | { type: "recovery_key"; recovery_key: string }
  | { type: "error"; code: string; message: string };

export function emptyEntry(): Entry {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: "",
    folder_id: null,
    name: "",
    urls: [],
    username: "",
    password: "",
    notes: "",
    custom_fields: [],
    tags: [],
    totp_secret: null,
    password_history: [],
    created_at: now,
    updated_at: now,
  };
}

export function emptyFolder(name = "New folder"): Folder {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: "",
    name,
    parent: null,
    created_at: now,
    updated_at: now,
  };
}

export const defaultGeneratorPolicy: GeneratorPolicy = {
  length: 20,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
  memorable: false,
  word_count: 5,
};

/** Seconds after copy before we try to clear the system clipboard. */
export const CLIPBOARD_CLEAR_SECONDS = 30;

export function randomFieldId(): string {
  const a = new Uint8Array(8);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Default idle seconds before auto-lock (unlocked vault). */
export const DEFAULT_AUTO_LOCK_SECONDS = 5 * 60;

const AUTO_LOCK_KEY = "aegis.settings.auto_lock_seconds";

export function getAutoLockSeconds(): number {
  const raw = storageGet(AUTO_LOCK_KEY);
  if (!raw) return DEFAULT_AUTO_LOCK_SECONDS;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 60) return DEFAULT_AUTO_LOCK_SECONDS;
  return Math.min(n, 60 * 60); // cap 1 hour
}

export function setAutoLockSeconds(secs: number): void {
  storageSet(AUTO_LOCK_KEY, String(Math.max(60, Math.min(secs, 3600))));
}
