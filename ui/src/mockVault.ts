/**
 * Local mock vault for UI development without Freenet.
 * Uses Web Crypto (AES-GCM) + PBKDF2 — NOT the production Argon2id path.
 * Production goes through the Rust vault-delegate.
 */

import type {
  Entry,
  EntrySummary,
  Folder,
  GeneratorPolicy,
  VaultRequest,
  VaultResponse,
} from "./messages";
import { storageGet, storageRemove, storageSet } from "./storage";
import { generateTotp } from "./totp";

interface VaultDoc {
  vault_id: string;
  entries: Record<string, Entry>;
  folders: Record<string, Folder>;
}

interface Stored {
  salt: number[];
  iv: number[];
  ciphertext: number[];
  vault_id: string;
}

const STORAGE_KEY = "aegis.mock.vault.v1";

function randomId(): string {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  // Copy into a plain ArrayBuffer-backed view for strict DOM lib typings.
  const saltBuf = new Uint8Array(salt);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuf, iterations: 100_000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(passphrase: string, doc: VaultDoc): Promise<Stored> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const pt = new TextEncoder().encode(JSON.stringify(doc));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
  return {
    salt: [...salt],
    iv: [...iv],
    ciphertext: [...ct],
    vault_id: doc.vault_id,
  };
}

async function open(passphrase: string, stored: Stored): Promise<VaultDoc> {
  const key = await deriveKey(passphrase, new Uint8Array(stored.salt));
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(stored.iv) },
      key,
      new Uint8Array(stored.ciphertext),
    );
    const doc = JSON.parse(new TextDecoder().decode(pt)) as VaultDoc;
    if (!doc.folders) doc.folders = {};
    return doc;
  } catch {
    throw new Error("auth failed");
  }
}

function entrySummary(e: Entry): EntrySummary {
  return {
    id: e.id,
    folder_id: e.folder_id,
    name: e.name,
    urls: e.urls,
    username: e.username,
    tags: e.tags,
    updated_at: e.updated_at,
    has_password: !!e.password,
    has_username: !!e.username,
    has_totp: !!(e.totp_secret && e.totp_secret.trim()),
    has_notes: !!(e.notes && e.notes.trim()),
    has_url: e.urls.some((u) => u.trim()),
    custom_field_count: e.custom_fields?.length ?? 0,
    has_history: !!(e.password_history && e.password_history.length),
  };
}

function mockChangedFields(a: Entry, b: Entry): string[] {
  const fields: string[] = [];
  if (a.name !== b.name) fields.push("name");
  if (a.username !== b.username) fields.push("username");
  if (a.password !== b.password) fields.push("password");
  if (a.notes !== b.notes) fields.push("notes");
  if (JSON.stringify(a.urls) !== JSON.stringify(b.urls)) fields.push("urls");
  if (JSON.stringify(a.tags) !== JSON.stringify(b.tags)) fields.push("tags");
  if (a.folder_id !== b.folder_id) fields.push("folder");
  if ((a.totp_secret ?? null) !== (b.totp_secret ?? null)) fields.push("totp");
  if (JSON.stringify(a.custom_fields) !== JSON.stringify(b.custom_fields))
    fields.push("custom_fields");
  if (JSON.stringify(a.password_history ?? []) !== JSON.stringify(b.password_history ?? []))
    fields.push("history");
  return fields;
}

function mockImportPreview(
  local: VaultDoc | null,
  backup: VaultDoc,
  note: string,
): VaultResponse {
  const only_local: EntrySummary[] = [];
  const only_backup: EntrySummary[] = [];
  const changed: {
    id: string;
    name: string;
    local_name: string;
    backup_name: string;
    fields: string[];
    local_updated_at: number;
    backup_updated_at: number;
    newer: string;
  }[] = [];
  let unchanged_count = 0;
  const folders_only_local: string[] = [];
  const folders_only_backup: string[] = [];

  if (local) {
    for (const [id, le] of Object.entries(local.entries)) {
      const be = backup.entries[id];
      if (!be) {
        only_local.push(entrySummary(le));
        continue;
      }
      const fields = mockChangedFields(le, be);
      if (!fields.length) {
        unchanged_count += 1;
      } else {
        changed.push({
          id,
          name: be.name || le.name,
          local_name: le.name,
          backup_name: be.name,
          fields,
          local_updated_at: le.updated_at,
          backup_updated_at: be.updated_at,
          newer:
            le.updated_at > be.updated_at
              ? "local"
              : le.updated_at < be.updated_at
                ? "backup"
                : "same",
        });
      }
    }
    for (const [id, be] of Object.entries(backup.entries)) {
      if (!local.entries[id]) only_backup.push(entrySummary(be));
    }
    for (const [id, lf] of Object.entries(local.folders ?? {})) {
      if (!backup.folders?.[id]) folders_only_local.push(lf.name);
    }
    for (const [id, bf] of Object.entries(backup.folders ?? {})) {
      if (!local.folders?.[id]) folders_only_backup.push(bf.name);
    }
    return {
      type: "import_preview",
      local_available: true,
      same_vault_id: local.vault_id === backup.vault_id,
      local_vault_id: local.vault_id,
      backup_vault_id: backup.vault_id,
      local_entry_count: Object.keys(local.entries).length,
      backup_entry_count: Object.keys(backup.entries).length,
      local_updated_at: null,
      backup_updated_at: 0,
      only_local,
      only_backup,
      changed,
      unchanged_count,
      folders_only_local,
      folders_only_backup,
      note,
    };
  }

  for (const be of Object.values(backup.entries)) only_backup.push(entrySummary(be));
  for (const bf of Object.values(backup.folders ?? {})) folders_only_backup.push(bf.name);
  return {
    type: "import_preview",
    local_available: false,
    same_vault_id: false,
    local_vault_id: null,
    backup_vault_id: backup.vault_id,
    local_entry_count: 0,
    backup_entry_count: Object.keys(backup.entries).length,
    local_updated_at: null,
    backup_updated_at: 0,
    only_local,
    only_backup,
    changed,
    unchanged_count: 0,
    folders_only_local,
    folders_only_backup,
    note,
  };
}

function generatePassword(policy: GeneratorPolicy): string {
  if (policy.memorable) {
    const words = ["alpha", "bravo", "coral", "delta", "ember", "flint", "grove", "harbor"];
    const parts: string[] = [];
    for (let i = 0; i < Math.max(3, policy.word_count); i++) {
      const w = words[Math.floor(Math.random() * words.length)];
      parts.push(`${w}${Math.floor(Math.random() * 10)}`);
    }
    return parts.join("-");
  }
  let set = "";
  if (policy.uppercase) set += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (policy.lowercase) set += "abcdefghijkmnopqrstuvwxyz";
  if (policy.digits) set += "23456789";
  if (policy.symbols) set += "!@#$%^&*()-_=+";
  if (!set) set = "abcdefghijkmnopqrstuvwxyz";
  const len = Math.min(128, Math.max(8, policy.length));
  const out: string[] = [];
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  for (let i = 0; i < len; i++) out.push(set[buf[i]! % set.length]!);
  return out.join("");
}

const RECOVERY_KEY = "aegis.mock.recovery.v1";

export class MockVaultClient {
  readonly label = "mock vault";
  private passphrase: string | null = null;
  private doc: VaultDoc | null = null;

  async request(req: VaultRequest): Promise<VaultResponse> {
    try {
      switch (req.op) {
        case "status": {
          const raw = storageGet(STORAGE_KEY);
          return {
            type: "status",
            has_vault: !!raw,
            unlocked: !!this.doc,
            vault_id: this.doc?.vault_id ?? null,
            has_recovery: !!storageGet(RECOVERY_KEY),
          };
        }
        case "create_vault": {
          if (storageGet(STORAGE_KEY)) {
            return { type: "error", code: "already_exists", message: "vault already exists" };
          }
          this.doc = { vault_id: randomId(), entries: {}, folders: {} };
          this.passphrase = req.passphrase;
          await this.persist();
          return { type: "unlocked", vault_id: this.doc.vault_id };
        }
        case "unlock": {
          const raw = storageGet(STORAGE_KEY);
          if (!raw) return { type: "error", code: "not_found", message: "no vault" };
          const stored = JSON.parse(raw) as Stored;
          this.doc = await open(req.passphrase, stored);
          this.passphrase = req.passphrase;
          return { type: "unlocked", vault_id: this.doc.vault_id };
        }
        case "lock": {
          this.doc = null;
          this.passphrase = null;
          return { type: "locked" };
        }
        case "list_summaries": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          const q = req.query?.toLowerCase();
          let entries: EntrySummary[] = Object.values(this.doc.entries).map((e) => ({
            id: e.id,
            folder_id: e.folder_id,
            name: e.name,
            urls: e.urls,
            username: e.username,
            tags: e.tags,
            updated_at: e.updated_at,
            has_password: Boolean(e.password),
            has_username: Boolean(e.username),
            has_totp: Boolean(e.totp_secret?.trim()),
            has_notes: Boolean(e.notes?.trim()),
            has_url: (e.urls ?? []).some((u) => u.trim()),
            custom_field_count: e.custom_fields?.length ?? 0,
            has_history: (e.password_history?.length ?? 0) > 0,
          }));
          if (q) {
            entries = entries.filter(
              (e) =>
                e.name.toLowerCase().includes(q) ||
                e.username.toLowerCase().includes(q) ||
                e.urls.some((u) => u.toLowerCase().includes(q)),
            );
          }
          entries.sort((a, b) => a.name.localeCompare(b.name));
          return { type: "summaries", entries };
        }
        case "get_entry": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          const entry = this.doc.entries[req.id];
          if (!entry) return { type: "error", code: "not_found", message: "not found" };
          return { type: "entry", entry };
        }
        case "upsert_entry": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          const entry = { ...req.entry };
          if (!entry.id) entry.id = randomId();
          entry.updated_at = Math.floor(Date.now() / 1000);
          if (!entry.created_at) entry.created_at = entry.updated_at;
          this.doc.entries[entry.id] = entry;
          await this.persist();
          return { type: "ok" };
        }
        case "delete_entry": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          delete this.doc.entries[req.id];
          await this.persist();
          return { type: "ok" };
        }
        case "generate_password": {
          const policy = req.policy ?? {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            memorable: false,
            word_count: 5,
          };
          return { type: "password", password: generatePassword(policy) };
        }
        case "generate_totp": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          try {
            const { code, secondsRemaining } = await generateTotp(
              req.secret,
              Math.floor(Date.now() / 1000),
              req.period ?? 30,
              req.digits ?? 6,
            );
            return {
              type: "totp",
              code,
              seconds_remaining: secondsRemaining,
              period: req.period ?? 30,
            };
          } catch (e) {
            return {
              type: "error",
              code: "invalid_request",
              message: e instanceof Error ? e.message : "totp failed",
            };
          }
        }
        case "list_folders": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          const folders = Object.values(this.doc.folders).sort((a, b) =>
            a.name.localeCompare(b.name),
          );
          return { type: "folders", folders };
        }
        case "upsert_folder": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          const folder = { ...req.folder };
          if (!folder.id) folder.id = randomId();
          folder.updated_at = Math.floor(Date.now() / 1000);
          if (!folder.created_at) folder.created_at = folder.updated_at;
          this.doc.folders[folder.id] = folder;
          await this.persist();
          return { type: "ok" };
        }
        case "delete_folder": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          delete this.doc.folders[req.id];
          for (const e of Object.values(this.doc.entries)) {
            if (e.folder_id === req.id) e.folder_id = null;
          }
          await this.persist();
          return { type: "ok" };
        }
        case "export_encrypted": {
          if (!this.doc || !this.passphrase) {
            return { type: "error", code: "locked", message: "locked" };
          }
          const stored = await seal(req.passphrase, this.doc);
          const blob = new TextEncoder().encode(JSON.stringify(stored));
          return { type: "export", blob: [...blob] };
        }
        case "import_encrypted": {
          if (storageGet(STORAGE_KEY) && !req.replace) {
            return {
              type: "error",
              code: "already_exists",
              message: "vault already exists (use replace to overwrite)",
            };
          }
          try {
            const raw = req.blob instanceof Uint8Array ? req.blob : new Uint8Array(req.blob);
            const stored = JSON.parse(new TextDecoder().decode(raw)) as Stored;
            this.doc = await open(req.passphrase, stored);
            this.passphrase = req.passphrase;
            await this.persist();
            return { type: "unlocked", vault_id: this.doc.vault_id };
          } catch {
            return { type: "error", code: "auth_failed", message: "import failed (wrong passphrase or bad file)" };
          }
        }
        case "preview_import": {
          try {
            const raw = req.blob instanceof Uint8Array ? req.blob : new Uint8Array(req.blob);
            const stored = JSON.parse(new TextDecoder().decode(raw)) as Stored;
            const backup = await open(req.passphrase, stored);
            let local: VaultDoc | null = this.doc;
            let note = "";
            if (!local) {
              const rawLocal = storageGet(STORAGE_KEY);
              if (rawLocal) {
                try {
                  const tryPw =
                    req.local_passphrase && req.local_passphrase.length > 0
                      ? req.local_passphrase
                      : req.passphrase;
                  local = await open(tryPw, JSON.parse(rawLocal) as Stored);
                } catch {
                  note =
                    "Could not open the local vault for comparison. Enter the local master passphrase if it differs from the export passphrase.";
                  local = null;
                }
              } else {
                note = "No local vault — this is a fresh import.";
              }
            }
            return mockImportPreview(local, backup, note);
          } catch {
            return {
              type: "error",
              code: "auth_failed",
              message: "preview failed (wrong passphrase or bad file)",
            };
          }
        }
        case "get_audit_log":
          return { type: "audit", events: [] };
        case "sync_now":
        case "sync_with_remote":
          return {
            type: "error",
            code: "not_implemented",
            message: "sync requires dev vault (rust) or freenet mode",
          };
        case "change_passphrase": {
          if (!this.doc || !this.passphrase) {
            return { type: "error", code: "locked", message: "locked" };
          }
          if (req.current_passphrase !== this.passphrase) {
            return { type: "error", code: "auth_failed", message: "current passphrase incorrect" };
          }
          if (req.new_passphrase.length < 8) {
            return {
              type: "error",
              code: "invalid_request",
              message: "new passphrase must be at least 8 characters",
            };
          }
          this.passphrase = req.new_passphrase;
          await this.persist();
          return { type: "ok" };
        }
        case "generate_recovery_key": {
          if (!this.doc || !this.passphrase) {
            return { type: "error", code: "locked", message: "locked" };
          }
          const parts: string[] = [];
          const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
          const buf = new Uint8Array(20);
          crypto.getRandomValues(buf);
          // rough base32
          let bits = 0;
          let nbits = 0;
          let b32 = "";
          for (const b of buf) {
            bits = (bits << 8) | b;
            nbits += 8;
            while (nbits >= 5) {
              nbits -= 5;
              b32 += alphabet[(bits >> nbits) & 31];
            }
          }
          for (let i = 0; i < 32; i += 4) parts.push(b32.slice(i, i + 4));
          const recovery_key = `AEGIS-${parts.join("-")}`;
          const norm = recovery_key
            .replace(/[^a-zA-Z0-9]/g, "")
            .toUpperCase()
            .replace(/^AEGIS/, "");
          storageSet(RECOVERY_KEY, norm);
          // Mock-only: remember current passphrase so recovery can re-open the AES blob.
          if (this.passphrase) storageSet(RECOVERY_KEY + ".pw", this.passphrase);
          return { type: "recovery_key", recovery_key };
        }
        case "unlock_with_recovery": {
          const stored = storageGet(RECOVERY_KEY);
          const norm = req.recovery_key
            .replace(/[^a-zA-Z0-9]/g, "")
            .toUpperCase()
            .replace(/^AEGIS/, "");
          if (!stored || stored !== norm) {
            return { type: "error", code: "auth_failed", message: "invalid recovery key" };
          }
          const raw = storageGet(STORAGE_KEY);
          if (!raw) return { type: "error", code: "not_found", message: "no vault" };
          // Mock: recovery unlock requires we still know passphrase from last session —
          // store a parallel encrypted blob keyed by recovery is complex; for mock,
          // we keep the vault openable if recovery matches by re-using stored cipher
          // with a fixed recovery-derived path: store passphrase under recovery in memory only.
          // Simpler: mock stores JSON {recoveryNorm, passphrase} encrypted is overkill —
          // store recovery maps to last passphrase in localStorage for mock only.
          const pair = storageGet(RECOVERY_KEY + ".pw");
          if (!pair) {
            return {
              type: "error",
              code: "internal",
              message: "mock recovery: generate recovery while unlocked first",
            };
          }
          this.doc = await open(pair, JSON.parse(raw));
          this.passphrase = pair;
          return { type: "unlocked", vault_id: this.doc.vault_id };
        }
        case "revoke_recovery_key": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          storageRemove(RECOVERY_KEY);
          storageRemove(RECOVERY_KEY + ".pw");
          return { type: "ok" };
        }
        case "password_health": {
          if (!this.doc) return { type: "error", code: "locked", message: "locked" };
          const entries = Object.values(this.doc.entries);
          const issues: {
            kind: string;
            entry_id: string;
            entry_name: string;
            detail: string;
          }[] = [];
          let empty_count = 0;
          let weak_count = 0;
          const byPw = new Map<string, Entry[]>();
          for (const e of entries) {
            if (!e.password) {
              empty_count++;
              issues.push({
                kind: "empty",
                entry_id: e.id,
                entry_name: e.name,
                detail: "no password set",
              });
              continue;
            }
            if (e.password.length < 10) {
              weak_count++;
              issues.push({
                kind: "too_short",
                entry_id: e.id,
                entry_name: e.name,
                detail: `only ${e.password.length} characters`,
              });
            }
            const list = byPw.get(e.password) ?? [];
            list.push(e);
            byPw.set(e.password, list);
          }
          let reused_groups = 0;
          for (const group of byPw.values()) {
            if (group.length < 2) continue;
            reused_groups++;
            const names = group.map((g) => g.name).join(", ");
            for (const e of group) {
              issues.push({
                kind: "reused",
                entry_id: e.id,
                entry_name: e.name,
                detail: `same password as: ${names}`,
              });
            }
          }
          let score = 100 - empty_count * 15 - weak_count * 8 - reused_groups * 12;
          score = Math.max(0, Math.min(100, score));
          return {
            type: "health",
            report: {
              total_entries: entries.length,
              issue_count: issues.length,
              score,
              issues: issues as never,
              reused_groups,
              empty_count,
              weak_count,
            },
          };
        }
        default:
          return { type: "error", code: "not_implemented", message: "unknown op" };
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("auth")) {
        return { type: "error", code: "auth_failed", message: "wrong passphrase" };
      }
      return { type: "error", code: "internal", message: msg };
    }
  }

  private async persist(): Promise<void> {
    if (!this.doc || !this.passphrase) return;
    const stored = await seal(this.passphrase, this.doc);
    storageSet(STORAGE_KEY, JSON.stringify(stored));
  }
}
