import { createVaultClient, type VaultClient } from "./client";
import {
  CLIPBOARD_CLEAR_SECONDS,
  defaultGeneratorPolicy,
  emptyEntry,
  emptyFolder,
  getAutoLockSeconds,
  randomFieldId,
  setAutoLockSeconds,
  type Entry,
  type EntrySummary,
  type Folder,
  type GeneratorPolicy,
  type HealthReport,
} from "./messages";
import { storageGet, storageSet } from "./storage";
import { generateTotp } from "./totp";

const app = document.querySelector<HTMLDivElement>("#app")!;

let client: VaultClient;
let unlocked = false;
let modeLabel = "…";
let idleTimer: ReturnType<typeof setTimeout> | null = null;
let lastActivity = Date.now();
let clipboardClearTimer: ReturnType<typeof setTimeout> | null = null;
/** Last value we wrote to the clipboard (only clear if still matches). */
let lastCopiedSecret: string | null = null;
/** Set when vault was unlocked via recovery key — nudge user to set a new passphrase. */
let unlockedViaRecovery = false;

async function initClient() {
  client = await createVaultClient();
  modeLabel = client.label;
}

function touchActivity() {
  lastActivity = Date.now();
  if (!unlocked) return;
  if (idleTimer) clearTimeout(idleTimer);
  const secs = getAutoLockSeconds();
  idleTimer = setTimeout(() => {
    void (async () => {
      if (!unlocked) return;
      const idle = (Date.now() - lastActivity) / 1000;
      if (idle < secs - 1) return;
      await client.request({ op: "lock" });
      unlocked = false;
      await render();
    })();
  }, secs * 1000);
}

function armAutoLock() {
  ["pointerdown", "keydown", "mousemove", "touchstart"].forEach((ev) => {
    window.addEventListener(ev, touchActivity, { passive: true });
  });
  touchActivity();
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function setError(container: HTMLElement, msg: string | null) {
  const existing = container.querySelector(".error");
  existing?.remove();
  if (msg) container.prepend(el("p", { class: "error", text: msg }));
}

/** Legacy copy path when Clipboard API is unavailable or blocked. */
function copyViaTextarea(value: string): boolean {
  const ta = document.createElement("textarea");
  ta.value = value;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  ta.style.top = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, value.length);
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}

/**
 * Copy a secret. Feedback is shown on `feedbackEl` (near the Copy control).
 * Clipboard is cleared silently after CLIPBOARD_CLEAR_SECONDS when possible.
 */
async function copySecret(
  value: string,
  label: string,
  feedbackEl?: HTMLElement,
): Promise<void> {
  const flash = (text: string, ok = true) => {
    if (!feedbackEl) return;
    feedbackEl.textContent = text;
    feedbackEl.classList.toggle("copy-feedback-ok", ok);
    feedbackEl.classList.toggle("copy-feedback-err", !ok);
    feedbackEl.hidden = false;
    window.setTimeout(() => {
      if (feedbackEl.textContent === text) {
        feedbackEl.textContent = "";
        feedbackEl.hidden = true;
      }
    }, 2000);
  };

  if (!value) {
    flash(`${label} is empty`, false);
    return;
  }

  let ok = false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      ok = true;
    }
  } catch {
    ok = false;
  }
  if (!ok) {
    ok = copyViaTextarea(value);
  }
  if (!ok) {
    flash("Copy failed", false);
    return;
  }

  lastCopiedSecret = value;
  flash("Copied");

  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = setTimeout(() => {
    void (async () => {
      try {
        if (navigator.clipboard?.readText && navigator.clipboard?.writeText) {
          const current = await navigator.clipboard.readText();
          if (lastCopiedSecret != null && current === lastCopiedSecret) {
            await navigator.clipboard.writeText("");
          }
        }
      } catch {
        // ignore
      }
      lastCopiedSecret = null;
      clipboardClearTimer = null;
    })();
  }, CLIPBOARD_CLEAR_SECONDS * 1000);
}

function showGeneratorPopover(
  anchor: HTMLElement,
  onPick: (password: string) => void,
): void {
  document.querySelector(".gen-popover")?.remove();

  const pop = el("div", { class: "gen-popover card" });
  pop.append(el("strong", { text: "Password generator" }));

  let policy: GeneratorPolicy = { ...defaultGeneratorPolicy };

  const length = el("input", {
    type: "range",
    min: "8",
    max: "64",
    value: String(policy.length),
  }) as HTMLInputElement;
  const lengthLabel = el("span", {
    class: "meta",
    text: `${policy.length} characters`,
  });
  length.addEventListener("input", () => {
    policy.length = Number(length.value);
    lengthLabel.textContent = `${policy.length} characters`;
  });

  const mkCheck = (key: keyof GeneratorPolicy, label: string, checked: boolean) => {
    const row = el("label", { class: "check-row" });
    const cb = el("input", { type: "checkbox" }) as HTMLInputElement;
    cb.checked = checked;
    cb.addEventListener("change", () => {
      (policy as unknown as Record<string, boolean | number>)[key as string] = cb.checked;
    });
    row.append(cb, document.createTextNode(` ${label}`));
    return row;
  };

  const memorable = mkCheck("memorable", "Memorable passphrase", false);
  const upper = mkCheck("uppercase", "Uppercase", true);
  const lower = mkCheck("lowercase", "Lowercase", true);
  const digits = mkCheck("digits", "Digits", true);
  const symbols = mkCheck("symbols", "Symbols", true);

  const preview = el("input", {
    type: "text",
    class: "mono",
    readonly: "true",
    value: "",
  }) as HTMLInputElement;

  const refresh = async () => {
    // Re-read memorable from checkbox (handler uses generic assign)
    const memCb = memorable.querySelector("input") as HTMLInputElement;
    policy.memorable = memCb.checked;
    policy.uppercase = (upper.querySelector("input") as HTMLInputElement).checked;
    policy.lowercase = (lower.querySelector("input") as HTMLInputElement).checked;
    policy.digits = (digits.querySelector("input") as HTMLInputElement).checked;
    policy.symbols = (symbols.querySelector("input") as HTMLInputElement).checked;
    policy.length = Number(length.value);
    const r = await client.request({ op: "generate_password", policy });
    if (r.type === "password") preview.value = r.password;
  };

  const regen = el("button", { text: "Regenerate" }) as HTMLButtonElement;
  regen.addEventListener("click", () => void refresh());
  const use = el("button", { class: "primary", text: "Use password" }) as HTMLButtonElement;
  use.addEventListener("click", () => {
    if (preview.value) onPick(preview.value);
    pop.remove();
  });
  const close = el("button", { text: "Close" }) as HTMLButtonElement;
  close.addEventListener("click", () => pop.remove());

  pop.append(
    el("div", { class: "gen-row" }, [length, lengthLabel]),
    memorable,
    upper,
    lower,
    digits,
    symbols,
    el("label", { text: "Preview" }),
    preview,
    el("div", { class: "row", style: "margin-top:0.5rem" }, [regen, use, close]),
  );

  // Position near anchor within the detail panel
  const host = anchor.closest(".card") ?? document.body;
  (host as HTMLElement).style.position = "relative";
  host.append(pop);
  void refresh();
}

/** Default KDF for the active backend (browser WASM prefers lighter Mobile). */
function defaultKdfProfile(): "test" | "mobile" | "interactive" {
  if (modeLabel.includes("mock")) return "test";
  if (modeLabel.includes("browser")) return "mobile";
  return "interactive";
}

function modeHint(): string {
  if (modeLabel.includes("dev")) {
    return "Using the local Rust vault server (real Argon2id + XChaCha20-Poly1305).";
  }
  if (modeLabel.includes("freenet")) {
    return "Using Freenet vault-delegate (optional production path — requires a Freenet peer).";
  }
  if (modeLabel.includes("browser")) {
    return "Browser vault: real Argon2id + XChaCha20 in WASM, sealed secrets in IndexedDB. No Freenet peer required. Use ?mode=freenet if you run Freenet.";
  }
  if (modeLabel.includes("mock")) {
    return "Legacy mock vault (not production crypto). Prefer default browser mode.";
  }
  return "Select a mode below.";
}

async function render() {
  app.innerHTML = "";
  const header = el("header", { class: "app-header" }, [
    el("h1", {}, ["Aegis ", el("span", { text: "Password Manager" })]),
    el("span", { class: "badge", text: modeLabel }),
  ]);
  app.append(header);

  const status = await client.request({ op: "status" });
  if (status.type === "error") {
    app.append(el("p", { class: "error", text: status.message }));
    app.append(el("p", { class: "hint", text: modeHint() }));
    app.append(modeLinks());
    return;
  }
  if (status.type !== "status") return;

  unlocked = status.unlocked;

  if (!status.has_vault) {
    renderCreate();
    return;
  }
  if (!unlocked) {
    if (idleTimer) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }
    renderUnlock();
    return;
  }
  armAutoLock();
  if (unlockedViaRecovery) {
    const banner = el("div", { class: "banner banner-warn" });
    banner.append(
      el("div", {}, [
        el("strong", { text: "Unlocked with recovery key. " }),
        el("span", {
          text: "Set a new master passphrase so you can unlock without the recovery key.",
        }),
      ]),
    );
    const openSettings = el("button", {
      class: "primary",
      text: "Change passphrase",
    }) as HTMLButtonElement;
    const dismiss = el("button", { text: "Dismiss" }) as HTMLButtonElement;
    openSettings.addEventListener("click", () => {
      showSettingsModal(() => {
        /* auto-lock refresh */
      }, "passphrase");
    });
    dismiss.addEventListener("click", () => {
      unlockedViaRecovery = false;
      banner.remove();
    });
    banner.append(el("div", { class: "banner-actions" }, [openSettings, dismiss]));
    app.append(banner);
  }
  await renderVault();
}

function modeLinks(): HTMLElement {
  const row = el("p", { class: "hint" }, [
    "Modes: ",
    el("a", { href: "?mode=browser", text: "browser" }),
    " · ",
    el("a", { href: "?mode=freenet", text: "freenet" }),
    " · ",
    el("a", { href: "?mode=dev", text: "dev (Rust)" }),
    " · ",
    el("a", { href: "?mode=mock", text: "mock" }),
  ]);
  return row;
}

function renderCreate() {
  const card = el("div", { class: "card" });
  card.append(el("h2", { text: "Create vault" }));
  card.append(el("p", { class: "hint", text: modeHint() }));
  card.append(modeLinks());

  const pw = el("input", {
    type: "password",
    id: "pw",
    autocomplete: "new-password",
    placeholder: "Master passphrase",
  }) as HTMLInputElement;
  const pw2 = el("input", {
    type: "password",
    id: "pw2",
    autocomplete: "new-password",
    placeholder: "Confirm passphrase",
  }) as HTMLInputElement;

  const btn = el("button", { class: "primary", text: "Create vault" }) as HTMLButtonElement;
  btn.addEventListener("click", async () => {
    setError(card, null);
    if (pw.value.length < 8) {
      setError(card, "Use at least 8 characters (longer is much better).");
      return;
    }
    if (pw.value !== pw2.value) {
      setError(card, "Passphrases do not match.");
      return;
    }
    btn.disabled = true;
    // Mock: fast test KDF. Browser WASM: Mobile (lighter). Native/Freenet: Interactive.
    const kdf_profile = modeLabel.includes("mock")
      ? "test"
      : modeLabel.includes("browser")
        ? "mobile"
        : "interactive";
    const resp = await client.request({
      op: "create_vault",
      passphrase: pw.value,
      kdf_profile,
    });
    btn.disabled = false;
    if (resp.type === "error") {
      setError(card, resp.message);
      return;
    }
    await render();
  });

  card.append(el("label", { text: "Master passphrase" }), pw);
  card.append(el("label", { text: "Confirm" }), pw2);
  card.append(btn);

  // Import encrypted backup
  const importCard = el("div", { class: "card" });
  importCard.append(el("h2", { text: "Import backup" }));
  importCard.append(
    el("p", {
      class: "hint",
      text: "Restore an .aegis encrypted export into this empty vault store.",
    }),
  );
  const fileInput = el("input", {
    type: "file",
    accept: ".aegis,application/octet-stream",
  }) as HTMLInputElement;
  const importPw = el("input", {
    type: "password",
    placeholder: "Export passphrase",
    autocomplete: "off",
  }) as HTMLInputElement;
  const importBtn = el("button", { text: "Import" }) as HTMLButtonElement;
  importBtn.addEventListener("click", async () => {
    setError(importCard, null);
    const file = fileInput.files?.[0];
    if (!file) {
      setError(importCard, "Choose a backup file first.");
      return;
    }
    if (!importPw.value) {
      setError(importCard, "Enter the passphrase used when exporting.");
      return;
    }
    importBtn.disabled = true;
    const buf = new Uint8Array(await file.arrayBuffer());
    const resp = await client.request({
      op: "import_encrypted",
      blob: buf,
      passphrase: importPw.value,
    });
    importBtn.disabled = false;
    if (resp.type === "error") {
      setError(importCard, resp.message);
      return;
    }
    await render();
  });
  importCard.append(el("label", { text: "Backup file" }), fileInput);
  importCard.append(el("label", { text: "Passphrase" }), importPw);
  importCard.append(importBtn);

  app.append(card, importCard);
}

function renderUnlock() {
  const card = el("div", { class: "card" });
  card.append(el("h2", { text: "Unlock vault" }));
  card.append(el("p", { class: "hint", text: modeHint() }));
  const pw = el("input", {
    type: "password",
    autocomplete: "current-password",
    placeholder: "Master passphrase",
  }) as HTMLInputElement;
  const btn = el("button", { class: "primary", text: "Unlock" }) as HTMLButtonElement;
  const submit = async () => {
    setError(card, null);
    btn.disabled = true;
    const resp = await client.request({ op: "unlock", passphrase: pw.value });
    btn.disabled = false;
    if (resp.type === "error") {
      setError(card, resp.message);
      return;
    }
    unlockedViaRecovery = false;
    await render();
  };
  btn.addEventListener("click", submit);
  pw.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void submit();
  });
  card.append(el("label", { text: "Master passphrase" }), pw, btn);

  // Recovery unlock
  const recCard = el("div", { class: "card" });
  recCard.append(el("h2", { text: "Unlock with recovery key" }));
  recCard.append(
    el("p", {
      class: "hint",
      text: "If you lost your master passphrase but saved a recovery key, paste it here.",
    }),
  );
  const rec = el("input", {
    type: "text",
    placeholder: "AEGIS-XXXX-XXXX-…",
    autocomplete: "off",
    spellcheck: "false",
    class: "mono",
  }) as HTMLInputElement;
  const recBtn = el("button", { text: "Unlock with recovery key" }) as HTMLButtonElement;
  recBtn.addEventListener("click", async () => {
    setError(recCard, null);
    if (!rec.value.trim()) {
      setError(recCard, "Enter your recovery key.");
      return;
    }
    recBtn.disabled = true;
    const resp = await client.request({
      op: "unlock_with_recovery",
      recovery_key: rec.value.trim(),
    });
    recBtn.disabled = false;
    if (resp.type === "error") {
      setError(recCard, resp.message);
      return;
    }
    unlockedViaRecovery = true;
    await render();
  });
  recCard.append(el("label", { text: "Recovery key" }), rec, recBtn);

  app.append(card, recCard);
}

const CONTRACT_STATE_KEY = "aegis.vaultSyncState";
const CONTRACT_VK_KEY = "aegis.vaultSyncOwnerVk";

function toBytes(raw: number[] | Uint8Array | undefined | null): Uint8Array {
  if (!raw) return new Uint8Array(0);
  if (raw instanceof Uint8Array) return raw;
  return new Uint8Array(raw);
}

/** Last VaultSync MVR from SyncWithRemote (bridge until contract Put is live). */
function loadCachedContractState(): Uint8Array {
  try {
    const b64 = storageGet(CONTRACT_STATE_KEY);
    if (!b64) return new Uint8Array(0);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}

function cacheContractState(state: Uint8Array, ownerVk: Uint8Array) {
  try {
    let s = "";
    for (let i = 0; i < state.length; i++) s += String.fromCharCode(state[i]!);
    storageSet(CONTRACT_STATE_KEY, btoa(s));
    if (ownerVk.length > 0) {
      let v = "";
      for (let i = 0; i < ownerVk.length; i++) v += String.fromCharCode(ownerVk[i]!);
      storageSet(CONTRACT_VK_KEY, btoa(v));
    }
  } catch (e) {
    console.warn("[aegis] could not cache contract state", e);
  }
}

/** Split comma/semicolon/whitespace-ish label text into unique tags. */
function parseTags(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of raw.split(/[,;]+/)) {
    const t = part.trim();
    if (!t) continue;
    const key = t.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}

function collectTags(summaries: EntrySummary[]): string[] {
  const map = new Map<string, string>(); // lower → display
  for (const e of summaries) {
    for (const t of e.tags ?? []) {
      const key = t.trim().toLowerCase();
      if (!key) continue;
      if (!map.has(key)) map.set(key, t.trim());
    }
  }
  return [...map.values()].sort((a, b) => a.localeCompare(b));
}

function tagMatches(entryTags: string[] | undefined, filter: string): boolean {
  const want = filter.toLowerCase();
  return (entryTags ?? []).some((t) => t.toLowerCase() === want);
}

/** Content-feature chips for the entry list (flags only — no secrets).
 *  Username is omitted: it already appears in the meta line. */
function entryFeaturePills(
  e: EntrySummary,
): { key: string; label: string; title: string }[] {
  const pills: { key: string; label: string; title: string }[] = [];
  const hasUrl =
    e.has_url ?? (e.urls ?? []).some((u) => Boolean(u?.trim()));
  const fieldCount = e.custom_field_count ?? 0;

  if (e.has_password) {
    pills.push({ key: "password", label: "Password", title: "Has password" });
  }
  if (e.has_totp) {
    pills.push({
      key: "totp",
      label: "2FA",
      title: "Authenticator (TOTP) configured",
    });
  }
  if (hasUrl) {
    pills.push({ key: "url", label: "URL", title: "Has website URL" });
  }
  if (e.has_notes) {
    pills.push({ key: "notes", label: "Note", title: "Has notes" });
  }
  if (fieldCount > 0) {
    pills.push({
      key: "fields",
      label: fieldCount === 1 ? "1 field" : `${fieldCount} fields`,
      title: `${fieldCount} custom field${fieldCount === 1 ? "" : "s"}`,
    });
  }
  if (e.has_history) {
    pills.push({
      key: "history",
      label: "History",
      title: "Password history available",
    });
  }
  return pills;
}

async function renderVault() {
  let folders: Folder[] = [];
  /** null = all, "" = uncategorized, id = folder */
  let folderFilter: string | null = null;
  /** null = all labels; otherwise exact tag (case-insensitive) */
  let tagFilter: string | null = null;
  let allSummaries: EntrySummary[] = [];
  let totpInterval: ReturnType<typeof setInterval> | null = null;

  const toolbar = el("div", { class: "toolbar" });
  const search = el("input", {
    type: "search",
    placeholder: "Search…",
    style: "flex:2;margin:0",
  }) as HTMLInputElement;
  const lockBtn = el("button", { text: "Lock" }) as HTMLButtonElement;
  const exportBtn = el("button", { text: "Export" }) as HTMLButtonElement;
  const auditBtn = el("button", { text: "Audit" }) as HTMLButtonElement;
  const healthBtn = el("button", { text: "Health" }) as HTMLButtonElement;
  const settingsBtn = el("button", { text: "Settings" }) as HTMLButtonElement;
  const syncBtn = el("button", { text: "Sync" }) as HTMLButtonElement;
  const newBtn = el("button", { class: "primary", text: "New entry" }) as HTMLButtonElement;
  const lockMins = Math.round(getAutoLockSeconds() / 60);
  const statusLine = el("p", {
    class: "hint",
    id: "status-line",
    text: `Auto-lock after ${lockMins} min idle`,
  });

  const clearTotpTimer = () => {
    if (totpInterval) {
      clearInterval(totpInterval);
      totpInterval = null;
    }
  };

  lockBtn.addEventListener("click", async () => {
    clearTotpTimer();
    await client.request({ op: "lock" });
    await render();
  });

  exportBtn.addEventListener("click", async () => {
    const passphrase = window.prompt(
      "Passphrase to encrypt the export file (can match your master passphrase):",
    );
    if (!passphrase) return;
    const resp = await client.request({ op: "export_encrypted", passphrase });
    if (resp.type !== "export") {
      window.alert(resp.type === "error" ? resp.message : "Export failed");
      return;
    }
    const bytes =
      resp.blob instanceof Uint8Array
        ? new Uint8Array(resp.blob)
        : new Uint8Array(resp.blob);
    const blob = new Blob([bytes.buffer], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-backup-${new Date().toISOString().slice(0, 10)}.aegis`;
    a.click();
    URL.revokeObjectURL(url);
  });

  auditBtn.addEventListener("click", async () => {
    const resp = await client.request({ op: "get_audit_log", limit: 50 });
    if (resp.type !== "audit") {
      window.alert(resp.type === "error" ? resp.message : "Audit log unavailable");
      return;
    }
    if (resp.events.length === 0) {
      window.alert("No audit events yet.");
      return;
    }
    const lines = resp.events
      .slice()
      .reverse()
      .map((e) => {
        const t = new Date(e.ts * 1000).toISOString().replace("T", " ").slice(0, 19);
        return `${t}  ${e.kind}${e.entry_id ? `  ${e.entry_id.slice(0, 8)}` : ""}  ${e.detail}`;
      })
      .join("\n");
    window.alert(lines);
  });

  syncBtn.addEventListener("click", async () => {
    syncBtn.disabled = true;
    statusLine.textContent = "Syncing…";
    // Freenet path: feed last contract blob (if any) into SyncWithRemote so
    // multi-device MVR can converge; store returned blob for publish / other devices.
    const useRemote =
      client.label.includes("freenet") ||
      new URLSearchParams(location.search).get("mode") === "freenet";
    let resp;
    if (useRemote) {
      const cached = loadCachedContractState();
      resp = await client.request({
        op: "sync_with_remote",
        remote_state: cached,
      });
    } else {
      resp = await client.request({ op: "sync_now" });
    }
    syncBtn.disabled = false;
    if (resp.type === "error") {
      statusLine.textContent = `Sync: ${resp.message}`;
      return;
    }
    if (resp.type === "synced") {
      const blob = toBytes(resp.contract_state);
      const vk = toBytes(resp.owner_verifying_key);
      if (blob.length > 0) {
        cacheContractState(blob, vk);
      }
      const netNote =
        blob.length > 0
          ? " · contract blob ready (see docs/PUBLISH.md)"
          : "";
      statusLine.textContent = `Sync: ${resp.action} — ${resp.detail} (${resp.remote_revisions} rev)${netNote}`;
      await refreshList();
      await refreshFolders();
      return;
    }
    statusLine.textContent = "Sync finished.";
  });

  healthBtn.addEventListener("click", async () => {
    statusLine.textContent = "Analyzing passwords…";
    const resp = await client.request({ op: "password_health" });
    if (resp.type !== "health") {
      statusLine.textContent =
        resp.type === "error" ? resp.message : "Health check failed";
      return;
    }
    showHealthModal(resp.report, async (entryId) => {
      const r = await client.request({ op: "get_entry", id: entryId });
      if (r.type === "entry") renderEditor(r.entry, false);
    });
    statusLine.textContent = `Health score: ${resp.report.score}/100 (${resp.report.issue_count} issues)`;
  });

  settingsBtn.addEventListener("click", () => {
    showSettingsModal(async () => {
      statusLine.textContent = `Auto-lock after ${Math.round(getAutoLockSeconds() / 60)} min idle`;
      touchActivity();
    });
  });

  toolbar.append(search, newBtn, syncBtn, exportBtn, healthBtn, settingsBtn, auditBtn, lockBtn);
  app.append(toolbar);
  app.append(statusLine);

  // Layout: folders | entries | detail
  const layout = el("div", { class: "vault-layout" });
  const folderCard = el("div", { class: "card folder-panel" });
  folderCard.append(el("h2", { text: "Folders" }));
  const folderList = el("ul", { class: "folder-list" });
  const addFolderBtn = el("button", {
    text: "+ Folder",
    style: "width:100%;margin-top:0.5rem",
  }) as HTMLButtonElement;
  folderCard.append(folderList, addFolderBtn);

  const listCard = el("div", { class: "card" });
  listCard.append(el("h2", { text: "Entries" }));
  const tagFilterRow = el("div", { class: "tag-filter-row" });
  const tagFilterSelect = el("select", {
    class: "tag-filter-select",
    title: "Filter by label",
  }) as HTMLSelectElement;
  tagFilterSelect.append(new Option("All labels", ""));
  tagFilterSelect.addEventListener("change", () => {
    tagFilter = tagFilterSelect.value || null;
    void refreshList();
  });
  tagFilterRow.append(
    el("label", { class: "tag-filter-label", text: "Label" }),
    tagFilterSelect,
  );
  const list = el("ul", { class: "entry-list" });
  listCard.append(tagFilterRow, list);

  function rebuildTagFilterOptions() {
    const tags = collectTags(allSummaries);
    const prev = tagFilter ?? "";
    tagFilterSelect.innerHTML = "";
    tagFilterSelect.append(new Option("All labels", ""));
    for (const t of tags) {
      const count = allSummaries.filter((e) => tagMatches(e.tags, t)).length;
      tagFilterSelect.append(new Option(`${t} (${count})`, t));
    }
    if (!prev) {
      tagFilterSelect.value = "";
      return;
    }
    const match = tags.find((t) => t.toLowerCase() === prev.toLowerCase());
    if (match) {
      tagFilterSelect.value = match;
      tagFilter = match;
    } else {
      // Keep active filter even if search/folder view has zero hits for it
      tagFilterSelect.append(new Option(`${prev} (0)`, prev));
      tagFilterSelect.value = prev;
      tagFilter = prev;
    }
  }

  function setTagFilter(tag: string | null) {
    tagFilter = tag;
    if (tag) {
      // Ensure option exists so select can show it
      const exists = [...tagFilterSelect.options].some(
        (o) => o.value.toLowerCase() === tag.toLowerCase(),
      );
      if (!exists) {
        tagFilterSelect.append(new Option(tag, tag));
      }
      const opt = [...tagFilterSelect.options].find(
        (o) => o.value.toLowerCase() === tag.toLowerCase(),
      );
      tagFilterSelect.value = opt?.value ?? tag;
    } else {
      tagFilterSelect.value = "";
    }
    void refreshList();
  }

  const detailCard = el("div", { class: "card detail-card" });
  detailCard.append(el("h2", { class: "detail-title", text: "Details" }));
  const detailBody = el("div", { class: "detail-scroll", id: "detail" });
  const detailActions = el("div", { class: "detail-actions" });
  detailCard.append(detailBody, detailActions);

  layout.append(folderCard, listCard, detailCard);
  app.append(layout);

  async function refreshFolders() {
    const resp = await client.request({ op: "list_folders" });
    folders = resp.type === "folders" ? resp.folders : [];
    folderList.innerHTML = "";

    const makeItem = (label: string, key: string | null, count?: number) => {
      const li = el("li", {
        class: folderFilter === key ? "active" : "",
      });
      li.append(
        el("span", {
          text: count !== undefined ? `${label} (${count})` : label,
        }),
      );
      li.addEventListener("click", () => {
        folderFilter = key;
        void refreshFolders();
        void refreshList();
      });
      return li;
    };

    const uncategorized = allSummaries.filter((e) => !e.folder_id).length;
    folderList.append(makeItem("All", null, allSummaries.length));
    folderList.append(makeItem("No folder", "", uncategorized));
    for (const f of folders) {
      const n = allSummaries.filter((e) => e.folder_id === f.id).length;
      const li = makeItem(f.name, f.id, n);
      const del = el("button", {
        class: "danger folder-del",
        text: "×",
        title: "Delete folder",
      }) as HTMLButtonElement;
      del.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (!confirm(`Delete folder “${f.name}”? Entries become uncategorized.`)) return;
        await client.request({ op: "delete_folder", id: f.id });
        if (folderFilter === f.id) folderFilter = null;
        await refreshFolders();
        await refreshList();
      });
      li.append(del);
      folderList.append(li);
    }
  }

  addFolderBtn.addEventListener("click", async () => {
    const name = window.prompt("Folder name");
    if (!name?.trim()) return;
    const folder = emptyFolder(name.trim());
    const r = await client.request({ op: "upsert_folder", folder });
    if (r.type === "error") {
      window.alert(r.message);
      return;
    }
    await refreshFolders();
  });

  async function refreshList() {
    const query = search.value || null;
    const resp = await client.request({
      op: "list_summaries",
      query,
    });
    list.innerHTML = "";
    if (resp.type !== "summaries") {
      const msg = resp.type === "error" ? resp.message : "Failed to load";
      list.append(el("li", { text: msg }));
      return;
    }
    allSummaries = resp.entries;
    rebuildTagFilterOptions();

    // Re-paint folder counts without infinite loop
    let entries = resp.entries;
    if (folderFilter === "") {
      entries = entries.filter((e) => !e.folder_id);
    } else if (folderFilter) {
      entries = entries.filter((e) => e.folder_id === folderFilter);
    }
    if (tagFilter) {
      entries = entries.filter((e) => tagMatches(e.tags, tagFilter!));
    }

    // Update folder list labels if already built
    void refreshFolders();

    if (entries.length === 0) {
      list.append(
        el("li", {
          text: tagFilter
            ? `No entries with label “${tagFilter}”`
            : "No entries yet",
        }),
      );
      return;
    }
    for (const e of entries) {
      const item = el("li", { class: "entry-row" });
      const folderName = e.folder_id
        ? folders.find((f) => f.id === e.folder_id)?.name
        : null;
      const metaParts = [
        e.username?.trim() || "",
        !e.username?.trim() && e.urls?.[0] ? e.urls[0] : "",
        folderName ? folderName : "",
      ].filter(Boolean);

      const body = el("div", { class: "entry-row-body" });
      body.append(el("div", { class: "entry-name", text: e.name }));

      if (metaParts.length > 0) {
        body.append(
          el("div", { class: "entry-meta", text: metaParts.join(" · ") }),
        );
      }

      // Features + labels share one accessory row when both present
      const features = entryFeaturePills(e);
      const tags = (e.tags ?? []).filter((t) => t.trim());
      if (features.length > 0 || tags.length > 0) {
        const accessories = el("div", { class: "entry-accessories" });

        if (features.length > 0) {
          const featureRow = el("div", {
            class: "feature-chips",
            role: "list",
            "aria-label": "Entry contents",
          });
          for (const f of features) {
            featureRow.append(
              el("span", {
                class: `feature-chip feature-${f.key}`,
                text: f.label,
                title: f.title,
                role: "listitem",
              }),
            );
          }
          accessories.append(featureRow);
        }

        if (tags.length > 0) {
          const labelRow = el("div", {
            class: "label-chips",
            role: "list",
            "aria-label": "Labels",
          });
          for (const t of tags) {
            const active =
              tagFilter !== null && t.toLowerCase() === tagFilter.toLowerCase();
            const pill = el("button", {
              type: "button",
              class: active ? "label-chip active" : "label-chip",
              text: t,
              title: active ? `Clear filter “${t}”` : `Filter by “${t}”`,
              role: "listitem",
            }) as HTMLButtonElement;
            pill.addEventListener("click", (ev) => {
              ev.preventDefault();
              ev.stopPropagation();
              if (active) setTagFilter(null);
              else setTagFilter(t);
            });
            labelRow.append(pill);
          }
          accessories.append(labelRow);
        }

        body.append(accessories);
      }

      item.append(body);
      item.addEventListener("click", () => void showEntry(e));
      list.append(item);
    }
  }

  async function showEntry(summary: EntrySummary) {
    clearTotpTimer();
    const resp = await client.request({ op: "get_entry", id: summary.id });
    if (resp.type !== "entry") {
      detailActions.replaceChildren();
      detailBody.textContent =
        resp.type === "error" ? resp.message : "Could not load entry";
      return;
    }
    renderEditor(resp.entry, false);
  }

  function renderEditor(entry: Entry, isNew: boolean) {
    clearTotpTimer();
    detailBody.innerHTML = "";
    detailActions.replaceChildren();
    const name = el("input", { value: entry.name }) as HTMLInputElement;
    const username = el("input", { value: entry.username }) as HTMLInputElement;
    const password = el("input", {
      type: "password",
      value: entry.password,
      class: "mono",
    }) as HTMLInputElement;
    const url = el("input", { value: entry.urls[0] ?? "" }) as HTMLInputElement;
    const notes = el("textarea", { rows: "3" }) as HTMLTextAreaElement;
    notes.value = entry.notes;
    const totpSecret = el("input", {
      type: "password",
      value: entry.totp_secret ?? "",
      class: "mono",
      placeholder: "Base32 secret (optional)",
      autocomplete: "off",
    }) as HTMLInputElement;

    const folderSelect = el("select") as HTMLSelectElement;
    folderSelect.append(new Option("— No folder —", ""));
    for (const f of folders) {
      folderSelect.append(new Option(f.name, f.id));
    }
    if (entry.folder_id) folderSelect.value = entry.folder_id;

    const tagsInput = el("input", {
      type: "text",
      value: (entry.tags ?? []).join(", "),
      placeholder: "work, banking, shared…",
      autocomplete: "off",
    }) as HTMLInputElement;
    const tagsPreview = el("div", { class: "label-chips editor-label-chips" });
    const renderTagsPreview = () => {
      tagsPreview.innerHTML = "";
      for (const t of parseTags(tagsInput.value)) {
        tagsPreview.append(
          el("span", { class: "label-chip static", text: t }),
        );
      }
    };
    tagsInput.addEventListener("input", renderTagsPreview);
    renderTagsPreview();

    const pwRow = el("div", { class: "password-field" });
    const toggle = el("button", { text: "Show" }) as HTMLButtonElement;
    const gen = el("button", { text: "Generate" }) as HTMLButtonElement;
    const copy = el("button", { text: "Copy" }) as HTMLButtonElement;
    const pwCopyFeedback = el("span", {
      class: "copy-feedback",
      hidden: "true",
    });
    toggle.addEventListener("click", () => {
      password.type = password.type === "password" ? "text" : "password";
      toggle.textContent = password.type === "password" ? "Show" : "Hide";
    });
    gen.addEventListener("click", () => {
      showGeneratorPopover(gen, (pw) => {
        password.value = pw;
        password.type = "text";
        toggle.textContent = "Hide";
      });
    });
    copy.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      void copySecret(password.value, "Password", pwCopyFeedback);
    });
    const pwControls = el("div", { class: "pw-controls" });
    pwControls.append(toggle, gen, copy, pwCopyFeedback);
    pwRow.append(password, pwControls);

    // TOTP live code
    const totpRow = el("div", { class: "totp-row" });
    const totpCode = el("span", { class: "mono totp-code", text: "——— ———" });
    const totpMeta = el("span", { class: "hint", text: "" });
    const totpCopy = el("button", { text: "Copy code" }) as HTMLButtonElement;
    const totpCopyFeedback = el("span", {
      class: "copy-feedback",
      hidden: "true",
    });
    const totpShow = el("button", { text: "Show seed" }) as HTMLButtonElement;
    totpShow.addEventListener("click", () => {
      totpSecret.type = totpSecret.type === "password" ? "text" : "password";
      totpShow.textContent = totpSecret.type === "password" ? "Show seed" : "Hide seed";
    });
    totpCopy.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const code = totpCode.textContent?.replace(/\s/g, "") ?? "";
      if (!code || code.includes("—") || code.includes("invalid")) {
        totpCopyFeedback.hidden = false;
        totpCopyFeedback.textContent = "No code yet";
        totpCopyFeedback.classList.add("copy-feedback-err");
        return;
      }
      void copySecret(code, "TOTP code", totpCopyFeedback);
    });
    totpRow.append(totpCode, totpMeta, totpCopy, totpCopyFeedback);

    // Password history
    const history = entry.password_history ?? [];
    const historyBlock = el("div", { class: "password-history" });
    if (history.length > 0) {
      const histToggle = el("button", {
        type: "button",
        class: "linkish",
        text: `▸ Password history (${history.length})`,
      }) as HTMLButtonElement;
      const histBody = el("div", { class: "password-history-body hidden" });
      for (const item of history) {
        const row = el("div", { class: "password-history-row" });
        const when = new Date(item.changed_at * 1000)
          .toISOString()
          .replace("T", " ")
          .slice(0, 16);
        const masked = el("input", {
          type: "password",
          class: "mono",
          value: item.password,
          readonly: "true",
        }) as HTMLInputElement;
        const show = el("button", { text: "Show" }) as HTMLButtonElement;
        show.addEventListener("click", () => {
          masked.type = masked.type === "password" ? "text" : "password";
          show.textContent = masked.type === "password" ? "Show" : "Hide";
        });
        const copyH = el("button", { text: "Copy" }) as HTMLButtonElement;
        const fbH = el("span", { class: "copy-feedback", hidden: "true" });
        copyH.addEventListener("click", (ev) => {
          ev.preventDefault();
          void copySecret(item.password, "Old password", fbH);
        });
        row.append(
          el("span", { class: "meta", text: when }),
          masked,
          show,
          copyH,
          fbH,
        );
        histBody.append(row);
      }
      histToggle.addEventListener("click", () => {
        const open = histBody.classList.toggle("hidden") === false;
        histToggle.textContent = open
          ? `▾ Password history (${history.length})`
          : `▸ Password history (${history.length})`;
      });
      historyBlock.append(histToggle, histBody);
    }

    // Custom fields
    type FieldRow = { id: string; name: string; value: string; kind: string };
    const customFields: FieldRow[] = (entry.custom_fields ?? []).map((f) => ({
      ...f,
    }));
    const fieldsHost = el("div", { class: "custom-fields" });
    const renderFields = () => {
      fieldsHost.innerHTML = "";
      for (const f of customFields) {
        const row = el("div", { class: "custom-field-row" });
        const nameIn = el("input", {
          type: "text",
          placeholder: "Field name",
          value: f.name,
        }) as HTMLInputElement;
        const valIn = el("input", {
          type: f.kind === "hidden" ? "password" : "text",
          placeholder: "Value",
          value: f.value,
          class: "mono",
        }) as HTMLInputElement;
        nameIn.addEventListener("input", () => {
          f.name = nameIn.value;
        });
        valIn.addEventListener("input", () => {
          f.value = valIn.value;
        });
        const copyF = el("button", { text: "Copy" }) as HTMLButtonElement;
        const fieldFb = el("span", { class: "copy-feedback", hidden: "true" });
        copyF.addEventListener("click", (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          void copySecret(valIn.value, f.name || "Field", fieldFb);
        });
        const rm = el("button", { class: "danger", text: "×" }) as HTMLButtonElement;
        rm.addEventListener("click", () => {
          const i = customFields.indexOf(f);
          if (i >= 0) customFields.splice(i, 1);
          renderFields();
        });
        row.append(nameIn, valIn, copyF, fieldFb, rm);
        fieldsHost.append(row);
      }
    };
    renderFields();
    const addField = el("button", { text: "+ Custom field" }) as HTMLButtonElement;
    addField.addEventListener("click", () => {
      customFields.push({
        id: randomFieldId(),
        name: "",
        value: "",
        kind: "text",
      });
      renderFields();
    });

    const tickTotp = async () => {
      const secret = totpSecret.value.trim();
      if (!secret) {
        totpCode.textContent = "——— ———";
        totpMeta.textContent = "";
        return;
      }
      try {
        // Prefer server (real crypto path) when unlocked
        const r = await client.request({
          op: "generate_totp",
          secret,
          period: 30,
          digits: 6,
        });
        if (r.type === "totp") {
          const pretty = `${r.code.slice(0, 3)} ${r.code.slice(3)}`;
          totpCode.textContent = pretty;
          totpMeta.textContent = `${r.seconds_remaining}s`;
          return;
        }
        // Fallback to client
        const { code, secondsRemaining } = await generateTotp(secret);
        totpCode.textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
        totpMeta.textContent = `${secondsRemaining}s`;
      } catch {
        totpCode.textContent = "invalid seed";
        totpMeta.textContent = "";
      }
    };
    totpSecret.addEventListener("input", () => void tickTotp());
    void tickTotp();
    totpInterval = setInterval(() => void tickTotp(), 1000);

    const save = el("button", {
      class: "primary",
      text: isNew ? "Add" : "Save",
    }) as HTMLButtonElement;
    const del = el("button", { class: "danger", text: "Delete" }) as HTMLButtonElement;
    del.classList.toggle("hidden", isNew);

    save.addEventListener("click", async () => {
      const next: Entry = {
        ...entry,
        name: name.value.trim() || "Untitled",
        username: username.value,
        password: password.value,
        urls: url.value ? [url.value] : [],
        notes: notes.value,
        folder_id: folderSelect.value || null,
        tags: parseTags(tagsInput.value),
        totp_secret: totpSecret.value.trim() || null,
        custom_fields: customFields
          .filter((f) => f.name.trim() || f.value)
          .map((f) => ({
            id: f.id || randomFieldId(),
            name: f.name.trim() || "Field",
            value: f.value,
            kind: f.kind || "text",
          })),
      };
      save.disabled = true;
      const r = await client.request({ op: "upsert_entry", entry: next });
      save.disabled = false;
      if (r.type === "error") {
        setError(detailBody, r.message);
        return;
      }
      const saveFb = detailActions.querySelector(".save-feedback") as HTMLElement | null;
      if (saveFb) {
        saveFb.hidden = false;
        saveFb.textContent = "Saved";
        setTimeout(() => {
          if (saveFb.textContent === "Saved") saveFb.hidden = true;
        }, 1500);
      }
      statusLine.textContent = "Saved";
      await refreshList();
    });

    del.addEventListener("click", async () => {
      if (!entry.id) return;
      await client.request({ op: "delete_entry", id: entry.id });
      clearTotpTimer();
      detailBody.innerHTML = "";
      detailActions.replaceChildren();
      await refreshList();
    });

    detailBody.append(
      el("label", { text: "Name" }),
      name,
      el("label", { text: "Folder" }),
      folderSelect,
      el("label", { text: "Labels" }),
      tagsInput,
      tagsPreview,
      el("p", {
        class: "hint tag-hint",
        text: "Comma-separated. Shown as pills in the list; click a pill to filter.",
      }),
      el("label", { text: "Username" }),
      username,
      el("label", { text: "Password" }),
      pwRow,
      historyBlock,
      el("label", { text: "URL" }),
      url,
      el("label", { text: "Authenticator (TOTP seed)" }),
      totpSecret,
      totpShow,
      totpRow,
      el("label", { text: "Custom fields" }),
      fieldsHost,
      addField,
      el("label", { text: "Notes" }),
      notes,
    );

    // Sticky action bar — always visible at bottom of detail panel
    const saveFb = el("span", {
      class: "copy-feedback save-feedback",
      hidden: "true",
    });
    detailActions.append(save, del, saveFb);
  }

  newBtn.addEventListener("click", () => {
    const e = emptyEntry();
    if (folderFilter && folderFilter !== "") e.folder_id = folderFilter;
    renderEditor(e, true);
  });
  search.addEventListener("input", () => void refreshList());

  await refreshList();
}

function showHealthModal(
  report: HealthReport,
  onOpenEntry: (id: string) => void | Promise<void>,
) {
  const overlay = el("div", { class: "modal-overlay" });
  const modal = el("div", { class: "modal card" });
  modal.append(el("h2", { text: `Password health — ${report.score}/100` }));
  modal.append(
    el("p", {
      class: "hint",
      text: `${report.total_entries} entries · ${report.issue_count} issues · ${report.reused_groups} reused groups · ${report.empty_count} empty · ${report.weak_count} weak`,
    }),
  );

  if (report.issues.length === 0) {
    modal.append(el("p", { text: "No issues found. Looking good." }));
  } else {
    const ul = el("ul", { class: "health-list" });
    for (const issue of report.issues.slice(0, 40)) {
      const li = el("li", {});
      const link = el("button", {
        class: "linkish",
        text: issue.entry_name || issue.entry_id.slice(0, 8),
      }) as HTMLButtonElement;
      link.addEventListener("click", () => {
        overlay.remove();
        void onOpenEntry(issue.entry_id);
      });
      li.append(
        el("span", { class: "health-kind", text: issue.kind.replace(/_/g, " ") }),
        document.createTextNode(" · "),
        link,
        el("div", { class: "meta", text: issue.detail }),
      );
      ul.append(li);
    }
    if (report.issues.length > 40) {
      modal.append(
        el("p", {
          class: "hint",
          text: `Showing 40 of ${report.issues.length} issues.`,
        }),
      );
    }
    modal.append(ul);
  }

  const close = el("button", { class: "primary", text: "Close" }) as HTMLButtonElement;
  close.addEventListener("click", () => overlay.remove());
  modal.append(close);
  overlay.append(modal);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });
  document.body.append(overlay);
}

function showSettingsModal(
  onSaved: () => void,
  openSection: "autolock" | "passphrase" | "recovery" = "autolock",
) {
  const overlay = el("div", { class: "modal-overlay" });
  const modal = el("div", { class: "modal card" });
  modal.append(el("h2", { text: "Settings" }));
  modal.append(
    el("p", {
      class: "hint",
      text: "Open a section to change that setting. Only one section expands at a time.",
    }),
  );

  const accordion = el("div", { class: "settings-accordion" });
  const panels: {
    id: string;
    root: HTMLElement;
    body: HTMLElement;
    chevron: HTMLElement;
  }[] = [];

  function collapseAll(except?: HTMLElement) {
    for (const p of panels) {
      const open = except != null && p.root === except;
      p.root.classList.toggle("open", open);
      p.body.hidden = !open;
      p.chevron.textContent = open ? "▾" : "▸";
      p.root
        .querySelector(".settings-section-toggle")
        ?.setAttribute("aria-expanded", open ? "true" : "false");
    }
  }

  function addSection(
    id: string,
    title: string,
    summary: string,
    buildBody: (body: HTMLElement) => void,
  ) {
    const root = el("div", { class: "settings-section" });
    const toggle = el("button", {
      type: "button",
      class: "settings-section-toggle",
      "aria-expanded": "false",
    }) as HTMLButtonElement;
    const chevron = el("span", { class: "settings-chevron", text: "▸" });
    const label = el("span", { class: "settings-section-label" }, [
      el("strong", { text: title }),
      el("span", { class: "meta", text: summary }),
    ]);
    toggle.append(chevron, label);

    const body = el("div", { class: "settings-section-body" });
    body.hidden = true;
    buildBody(body);

    toggle.addEventListener("click", () => {
      const willOpen = body.hidden;
      collapseAll(willOpen ? root : undefined);
    });

    root.append(toggle, body);
    accordion.append(root);
    panels.push({ id, root, body, chevron });
  }

  // —— Auto-lock ——
  addSection(
    "autolock",
    "Auto-lock",
    `${Math.round(getAutoLockSeconds() / 60)} min idle`,
    (body) => {
      body.append(
        el("p", {
          class: "hint",
          text: "Lock the vault after this many minutes of inactivity (this browser only).",
        }),
      );
      const mins = el("input", {
        type: "number",
        min: "1",
        max: "60",
        value: String(Math.round(getAutoLockSeconds() / 60)),
      }) as HTMLInputElement;
      const saveLock = el("button", {
        class: "primary",
        text: "Save auto-lock",
      }) as HTMLButtonElement;
      saveLock.addEventListener("click", () => {
        const m = Number(mins.value);
        if (!Number.isFinite(m) || m < 1) {
          window.alert("Enter 1–60 minutes");
          return;
        }
        setAutoLockSeconds(Math.round(m * 60));
        onSaved();
        statusNote(modal, `Auto-lock set to ${Math.round(m)} min`);
        // Refresh section summary
        const meta = panels.find((p) => p.id === "autolock")?.root.querySelector(".meta");
        if (meta) meta.textContent = `${Math.round(m)} min idle`;
      });
      body.append(el("label", { text: "Minutes" }), mins, saveLock);
    },
  );

  // —— Change passphrase ——
  addSection("passphrase", "Change master passphrase", "Re-wrap vault key", (body) => {
    body.append(
      el("p", {
        class: "hint",
        text: "Re-wraps the vault key. Entries are not re-encrypted. Use a strong unique passphrase.",
      }),
    );
    const cur = el("input", {
      type: "password",
      placeholder: "Current passphrase",
      autocomplete: "current-password",
    }) as HTMLInputElement;
    const neu = el("input", {
      type: "password",
      placeholder: "New passphrase",
      autocomplete: "new-password",
    }) as HTMLInputElement;
    const neu2 = el("input", {
      type: "password",
      placeholder: "Confirm new passphrase",
      autocomplete: "new-password",
    }) as HTMLInputElement;
    const changeBtn = el("button", {
      class: "primary",
      text: "Change passphrase",
    }) as HTMLButtonElement;
    changeBtn.addEventListener("click", async () => {
      if (neu.value.length < 8) {
        window.alert("New passphrase must be at least 8 characters");
        return;
      }
      if (neu.value !== neu2.value) {
        window.alert("New passphrases do not match");
        return;
      }
      changeBtn.disabled = true;
      const r = await client.request({
        op: "change_passphrase",
        current_passphrase: cur.value,
        new_passphrase: neu.value,
        kdf_profile: modeLabel.includes("mock") ? "test" : "interactive",
      });
      changeBtn.disabled = false;
      if (r.type === "error") {
        window.alert(r.message);
        return;
      }
      cur.value = "";
      neu.value = "";
      neu2.value = "";
      unlockedViaRecovery = false;
      statusNote(modal, "Passphrase updated");
      window.alert("Master passphrase changed successfully.");
    });
    body.append(cur, neu, neu2, changeBtn);
  });

  // —— Recovery key ——
  addSection("recovery", "Recovery key", "Offline unlock if passphrase is lost", (body) => {
    body.append(
      el("p", {
        class: "hint",
        text: "A one-time high-entropy key that unlocks the vault if you forget your passphrase. Store it offline (password manager, paper, safe). Generating a new key replaces any previous one.",
      }),
    );
    const genRec = el("button", {
      text: "Generate recovery key",
    }) as HTMLButtonElement;
    const revRec = el("button", {
      class: "danger",
      text: "Revoke recovery key",
    }) as HTMLButtonElement;
    const recOut = el("div", { class: "recovery-out hidden" });
    const busyRow = el("div", { class: "busy-row hidden" });
    busyRow.append(
      el("span", { class: "spinner spinner-lg", "aria-hidden": "true" }),
      el("span", {
        text: "Generating recovery key… (deriving key — may take a few seconds)",
      }),
    );
    genRec.addEventListener("click", async () => {
      if (
        !confirm(
          "Generate a new recovery key? Any previous recovery key will stop working. You will only see the new key once.",
        )
      ) {
        return;
      }
      genRec.disabled = true;
      revRec.disabled = true;
      busyRow.classList.remove("hidden");
      recOut.classList.add("hidden");
      try {
        const r = await client.request({
          op: "generate_recovery_key",
          kdf_profile: modeLabel.includes("mock") ? "test" : "interactive",
        });
        if (r.type === "error") {
          window.alert(r.message);
          return;
        }
        if (r.type !== "recovery_key") return;
        recOut.classList.remove("hidden");
        recOut.innerHTML = "";
        recOut.append(
          el("p", {
            class: "hint",
            text: "Copy and store this key now. It will not be shown again.",
          }),
        );
        const keyBox = el("div", {
          class: "recovery-key-display mono",
          role: "textbox",
          "aria-readonly": "true",
          tabindex: "0",
        });
        keyBox.textContent = r.recovery_key;
        const copy = el("button", {
          class: "primary",
          text: "Copy recovery key",
        }) as HTMLButtonElement;
        copy.addEventListener("click", (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          void (async () => {
            try {
              if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(r.recovery_key);
              } else if (!copyViaTextarea(r.recovery_key)) {
                throw new Error("copy failed");
              }
              statusNote(modal, "Recovery key copied — store it offline");
            } catch {
              // Last resort: select the key display so user can Ctrl+C
              const box = recOut.querySelector(".recovery-key-display") as HTMLElement | null;
              if (box) {
                const range = document.createRange();
                range.selectNodeContents(box);
                const sel = window.getSelection();
                sel?.removeAllRanges();
                sel?.addRange(range);
              }
              statusNote(modal, "Select the key and press Ctrl+C / ⌘C to copy");
            }
          })();
        });
        recOut.append(keyBox, copy);
      } finally {
        busyRow.classList.add("hidden");
        genRec.disabled = false;
        revRec.disabled = false;
      }
    });
    revRec.addEventListener("click", async () => {
      if (
        !confirm(
          "Revoke recovery key? You will only be able to unlock with the master passphrase.",
        )
      ) {
        return;
      }
      const r = await client.request({ op: "revoke_recovery_key" });
      if (r.type === "error") {
        window.alert(r.message);
        return;
      }
      recOut.classList.add("hidden");
      recOut.innerHTML = "";
      statusNote(modal, "Recovery key revoked");
    });
    body.append(genRec, revRec, busyRow, recOut);
  });

  modal.append(accordion);

  // Open requested section (default auto-lock)
  const target = panels.find((p) => p.id === openSection) ?? panels[0];
  if (target) collapseAll(target.root);

  const close = el("button", {
    text: "Close",
    style: "margin-top:1rem",
  }) as HTMLButtonElement;
  close.addEventListener("click", () => overlay.remove());
  modal.append(close);
  overlay.append(modal);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });
  document.body.append(overlay);
}

function statusNote(modal: HTMLElement, text: string) {
  const existing = modal.querySelector(".settings-note");
  existing?.remove();
  modal.append(el("p", { class: "hint settings-note", text }));
}

initClient()
  .then(() => render())
  .catch((e) => {
    app.textContent = String(e);
  });
