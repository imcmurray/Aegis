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
  type ImportEntryChange,
  type VaultResponse,
} from "./messages";
import {
  meshCapabilities,
  probeFreenetPeer,
  type PeerProbe,
} from "./peerStatus";
import { storageSet } from "./storage";
import { generateTotp } from "./totp";

const app = document.querySelector<HTMLDivElement>("#app")!;

let client: VaultClient;
let unlocked = false;
let modeLabel = "…";
let peerProbe: PeerProbe | null = null;
let idleTimer: ReturnType<typeof setTimeout> | null = null;
let lastActivity = Date.now();
let clipboardClearTimer: ReturnType<typeof setTimeout> | null = null;
/** Last value we wrote to the clipboard (only clear if still matches). */
let lastCopiedSecret: string | null = null;
/** Set when vault was unlocked via recovery key — nudge user to set a new passphrase. */
let unlockedViaRecovery = false;

async function refreshPeerProbe(force = false) {
  peerProbe = await probeFreenetPeer({ force });
  return peerProbe;
}

function caps() {
  return meshCapabilities(peerProbe, Boolean(client?.freenetApi));
}

async function initClient() {
  client = await createVaultClient();
  modeLabel = client.label;
  // Peer probe is independent of vault backend (informs Sync / multi-device UX).
  void refreshPeerProbe(true);
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
    return "Freenet vault-delegate — multi-device Sync available after unlock (requires a local peer).";
  }
  if (modeLabel.includes("browser")) {
    return "This browser’s vault (real crypto, IndexedDB). Multi-device is optional later via Export or Freenet Sync.";
  }
  if (modeLabel.includes("mock")) {
    return "Legacy mock vault (not production crypto). Prefer default browser mode.";
  }
  return "Select a mode below.";
}

function isBrowserMode(): boolean {
  return modeLabel.includes("browser") && !modeLabel.includes("freenet");
}

function isFreenetMode(): boolean {
  return modeLabel.includes("freenet");
}

function buildHeader(): HTMLElement {
  const c = caps();
  const peerClass =
    c.peerOk
      ? "peer-chip peer-online"
      : c.blocked
        ? "peer-chip peer-blocked"
        : "peer-chip peer-offline";
  const peerTitle = c.detail;
  const badges = el("div", { class: "header-badges" }, [
    el("span", { class: "badge badge-mode", text: modeLabel, title: modeHint() }),
    el("span", {
      class: peerClass,
      text: c.label,
      title: peerTitle,
    }),
  ]);
  const header = el("header", { class: "app-header" }, [
    el("h1", {}, ["Aegis ", el("span", { text: "Password Manager" })]),
    badges,
  ]);
  return header;
}

/** Capability strip under header — teaches new users what is available. */
function buildCapabilityBar(): HTMLElement {
  const c = caps();
  const bar = el("div", { class: "capability-bar", role: "status" });

  const item = (
    kind: "on" | "off" | "warn",
    title: string,
    blurb: string,
  ) => {
    const card = el("div", { class: `cap-card cap-${kind}` });
    card.append(el("div", { class: "cap-title", text: title }));
    card.append(el("div", { class: "cap-blurb", text: blurb }));
    return card;
  };

  bar.append(
    item("on", "This browser", "Create, unlock, and store your vault here."),
    item(
      "on",
      "Export / Import",
      "Move an encrypted backup to another PC anytime.",
    ),
    item(
      c.canMeshSync ? "on" : c.blocked ? "warn" : "off",
      "Freenet mesh Sync",
      c.canMeshSync
        ? "Peer online — multi-device Sync can publish encrypted vault state."
        : c.blocked
          ? "Blocked on HTTPS pages. Open Aegis via local Freenet HTTP to use Sync."
          : "Peer offline. Start `freenet local` to enable mesh Sync.",
    ),
  );
  return bar;
}

async function render() {
  // Refresh peer status (cached ~8s unless forced elsewhere)
  if (!peerProbe || Date.now() - peerProbe.checkedAt > 12_000) {
    await refreshPeerProbe(false);
  }

  app.innerHTML = "";
  app.append(buildHeader());
  app.append(buildCapabilityBar());

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
  // Collapsed “advanced” — most users stay on browser vault.
  const details = el("details", { class: "advanced-modes" });
  details.append(
    el("summary", {
      class: "hint",
      text: "Advanced backends (optional)",
    }),
  );
  const row = el("p", { class: "hint" }, [
    el("a", { href: "?mode=browser", text: "browser" }),
    " (default) · ",
    el("a", { href: "?mode=freenet", text: "freenet" }),
    " · ",
    el("a", { href: "?mode=dev", text: "dev (Rust)" }),
    " · ",
    el("a", { href: "?mode=mock", text: "mock" }),
  ]);
  details.append(row);
  return details;
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
    const kdf_profile = defaultKdfProfile();
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
  card.append(
    el("p", {
      class: "hint",
      text: "VaultSync / multi-device is optional. Create here first; enable Sync later in Settings if you want Freenet mesh access on another PC.",
    }),
  );

  // Import encrypted backup
  const importCard = el("div", { class: "card" });
  importCard.append(el("h2", { text: "Import backup" }));
  importCard.append(
    el("p", {
      class: "hint",
      text: "Restore an encrypted .aegis export. Best way to move or re-sync browsers without Freenet.",
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
      replace: false,
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

function formatPreviewTs(ts: number | null | undefined): string {
  if (ts == null || !ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

function previewListSection(
  title: string,
  items: string[],
  emptyText: string,
): HTMLElement {
  const sec = el("div", { class: "import-preview-section" });
  sec.append(el("h4", { text: title }));
  if (!items.length) {
    sec.append(el("p", { class: "hint", text: emptyText }));
    return sec;
  }
  const ul = el("ul", { class: "import-preview-list" });
  for (const line of items) {
    ul.append(el("li", { text: line }));
  }
  sec.append(ul);
  return sec;
}

/** Render a safe local-vs-backup diff into a container. */
function renderImportPreviewPanel(
  host: HTMLElement,
  preview: Extract<VaultResponse, { type: "import_preview" }>,
) {
  host.replaceChildren();
  host.classList.remove("hidden");

  const head = el("div", { class: "import-preview-head" });
  head.append(el("strong", { text: "Changes if you replace" }));
  if (preview.local_available) {
    head.append(
      el("span", {
        class: "hint",
        text: `Local ${preview.local_entry_count} → backup ${preview.backup_entry_count} entries · ${preview.unchanged_count} unchanged`,
      }),
    );
  } else {
    head.append(
      el("span", {
        class: "hint",
        text: `Backup has ${preview.backup_entry_count} entries (local not opened for comparison)`,
      }),
    );
  }
  host.append(head);

  if (preview.note) {
    host.append(el("p", { class: "hint import-preview-note", text: preview.note }));
  }

  if (preview.local_available && !preview.same_vault_id) {
    host.append(
      el("p", {
        class: "hint import-preview-warn",
        text: "Vault IDs differ — this backup may be from a different vault (not a re-sync of the same one).",
      }),
    );
  }

  const meta = el("p", { class: "hint import-preview-meta" });
  meta.textContent =
    `Local updated: ${formatPreviewTs(preview.local_updated_at)} · ` +
    `Backup updated: ${formatPreviewTs(preview.backup_updated_at)}`;
  host.append(meta);

  const onlyLocalLines = preview.only_local.map((e) => {
    const user = e.username ? ` (${e.username})` : "";
    return `${e.name}${user}`;
  });
  host.append(
    previewListSection(
      `Only on this browser (${preview.only_local.length}) — will be lost`,
      onlyLocalLines,
      "Nothing unique to this browser.",
    ),
  );

  const onlyBackupLines = preview.only_backup.map((e) => {
    const user = e.username ? ` (${e.username})` : "";
    return `${e.name}${user}`;
  });
  host.append(
    previewListSection(
      `Only in backup (${preview.only_backup.length}) — will be added`,
      onlyBackupLines,
      "No new entries in the backup.",
    ),
  );

  const changedLines = preview.changed.map((c: ImportEntryChange) => {
    const fields = c.fields.join(", ");
    const newer =
      c.newer === "backup"
        ? "backup newer"
        : c.newer === "local"
          ? "local newer"
          : "same age";
    const rename =
      c.local_name !== c.backup_name
        ? ` “${c.local_name}” → “${c.backup_name}”`
        : "";
    return `${c.name}${rename}: ${fields} (${newer})`;
  });
  host.append(
    previewListSection(
      `Changed on both sides (${preview.changed.length})`,
      changedLines,
      "No overlapping entries differ.",
    ),
  );

  if (preview.folders_only_local.length || preview.folders_only_backup.length) {
    const folderLines: string[] = [];
    for (const n of preview.folders_only_local) folderLines.push(`− folder “${n}” (local only)`);
    for (const n of preview.folders_only_backup) folderLines.push(`+ folder “${n}” (backup only)`);
    host.append(
      previewListSection("Folders", folderLines, "Folders match."),
    );
  }

  if (
    preview.local_available &&
    !preview.only_local.length &&
    !preview.only_backup.length &&
    !preview.changed.length
  ) {
    host.append(
      el("p", {
        class: "hint import-preview-same",
        text: "Vaults look identical — replace would rewrite the same data.",
      }),
    );
  }
}

/** Replace-from-backup fields for unlock screen (mounted into a collapsible body). */
function mountReplaceImportForm(container: HTMLElement) {
  container.append(
    el("p", {
      class: "hint",
      text: "Export from the machine with the newest data, then preview and replace here. Overwrites this browser’s vault only.",
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
  const localPw = el("input", {
    type: "password",
    placeholder: "Only if different from export passphrase",
    autocomplete: "off",
  }) as HTMLInputElement;

  const previewPanel = el("div", { class: "import-preview hidden" });
  let lastPreview:
    | Extract<VaultResponse, { type: "import_preview" }>
    | null = null;

  const previewBtn = el("button", {
    text: "Preview changes",
  }) as HTMLButtonElement;
  const importBtn = el("button", {
    class: "danger",
    text: "Replace local vault",
  }) as HTMLButtonElement;

  const row = el("div", { class: "row import-preview-actions" });
  row.append(previewBtn, importBtn);

  async function readBlob(): Promise<Uint8Array | null> {
    setError(container, null);
    const file = fileInput.files?.[0];
    if (!file) {
      setError(container, "Choose a backup file first.");
      return null;
    }
    if (!importPw.value) {
      setError(container, "Enter the passphrase used when exporting.");
      return null;
    }
    return new Uint8Array(await file.arrayBuffer());
  }

  previewBtn.addEventListener("click", async () => {
    const buf = await readBlob();
    if (!buf) return;
    previewBtn.disabled = true;
    importBtn.disabled = true;
    const resp = await client.request({
      op: "preview_import",
      blob: buf,
      passphrase: importPw.value,
      local_passphrase: localPw.value.trim() || null,
    });
    previewBtn.disabled = false;
    importBtn.disabled = false;
    if (resp.type === "error") {
      setError(container, resp.message);
      return;
    }
    if (resp.type !== "import_preview") {
      setError(container, "Unexpected response from preview.");
      return;
    }
    lastPreview = resp;
    renderImportPreviewPanel(previewPanel, resp);
  });

  importBtn.addEventListener("click", async () => {
    const buf = await readBlob();
    if (!buf) return;

    let summary = "";
    if (lastPreview?.local_available) {
      const lost = lastPreview.only_local.length;
      const gained = lastPreview.only_backup.length;
      const changed = lastPreview.changed.length;
      summary =
        `\n\nPreview: −${lost} only-local · +${gained} only-backup · ~${changed} changed · ` +
        `${lastPreview.unchanged_count} unchanged.`;
      if (lost > 0) {
        summary += `\nEntries only on this browser will be lost.`;
      }
    } else if (!lastPreview) {
      summary = "\n\nTip: use Preview changes first to see what differs.";
    }

    if (
      !confirm(
        "Replace this browser’s vault with the backup?" +
          summary +
          "\n\nThis cannot be undone for data that exists only here.",
      )
    ) {
      return;
    }
    importBtn.disabled = true;
    previewBtn.disabled = true;
    const resp = await client.request({
      op: "import_encrypted",
      blob: buf,
      passphrase: importPw.value,
      replace: true,
    });
    importBtn.disabled = false;
    previewBtn.disabled = false;
    if (resp.type === "error") {
      setError(container, resp.message);
      return;
    }
    unlockedViaRecovery = false;
    await render();
  });

  container.append(el("label", { text: "Backup file" }), fileInput);
  container.append(el("label", { text: "Export passphrase" }), importPw);
  container.append(
    el("label", { text: "Local master passphrase (optional)" }),
    localPw,
  );
  container.append(row, previewPanel);
}

function unlockAltSection(
  summary: string,
  buildBody: (body: HTMLElement) => void,
): HTMLElement {
  const details = el("details", { class: "unlock-alt" });
  details.append(el("summary", { text: summary }));
  const body = el("div", { class: "unlock-alt-body" });
  buildBody(body);
  details.append(body);
  return details;
}

function renderUnlock() {
  const card = el("div", { class: "card unlock-card" });
  card.append(el("h2", { text: "Unlock vault" }));
  card.append(el("p", { class: "hint unlock-mode-hint", text: modeHint() }));

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
  const primary = el("div", { class: "unlock-primary" });
  const primaryFields = el("div", { class: "unlock-primary-fields" });
  primaryFields.append(el("label", { text: "Master passphrase" }), pw);
  primary.append(primaryFields, btn);
  card.append(primary);

  // Secondary paths side-by-side on wide screens (less vertical scroll).
  const alts = el("div", { class: "unlock-alts" });

  alts.append(
    unlockAltSection("Unlock with recovery key", (body) => {
      body.append(
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
      const recBtn = el("button", {
        text: "Unlock with recovery key",
      }) as HTMLButtonElement;
      recBtn.addEventListener("click", async () => {
        setError(body, null);
        if (!rec.value.trim()) {
          setError(body, "Enter your recovery key.");
          return;
        }
        recBtn.disabled = true;
        const resp = await client.request({
          op: "unlock_with_recovery",
          recovery_key: rec.value.trim(),
        });
        recBtn.disabled = false;
        if (resp.type === "error") {
          setError(body, resp.message);
          return;
        }
        unlockedViaRecovery = true;
        await render();
      });
      rec.addEventListener("keydown", (e) => {
        if (e.key === "Enter") recBtn.click();
      });
      body.append(el("label", { text: "Recovery key" }), rec, recBtn);
    }),
  );

  alts.append(
    unlockAltSection("Replace vault from backup", (body) => {
      mountReplaceImportForm(body);
    }),
  );

  card.append(alts);
  card.append(
    el("p", {
      class: "hint unlock-tip",
      text: "After unlock: Export for another PC, or Settings → Multi-device for Freenet Sync.",
    }),
  );
  card.append(modeLinks());

  app.append(card);
}

const CONTRACT_STATE_KEY = "aegis.vaultSyncState";
const CONTRACT_VK_KEY = "aegis.vaultSyncOwnerVk";

function toBytes(raw: number[] | Uint8Array | undefined | null): Uint8Array {
  if (!raw) return new Uint8Array(0);
  if (raw instanceof Uint8Array) return raw;
  return new Uint8Array(raw);
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
  /** Preferred folder id when creating a new entry (last expanded named folder). */
  let preferredFolderId: string | null = null;
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
  const c0 = caps();
  // Mesh Sync needs peer; local sync_now still works but we grey mesh-oriented control
  // when user expects Freenet multi-device and peer is missing.
  const meshReady = Boolean(client.freenetApi) && c0.canMeshSync;
  if (!meshReady && isFreenetMode()) {
    syncBtn.disabled = true;
    syncBtn.classList.add("btn-disabled");
    syncBtn.title = c0.blocked
      ? "Freenet peer blocked from this page (HTTPS). Open via local peer HTTP."
      : "Freenet peer offline — start `freenet local` to Sync on the mesh.";
  } else if (!client.freenetApi && isBrowserMode()) {
    syncBtn.title =
      "Local sync only. For multi-PC Freenet mesh, enable Freenet in Settings when a peer is online.";
  } else {
    syncBtn.title = meshReady
      ? "Push/pull encrypted vault state on Freenet (owner-key identity)"
      : "Local vault sync";
  }
  const statusLine = el("p", {
    class: "hint",
    id: "status-line",
    text: meshReady
      ? `Peer online · auto-lock ${lockMins} min`
      : c0.blocked
        ? `Peer blocked on HTTPS · auto-lock ${lockMins} min · Export still works`
        : `Peer offline · auto-lock ${lockMins} min · Export still works`,
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

  async function runSync() {
    const c = caps();
    if (isFreenetMode() && !c.canMeshSync) {
      statusLine.textContent = c.blocked
        ? "Sync unavailable: peer blocked on HTTPS. Open Aegis via freenet local HTTP."
        : "Sync unavailable: Freenet peer offline. Run `freenet local` and refresh.";
      return;
    }
    syncBtn.disabled = true;
    statusLine.textContent = "Syncing…";
    try {
      // Freenet mesh: Get remote VaultSync → merge → Put/Update (owner-key identity).
      if (client.freenetApi && c.canMeshSync) {
        const { freenetVaultSyncRoundTrip } = await import("./vaultSync");
        const summary = await freenetVaultSyncRoundTrip(
          client.freenetApi,
          async (remoteState) => {
            const r = await client.request({
              op: "sync_with_remote",
              remote_state: remoteState,
            });
            if (r.type === "synced") {
              const blob = toBytes(r.contract_state);
              const vk = toBytes(r.owner_verifying_key);
              if (blob.length > 0) cacheContractState(blob, vk);
            }
            return r;
          },
        );
        statusLine.textContent = `Sync: ${summary}`;
        await refreshList();
        return;
      }

      // Browser / dev: local MVR only — multi-device mesh needs Freenet mode (Settings).
      const resp = await client.request({ op: "sync_now" });
      if (resp.type === "error") {
        statusLine.textContent = `Sync: ${resp.message}`;
        return;
      }
      if (resp.type === "synced") {
        const extra = isBrowserMode()
          ? " · local only (mesh Sync needs Freenet peer — see Settings)"
          : "";
        statusLine.textContent = `Sync: ${resp.action} — ${resp.detail} (${resp.remote_revisions} rev)${extra}`;
        await refreshList();
        return;
      }
      statusLine.textContent = "Sync finished.";
    } catch (e) {
      statusLine.textContent = `Sync: ${e instanceof Error ? e.message : String(e)}`;
    } finally {
      // Re-apply disabled state for freenet-without-peer
      const c2 = caps();
      syncBtn.disabled = isFreenetMode() && !c2.canMeshSync;
    }
  }

  syncBtn.addEventListener("click", () => void runSync());
  window.addEventListener("aegis-sync-now", () => void runSync());

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

  search.placeholder = "Search name, user, URL, labels…";
  toolbar.append(search, newBtn, syncBtn, exportBtn, healthBtn, settingsBtn, auditBtn, lockBtn);
  app.append(toolbar);
  app.append(statusLine);

  // Layout: combined folder tree + detail
  const layout = el("div", { class: "vault-layout vault-layout-tree" });

  /** Folder keys that are expanded. "" = uncategorized. Auto-opens on search. */
  const expandedFolders = new Set<string>([""]);
  let userCollapsedWhileSearch = false;

  const treeCard = el("div", { class: "card tree-panel" });
  const treeHead = el("div", { class: "tree-head" });
  treeHead.append(el("h2", { text: "Vault" }));
  const treeHeadActions = el("div", { class: "tree-head-actions" });
  const expandAllBtn = el("button", {
    type: "button",
    class: "btn-ghost btn-tiny",
    text: "Expand",
    title: "Expand all folders",
  }) as HTMLButtonElement;
  const collapseAllBtn = el("button", {
    type: "button",
    class: "btn-ghost btn-tiny",
    text: "Collapse",
    title: "Collapse all folders",
  }) as HTMLButtonElement;
  const addFolderBtn = el("button", {
    type: "button",
    class: "btn-ghost btn-tiny",
    text: "+ Folder",
  }) as HTMLButtonElement;
  treeHeadActions.append(expandAllBtn, collapseAllBtn, addFolderBtn);
  treeHead.append(treeHeadActions);

  const tagFilterRow = el("div", { class: "tag-filter-row" });
  const tagFilterSelect = el("select", {
    class: "tag-filter-select",
    title: "Filter by label",
  }) as HTMLSelectElement;
  tagFilterSelect.append(new Option("All labels", ""));
  tagFilterSelect.addEventListener("change", () => {
    tagFilter = tagFilterSelect.value || null;
    void refreshTree();
  });
  tagFilterRow.append(
    el("label", { class: "tag-filter-label", text: "Label" }),
    tagFilterSelect,
  );

  const treeRoot = el("div", {
    class: "vault-tree",
    role: "tree",
    "aria-label": "Folders and entries",
  });
  const treeScroll = el("div", { class: "tree-scroll" });
  treeScroll.append(treeRoot);
  treeCard.append(treeHead, tagFilterRow, treeScroll);

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
      tagFilterSelect.append(new Option(`${prev} (0)`, prev));
      tagFilterSelect.value = prev;
      tagFilter = prev;
    }
  }

  function setTagFilter(tag: string | null) {
    tagFilter = tag;
    if (tag) {
      const exists = [...tagFilterSelect.options].some(
        (o) => o.value.toLowerCase() === tag.toLowerCase(),
      );
      if (!exists) tagFilterSelect.append(new Option(tag, tag));
      const opt = [...tagFilterSelect.options].find(
        (o) => o.value.toLowerCase() === tag.toLowerCase(),
      );
      tagFilterSelect.value = opt?.value ?? tag;
    } else {
      tagFilterSelect.value = "";
    }
    void refreshTree();
  }

  const detailCard = el("div", { class: "card detail-card" });
  detailCard.append(el("h2", { class: "detail-title", text: "Details" }));
  const detailBody = el("div", { class: "detail-scroll", id: "detail" });
  const detailActions = el("div", { class: "detail-actions" });
  detailCard.append(detailBody, detailActions);

  layout.append(treeCard, detailCard);
  app.append(layout);

  function isSearching(): boolean {
    return Boolean(search.value.trim() || tagFilter);
  }

  function entryMatchesFilters(e: EntrySummary, serverAlreadyFiltered: boolean): boolean {
    if (tagFilter && !tagMatches(e.tags, tagFilter)) return false;
    if (serverAlreadyFiltered) return true;
    // Client-side safety for name/user/url already filtered by server query
    return true;
  }

  /** Long-press (≈0.4s) then drag entry; drop on a folder to move. */
  let dragState: {
    entryId: string;
    entryName: string;
    fromFolder: string | null;
    ghost: HTMLElement;
    activeDrop: HTMLElement | null;
  } | null = null;

  function clearDropHighlights() {
    treeRoot
      .querySelectorAll(".drop-target")
      .forEach((n) => n.classList.remove("drop-target"));
  }

  function folderKeyFromEl(target: EventTarget | null): string | null {
    const node = target instanceof Element ? target : null;
    const zone = node?.closest("[data-drop-folder]") as HTMLElement | null;
    if (!zone) return null;
    return zone.getAttribute("data-drop-folder");
  }

  function setActiveDrop(zone: HTMLElement | null) {
    if (dragState?.activeDrop === zone) return;
    clearDropHighlights();
    if (zone) zone.classList.add("drop-target");
    if (dragState) dragState.activeDrop = zone;
  }

  async function moveEntryToFolder(
    entryId: string,
    folderKey: string,
  ): Promise<void> {
    const folderId = folderKey === "" ? null : folderKey;
    const r = await client.request({ op: "get_entry", id: entryId });
    if (r.type !== "entry") {
      statusLine.textContent =
        r.type === "error" ? r.message : "Could not move entry";
      return;
    }
    const cur = r.entry.folder_id ?? null;
    if (cur === folderId) {
      statusLine.textContent = "Already in that folder";
      return;
    }
    const next = { ...r.entry, folder_id: folderId };
    const up = await client.request({ op: "upsert_entry", entry: next });
    if (up.type === "error") {
      statusLine.textContent = up.message;
      return;
    }
    expandedFolders.add(folderKey);
    if (folderId) preferredFolderId = folderId;
    const destName =
      folderId == null
        ? "Uncategorized"
        : (folders.find((f) => f.id === folderId)?.name ?? "folder");
    statusLine.textContent = `Moved “${r.entry.name}” → ${destName}`;
    await refreshTree();
  }

  function endDrag(commit: boolean, dropKey: string | null) {
    if (!dragState) return;
    const { entryId, ghost, fromFolder } = dragState;
    ghost.remove();
    clearDropHighlights();
    document.body.classList.remove("is-dnd");
    treeRoot
      .querySelectorAll(".is-dragging")
      .forEach((n) => n.classList.remove("is-dragging"));
    dragState = null;
    if (commit && dropKey !== null && dropKey !== (fromFolder ?? "")) {
      void moveEntryToFolder(entryId, dropKey);
    }
  }

  function buildEntryRow(e: EntrySummary): HTMLElement {
    const item = el("div", {
      class: "entry-row tree-entry",
      role: "treeitem",
      tabindex: "0",
      title: "Click to open · press-and-hold, then drag to a folder",
    });
    const metaParts = [
      e.username?.trim() || "",
      !e.username?.trim() && e.urls?.[0] ? e.urls[0] : "",
    ].filter(Boolean);

    const body = el("div", { class: "entry-row-body" });
    body.append(el("div", { class: "entry-name", text: e.name }));
    if (metaParts.length > 0) {
      body.append(el("div", { class: "entry-meta", text: metaParts.join(" · ") }));
    }

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

    // —— Press-and-hold → ghost drag between folders ——
    const LONG_MS = 380;
    let pressTimer: ReturnType<typeof setTimeout> | null = null;
    let pressOrigin: { x: number; y: number } | null = null;
    let suppressClick = false;

    const clearPress = () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
      }
      pressOrigin = null;
    };

    const onPointerMove = (ev: PointerEvent) => {
      if (!dragState) {
        // Cancel long-press if user moves before threshold
        if (
          pressOrigin &&
          (Math.abs(ev.clientX - pressOrigin.x) > 8 ||
            Math.abs(ev.clientY - pressOrigin.y) > 8)
        ) {
          clearPress();
        }
        return;
      }
      dragState.ghost.style.transform = `translate(${ev.clientX + 12}px, ${ev.clientY + 12}px)`;
      const zone = document
        .elementFromPoint(ev.clientX, ev.clientY)
        ?.closest("[data-drop-folder]") as HTMLElement | null;
      setActiveDrop(zone);
    };

    const onPointerUp = (ev: PointerEvent) => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("pointercancel", onPointerUp);
      if (dragState) {
        const key = folderKeyFromEl(
          document.elementFromPoint(ev.clientX, ev.clientY),
        );
        suppressClick = true;
        endDrag(true, key);
        setTimeout(() => {
          suppressClick = false;
        }, 50);
      } else {
        clearPress();
      }
    };

    item.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      if ((ev.target as HTMLElement).closest("button, a, input, select")) return;
      clearPress();
      pressOrigin = { x: ev.clientX, y: ev.clientY };
      pressTimer = setTimeout(() => {
        pressTimer = null;
        // Start drag
        const ghost = el("div", { class: "drag-ghost" });
        ghost.append(el("strong", { text: e.name }));
        if (e.username) {
          ghost.append(el("span", { class: "meta", text: e.username }));
        }
        ghost.style.transform = `translate(${ev.clientX + 12}px, ${ev.clientY + 12}px)`;
        document.body.append(ghost);
        document.body.classList.add("is-dnd");
        item.classList.add("is-dragging");
        dragState = {
          entryId: e.id,
          entryName: e.name,
          fromFolder: e.folder_id,
          ghost,
          activeDrop: null,
        };
        // Expand all folders so drop targets are visible
        expandedFolders.add("");
        for (const f of folders) expandedFolders.add(f.id);
        void refreshTree();
        try {
          item.setPointerCapture(ev.pointerId);
        } catch {
          /* ignore */
        }
      }, LONG_MS);

      window.addEventListener("pointermove", onPointerMove);
      window.addEventListener("pointerup", onPointerUp);
      window.addEventListener("pointercancel", onPointerUp);
    });

    item.addEventListener("click", (ev) => {
      if (suppressClick || dragState) {
        ev.preventDefault();
        ev.stopPropagation();
        return;
      }
      void showEntry(e);
    });
    item.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        void showEntry(e);
      }
    });
    return item;
  }

  function buildFolderGroup(
    key: string,
    title: string,
    entries: EntrySummary[],
    opts?: { canDelete?: boolean; folderId?: string },
  ): HTMLElement | null {
    if (isSearching() && entries.length === 0) return null;

    const open =
      isSearching() && !userCollapsedWhileSearch
        ? entries.length > 0
        : expandedFolders.has(key);

    const group = el("div", {
      class: open ? "tree-folder open" : "tree-folder",
      role: "group",
      "data-drop-folder": key,
    });
    const header = el("div", {
      class: "tree-folder-header",
      role: "treeitem",
      "aria-expanded": open ? "true" : "false",
      tabindex: "0",
      "data-drop-folder": key,
    });
    const chev = el("span", {
      class: "tree-chevron",
      text: open ? "▾" : "▸",
      "aria-hidden": "true",
    });
    const icon = el("span", {
      class: "tree-folder-icon",
      text: "▸",
      "aria-hidden": "true",
    });
    // Use a folder glyph via CSS; keep text minimal
    icon.textContent = "";
    const nameEl = el("span", { class: "tree-folder-name", text: title });
    const countEl = el("span", {
      class: "tree-folder-count",
      text: String(entries.length),
    });
    header.append(chev, icon, nameEl, countEl);

    if (opts?.canDelete && opts.folderId) {
      const del = el("button", {
        type: "button",
        class: "tree-folder-del",
        text: "×",
        title: "Delete folder",
      }) as HTMLButtonElement;
      del.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (
          !confirm(
            `Delete folder “${title}”? Entries become uncategorized.`,
          )
        ) {
          return;
        }
        await client.request({ op: "delete_folder", id: opts.folderId! });
        expandedFolders.delete(opts.folderId!);
        await refreshTree();
      });
      header.append(del);
    }

    const toggle = () => {
      if (isSearching()) userCollapsedWhileSearch = true;
      if (expandedFolders.has(key)) expandedFolders.delete(key);
      else {
        expandedFolders.add(key);
        if (key) preferredFolderId = key;
      }
      void refreshTree();
    };
    header.addEventListener("click", (ev) => {
      if ((ev.target as HTMLElement).closest(".tree-folder-del")) return;
      toggle();
    });
    header.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        toggle();
      }
    });

    group.append(header);

    if (open) {
      const children = el("div", {
        class: "tree-folder-children",
        role: "group",
        "data-drop-folder": key,
      });
      if (entries.length === 0) {
        children.append(
          el("div", {
            class: "tree-empty",
            text: isSearching() ? "No matches" : "No entries in this folder",
          }),
        );
      } else {
        for (const e of entries) {
          children.append(buildEntryRow(e));
        }
      }
      group.append(children);
    }

    return group;
  }

  async function refreshFolders() {
    const resp = await client.request({ op: "list_folders" });
    folders = resp.type === "folders" ? resp.folders : [];
  }

  async function refreshTree() {
    await refreshFolders();
    const query = search.value.trim() || null;
    const resp = await client.request({
      op: "list_summaries",
      query,
    });
    treeRoot.innerHTML = "";
    if (resp.type !== "summaries") {
      const msg = resp.type === "error" ? resp.message : "Failed to load";
      treeRoot.append(el("div", { class: "tree-empty", text: msg }));
      return;
    }
    allSummaries = resp.entries;
    rebuildTagFilterOptions();

    let entries = resp.entries.filter((e) => entryMatchesFilters(e, true));
    if (tagFilter) {
      entries = entries.filter((e) => tagMatches(e.tags, tagFilter!));
    }

    // Auto-expand folders that have matches when searching
    if (isSearching() && !userCollapsedWhileSearch) {
      expandedFolders.clear();
      for (const e of entries) {
        expandedFolders.add(e.folder_id ?? "");
      }
    }

    const byFolder = new Map<string, EntrySummary[]>();
    byFolder.set("", []);
    for (const f of folders) byFolder.set(f.id, []);
    for (const e of entries) {
      const key = e.folder_id && byFolder.has(e.folder_id) ? e.folder_id : "";
      byFolder.get(key)!.push(e);
    }

    // Result summary when filtering
    if (isSearching()) {
      treeRoot.append(
        el("div", {
          class: "tree-result-banner",
          text:
            entries.length === 0
              ? "No matching entries"
              : `${entries.length} match${entries.length === 1 ? "" : "es"}`,
        }),
      );
    }

    // Named folders (sorted by name)
    const sortedFolders = [...folders].sort((a, b) =>
      a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
    );
    for (const f of sortedFolders) {
      const groupEntries = byFolder.get(f.id) ?? [];
      // When not searching, still show empty folders
      if (!isSearching() || groupEntries.length > 0) {
        const g = buildFolderGroup(f.id, f.name, groupEntries, {
          canDelete: true,
          folderId: f.id,
        });
        if (g) treeRoot.append(g);
      }
    }

    // Uncategorized
    const loose = byFolder.get("") ?? [];
    if (!isSearching() || loose.length > 0) {
      const g = buildFolderGroup("", "Uncategorized", loose);
      if (g) treeRoot.append(g);
    }

    if (!isSearching() && entries.length === 0 && folders.length === 0) {
      treeRoot.append(
        el("div", {
          class: "tree-empty tree-empty-hero",
          text: "No entries yet — create one with New entry",
        }),
      );
    }
  }

  // Aliases used by rest of renderVault (sync, editor save, etc.)
  async function refreshList() {
    await refreshTree();
  }

  expandAllBtn.addEventListener("click", () => {
    userCollapsedWhileSearch = false;
    expandedFolders.add("");
    for (const f of folders) expandedFolders.add(f.id);
    void refreshTree();
  });
  collapseAllBtn.addEventListener("click", () => {
    if (isSearching()) userCollapsedWhileSearch = true;
    expandedFolders.clear();
    void refreshTree();
  });

  addFolderBtn.addEventListener("click", async () => {
    const name = window.prompt("Folder name");
    if (!name?.trim()) return;
    const folder = emptyFolder(name.trim());
    const r = await client.request({ op: "upsert_folder", folder });
    if (r.type === "error") {
      window.alert(r.message);
      return;
    }
    if (folder.id) expandedFolders.add(folder.id);
    // upsert may assign id in response — re-list
    await refreshTree();
  });

  search.addEventListener("input", () => {
    userCollapsedWhileSearch = false;
    void refreshTree();
  });

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
    if (preferredFolderId && folders.some((f) => f.id === preferredFolderId)) {
      e.folder_id = preferredFolderId;
    }
    renderEditor(e, true);
  });

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
  openSection: "autolock" | "passphrase" | "recovery" | "multidevice" = "autolock",
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

  // —— Multi-device (optional VaultSync / Export) ——
  const c = caps();
  addSection(
    "multidevice",
    "Multi-device & Sync",
    c.canMeshSync ? "Peer online · mesh ready" : "Optional · peer not ready",
    (body) => {
      body.append(
        el("p", {
          class: "hint",
          text:
            "Your vault is local-first. Multi-device is opt-in after you create or import a vault.",
        }),
      );

      // Live peer status card
      const peerCard = el("div", {
        class: `peer-status-card ${c.peerOk ? "is-online" : c.blocked ? "is-blocked" : "is-offline"}`,
      });
      peerCard.append(
        el("div", { class: "peer-status-row" }, [
          el("span", {
            class: `peer-dot ${c.peerOk ? "on" : c.blocked ? "warn" : "off"}`,
          }),
          el("strong", {
            text: c.peerOk
              ? "Freenet peer detected"
              : c.blocked
                ? "Peer blocked on this page"
                : "No Freenet peer detected",
          }),
        ]),
      );
      peerCard.append(
        el("p", {
          class: "peer-status-detail",
          text: c.detail,
        }),
      );
      const recheck = el("button", {
        type: "button",
        class: "btn-ghost",
        text: "Check again",
      }) as HTMLButtonElement;
      recheck.addEventListener("click", async () => {
        recheck.disabled = true;
        recheck.textContent = "Checking…";
        await refreshPeerProbe(true);
        recheck.disabled = false;
        recheck.textContent = "Check again";
        // Rebuild settings to refresh greys / copy
        overlay.remove();
        showSettingsModal(onSaved, "multidevice");
      });
      peerCard.append(recheck);
      body.append(peerCard);

      // Capability rows
      body.append(el("h3", { class: "settings-subhead", text: "What you can do" }));

      const row = (
        enabled: boolean,
        title: string,
        blurb: string,
        action?: HTMLElement,
      ) => {
        const r = el("div", {
          class: enabled ? "feature-row" : "feature-row feature-row-disabled",
        });
        r.append(
          el("div", { class: "feature-row-text" }, [
            el("strong", { text: title }),
            el("span", { class: "meta", text: blurb }),
          ]),
        );
        if (action) {
          if (!enabled) {
            action.setAttribute("disabled", "true");
            action.classList.add("btn-disabled");
            (action as HTMLButtonElement).disabled = true;
          }
          r.append(action);
        }
        body.append(r);
      };

      row(
        true,
        "Export / Import backup",
        "Always available. Encrypted .aegis file — best for any PC without Freenet.",
      );

      const syncNow = el("button", {
        class: "primary",
        text: "Sync now",
      }) as HTMLButtonElement;
      syncNow.addEventListener("click", () => {
        overlay.remove();
        window.dispatchEvent(new CustomEvent("aegis-sync-now"));
      });
      row(
        c.canMeshSync && Boolean(client.freenetApi),
        "Freenet mesh Sync",
        c.canMeshSync && client.freenetApi
          ? "Push/pull encrypted revisions under your owner key (master passphrase)."
          : !c.canMeshSync
            ? c.blocked
              ? "Unavailable on HTTPS static hosting. Use local Freenet HTTP UI."
              : "Requires a running Freenet peer (`freenet local`)."
            : "Switch to Freenet mode (below) while a peer is online.",
        syncNow,
      );

      // Switch to Freenet mode
      body.append(el("h3", { class: "settings-subhead", text: "Enable Freenet backend" }));
      const freenetLink = el("a", {
        href: "?mode=freenet&register=1",
        class: c.canUseFreenetMode ? "button-link" : "button-link button-link-disabled",
        text: c.canUseFreenetMode
          ? "Open Freenet mode & register delegate"
          : "Freenet mode (peer required)",
      }) as HTMLAnchorElement;
      if (!c.canUseFreenetMode) {
        freenetLink.setAttribute("aria-disabled", "true");
        freenetLink.addEventListener("click", (e) => {
          e.preventDefault();
          window.alert(
            c.blocked
              ? "Browsers block Freenet WebSockets from HTTPS pages like GitHub Pages.\n\n" +
                "Run: freenet local\nThen open Aegis at http://127.0.0.1:7509/… or http://localhost with Vite/serve."
              : "Start a Freenet peer first:\n\n  freenet local\n\nThen click Check again, and open Freenet mode.",
          );
        });
      } else {
        freenetLink.addEventListener("click", (e) => {
          if (
            !confirm(
              "Freenet mode uses the peer’s secret store (separate from the browser vault on this page). " +
                "Export a backup first if you want to move this vault. Continue?",
            )
          ) {
            e.preventDefault();
          }
        });
      }
      body.append(freenetLink);
      body.append(
        el("p", {
          class: "hint",
          text:
            "Identity is your master passphrase → owner key. Not a browser profile, Google, or Microsoft account.",
        }),
      );
    },
  );

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
        kdf_profile: defaultKdfProfile(),
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
          kdf_profile: defaultKdfProfile(),
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
