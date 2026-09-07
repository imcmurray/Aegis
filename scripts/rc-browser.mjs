/**
 * Aegis v2 release-candidate browser validation.
 * Production UI/WASM only (no mock). Isolated IndexedDB per context.
 *
 *   node scripts/rc-browser.mjs --browser chromium --url http://127.0.0.1:4173/
 */
import { chromium, firefox } from "playwright";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const URL = process.argv.includes("--url")
  ? process.argv[process.argv.indexOf("--url") + 1]
  : "http://127.0.0.1:4173/";
const BROWSER = process.argv.includes("--browser")
  ? process.argv[process.argv.indexOf("--browser") + 1]
  : "chromium";

const PW = "correct horse battery staple";
const PW2 = "another horse battery staple";
const PW3 = "third horse battery staple";
const BACKUP_PW = "backup horse battery";
const TIMEOUT = 180_000;

const results = [];
function rec(name, ok, detail = "") {
  results.push({ name, ok, detail });
  const mark = ok ? "PASS" : "FAIL";
  console.log(`${mark}  ${name}${detail ? " — " + detail : ""}`);
}

function asciiHas(bytes, needle) {
  const n = Buffer.from(needle, "utf8");
  const b = Buffer.from(bytes);
  return b.includes(n);
}

/** MemoryStore CBOR-encodes Vec<u8> as an array of integers, not a byte string. */
function cborSeqHas(bytes, needle) {
  const n = Buffer.from(needle, "utf8");
  const enc = [];
  for (const c of n) {
    if (c <= 23) enc.push(c);
    else enc.push(0x18, c);
  }
  return Buffer.from(bytes).includes(Buffer.from(enc));
}

function storeHas(bytes, needle) {
  return asciiHas(bytes, needle) || cborSeqHas(bytes, needle);
}

function printableTokens(bytes) {
  const b = Buffer.from(bytes);
  const out = [];
  let cur = "";
  for (const c of b) {
    if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
    else {
      if (cur.length >= 8) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= 8) out.push(cur);
  return [...new Set(out)].slice(0, 40);
}

async function dumpIdb(page) {
  return page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const r = indexedDB.open("aegis-browser-vault", 1);
      r.onupgradeneeded = () => {
        if (!r.result.objectStoreNames.contains("secrets")) {
          r.result.createObjectStore("secrets");
        }
      };
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    return await new Promise((resolve, reject) => {
      const tx = db.transaction("secrets", "readonly");
      const g = tx.objectStore("secrets").get("v1");
      g.onsuccess = () => {
        const v = g.result;
        if (!v) return resolve([]);
        const u8 = v instanceof Uint8Array ? v : new Uint8Array(v);
        resolve([...u8]);
      };
      g.onerror = () => reject(g.error);
    });
  });
}

async function waitVault(page) {
  await page.getByRole("button", { name: "New entry" }).waitFor({ timeout: TIMEOUT });
}

async function createVault(page, passphrase) {
  await page.getByRole("heading", { name: "Create vault" }).waitFor({ timeout: TIMEOUT });
  await page.locator("#pw").fill(passphrase);
  await page.locator("#pw2").fill(passphrase);
  await page.getByRole("button", { name: "Create vault" }).click();
  await waitVault(page);
}

async function addEntry(page, name, password) {
  await page.getByRole("button", { name: "New entry" }).click();
  await page.locator("#entry-name").fill(name);
  await page.locator("#entry-password").fill(password);
  await page.locator("#entry-username").fill("user-" + name);
  await page.getByRole("button", { name: "Add" }).click();
  await page.locator("#status-line", { hasText: "Saved" }).waitFor({ timeout: TIMEOUT });
  await page.locator(".entry-name", { hasText: name }).waitFor({ timeout: TIMEOUT });
}

async function openSettings(page, sectionTitle) {
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("heading", { name: "Settings" }).waitFor();
  await page.locator(".settings-section-toggle", { hasText: sectionTitle }).click();
}

async function closeSettings(page) {
  const close = page.getByRole("button", { name: "Close" });
  if (await close.count()) await close.last().click();
  await page.getByRole("heading", { name: "Settings" }).waitFor({ state: "hidden", timeout: TIMEOUT }).catch(() => {});
}

async function waitSettingsNote(page, text) {
  await page.locator(".settings-note", { hasText: text }).waitFor({ timeout: TIMEOUT });
  return (await page.locator(".settings-note").innerText()).trim();
}

async function run(browserType) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-rc-"));
  const browser = await browserType.launch({ headless: true });
  const version = browser.version();
  rec("browser-launch", true, `${BROWSER} ${version}`);

  const context = await browser.newContext({ acceptDownloads: true });
  context.setDefaultTimeout(TIMEOUT);
  const page = await context.newPage();
  page.on("pageerror", (err) => rec("pageerror", false, String(err)));
  page.on("dialog", async (d) => {
    if (d.type() === "prompt") await d.accept(BACKUP_PW);
    else await d.accept();
  });

  await page.goto(URL, { waitUntil: "networkidle" });
  rec("load-production-ui", await page.getByRole("heading", { name: "Create vault" }).isVisible());

  // 1. Create v2 vault
  await createVault(page, PW);
  const fmt = await page.locator(".badge", { hasText: "v2" }).count();
  rec("create-v2-vault", fmt > 0, "format badge v2");
  rec("create-form-unmounted", (await page.locator("#pw").count()) === 0);

  // 2. CRUD
  await addEntry(page, "Mail", "inbox-secret");
  await page.locator(".entry-name", { hasText: "Mail" }).click();
  await page.locator("#entry-notes").fill("updated-note");
  await page.getByRole("button", { name: "Save" }).click();
  await page.locator("#status-line", { hasText: "Saved" }).waitFor({ timeout: TIMEOUT });
  rec("add-edit-entry", true, "Mail saved");
  const entryId = await page.locator(".tree-entry").first().getAttribute("data-entry-id");
  rec("entry-id-in-dom", Boolean(entryId), entryId || "missing data-entry-id");

  await addEntry(page, "Temp", "temp-secret");
  await page.locator(".entry-name", { hasText: "Temp" }).click();
  await page.getByRole("button", { name: "Delete" }).click();
  await page.locator(".entry-name", { hasText: "Temp" }).waitFor({ state: "detached", timeout: TIMEOUT });
  rec("delete-entry", (await page.locator(".entry-name", { hasText: "Temp" }).count()) === 0);

  const vaultId = await page.locator("[data-vault-id]").first().getAttribute("data-vault-id");
  rec("vault-id-visible", Boolean(vaultId), vaultId || "missing");

  // 3. Lock, reload, unlock; no session key in IDB
  await page.getByRole("button", { name: "Lock" }).click();
  await page.getByRole("heading", { name: "Unlock vault" }).waitFor({ timeout: TIMEOUT });
  rec("lock", true);
  await page.reload({ waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "Unlock vault" }).waitFor({ timeout: TIMEOUT });
  rec("reload-stays-locked", true);

  const idbLocked = await dumpIdb(page);
  const idbTokens = printableTokens(idbLocked).filter((t) => /aegis|AEGIS/i.test(t));
  rec(
    "no-v1-session-in-idb",
    !storeHas(idbLocked, "aegis/v1/session"),
    `${idbLocked.length} bytes tokens=${idbTokens.join(",")}`,
  );
  rec("no-v2-session-key", !storeHas(idbLocked, "aegis/v2/session"));
  rec(
    "idb-has-v2-envelope",
    storeHas(idbLocked, "aegis/v2/envelope") || storeHas(idbLocked, "AEGIS_VAULT_V2"),
    `seq=${cborSeqHas(idbLocked, "aegis/v2/envelope")} magic=${storeHas(idbLocked, "AEGIS_VAULT_V2")} ${idbLocked.length}B`,
  );

  await page.locator("input[type=password]").first().fill(PW);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await waitVault(page);
  await page.locator(".entry-name", { hasText: "Mail" }).waitFor({ timeout: TIMEOUT });
  rec("unlock-from-idb", await page.locator(".entry-name", { hasText: "Mail" }).isVisible());

  // 4. Change passphrase (RootSecret/epoch unchanged — identity badge stays)
  const idBefore = await page.locator("[data-vault-id]").first().getAttribute("data-vault-id");
  await openSettings(page, "Change master passphrase");
  await page.getByPlaceholder("Current passphrase", { exact: true }).fill(PW);
  await page.getByPlaceholder("New passphrase", { exact: true }).fill(PW2);
  await page.getByPlaceholder("Confirm new passphrase", { exact: true }).fill(PW2);
  await page.getByRole("button", { name: "Change passphrase" }).click();
  const pwNote = await waitSettingsNote(page, "Passphrase updated");
  rec("passphrase-fields-cleared",
    (await page.getByPlaceholder("Current passphrase", { exact: true }).inputValue()) === "" &&
    (await page.getByPlaceholder("New passphrase", { exact: true }).inputValue()) === "",
    pwNote,
  );
  await closeSettings(page);
  await page.getByRole("button", { name: "Lock" }).click();
  await page.getByRole("heading", { name: "Unlock vault" }).waitFor({ timeout: TIMEOUT });
  await page.locator("input[type=password]").first().fill(PW);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  const oldPwRejected = await page.locator(".error").count();
  rec("old-passphrase-rejected", oldPwRejected > 0 || (await page.getByRole("heading", { name: "Unlock vault" }).isVisible()));
  if (await page.getByRole("heading", { name: "Unlock vault" }).isVisible()) {
    await page.locator("input[type=password]").first().fill(PW2);
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
  }
  await waitVault(page);
  const idAfterPw = await page.locator("[data-vault-id]").first().getAttribute("data-vault-id");
  rec("passphrase-change-keeps-vault-id", idBefore === idAfterPw, `${idBefore} → ${idAfterPw}`);

  // 5. Export backup
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export" }).click(),
  ]);
  const backupPath = path.join(tmp, "vault.aegis");
  await download.saveAs(backupPath);
  rec("export-aegis-backup", fs.existsSync(backupPath) && fs.statSync(backupPath).size > 32, download.suggestedFilename());

  // 6. Generate Recovery Kit
  await openSettings(page, "Recovery Kit");
  const [kitDl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Generate Recovery Kit" }).click(),
  ]);
  const kitPath = path.join(tmp, "vault.aegis-recovery");
  await kitDl.saveAs(kitPath);
  const recSecret = (await page.locator(".recovery-key-display").innerText()).trim();
  rec("generate-recovery-kit", recSecret.startsWith("AEGIS2-") && fs.statSync(kitPath).size > 32, recSecret.slice(0, 16) + "…");
  rec("recovery-secret-one-time-display", recSecret.length > 20);
  const [kit2dl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Re-download Recovery Kit" }).click(),
  ]);
  const kit2Path = path.join(tmp, "vault-redownload.aegis-recovery");
  await kit2dl.saveAs(kit2Path);
  rec("redownload-recovery-kit", fs.statSync(kit2Path).size > 32);
  await closeSettings(page);
  rec("recovery-secret-gone-after-close", (await page.locator(".recovery-key-display").count()) === 0);
  await openSettings(page, "Recovery Kit");
  rec(
    "recovery-secret-not-reshown",
    (await page.locator(".recovery-key-display").count()) === 0,
  );
  await closeSettings(page);
  const idbAfterKit = await dumpIdb(page);
  rec(
    "recovery-secret-not-in-idb",
    !storeHas(idbAfterKit, recSecret) && !storeHas(idbAfterKit, "AEGIS2-"),
  );

  // 7. Local sync button (browser mode = local only) + Settings sharing/sync flows
  await page.getByRole("button", { name: "Sync" }).click();
  await page.locator("#status-line", { hasText: /Sync:/ }).waitFor({ timeout: TIMEOUT });
  rec("local-sync-click", true, (await page.locator("#status-line").innerText()).trim());
  await openSettings(page, "Multi-device & Sync");
  rec(
    "settings-multidevice-section",
    await page.getByRole("button", { name: "Sync now" }).isVisible(),
  );
  rec(
    "settings-freenet-sync-disabled-in-browser",
    await page.getByRole("button", { name: "Sync now" }).isDisabled(),
  );
  await closeSettings(page);

  // 8. Settings share export identity
  await openSettings(page, "Hybrid share");
  rec("settings-share-section", await page.getByRole("button", { name: "Export my share identity" }).isVisible());
  const [idDl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export my share identity" }).click(),
  ]);
  const identA = path.join(tmp, "a-identity.bin");
  await idDl.saveAs(identA);
  rec("export-share-identity", fs.statSync(identA).size > 32);
  await closeSettings(page);

  const liveId = await page.locator("[data-vault-id]").first().getAttribute("data-vault-id");

  // 9. Backup restore in a fresh profile → NEW identity
  const ctx2 = await browser.newContext({ acceptDownloads: true });
  ctx2.setDefaultTimeout(TIMEOUT);
  const page2 = await ctx2.newPage();
  page2.on("pageerror", (err) => rec("pageerror", false, String(err)));
  page2.on("dialog", async (d) => d.accept());
  await page2.goto(URL, { waitUntil: "networkidle" });
  await page2.getByRole("heading", { name: "Import backup" }).waitFor();
  await page2.locator('input[accept=".aegis,application/octet-stream"]').first().setInputFiles(backupPath);
  await page2.getByPlaceholder("Backup / export passphrase").fill(BACKUP_PW);
  await page2.getByPlaceholder("New v2 vault passphrase").first().fill(PW3);
  await page2.getByRole("button", { name: "Import", exact: true }).click();
  await waitVault(page2);
  const restoredId = await page2.locator("[data-vault-id]").first().getAttribute("data-vault-id");
  rec(
    "backup-restore-new-identity",
    Boolean(restoredId) && restoredId !== liveId,
    `live=${liveId} restored=${restoredId}`,
  );
  rec("backup-restore-has-mail", await page2.locator(".entry-name", { hasText: "Mail" }).isVisible());
  await ctx2.close();

  // 10. Empty-install identity-preserving recovery
  const ctx3 = await browser.newContext({ acceptDownloads: true });
  ctx3.setDefaultTimeout(TIMEOUT);
  const page3 = await ctx3.newPage();
  page3.on("pageerror", (err) => rec("pageerror", false, String(err)));
  page3.on("dialog", async (d) => d.accept());
  await page3.goto(URL, { waitUntil: "networkidle" });
  await page3.getByRole("heading", { name: "Disaster recovery (same identity)" }).waitFor();
  const recoverCard = page3.locator(".card", { hasText: "Disaster recovery" });
  await recoverCard.locator('input[accept=".aegis-recovery,application/octet-stream"]').setInputFiles(kitPath);
  await recoverCard.getByPlaceholder("Recovery secret (AEGIS2-…)").fill(recSecret);
  await recoverCard.locator('input[accept=".aegis,application/octet-stream"]').setInputFiles(backupPath);
  await recoverCard.getByPlaceholder("Backup passphrase").fill(BACKUP_PW);
  await recoverCard.getByPlaceholder("New v2 vault passphrase (not the recovery secret)").fill(PW3);
  await recoverCard.getByRole("button", { name: "Restore identity + backup data" }).click();
  await waitVault(page3);
  const recoveredId = await page3.locator("[data-vault-id]").first().getAttribute("data-vault-id");
  rec(
    "kit-plus-backup-same-identity",
    recoveredId === liveId,
    `live=${liveId} recovered=${recoveredId}`,
  );
  rec("kit-plus-backup-has-mail", await page3.locator(".entry-name", { hasText: "Mail" }).isVisible());
  await ctx3.close();

  // 11. Lost-passphrase recovery on original context
  await page.getByRole("button", { name: "Lock" }).click();
  await page.getByRole("heading", { name: "Unlock vault" }).waitFor({ timeout: TIMEOUT });
  await page.getByText("Forgot passphrase (Recovery Kit)").click();
  const forgot = page.locator(".unlock-alt", { hasText: "Forgot passphrase" });
  await forgot.locator('input[accept=".aegis-recovery,application/octet-stream"]').setInputFiles(kitPath);
  await forgot.getByPlaceholder("Recovery secret (AEGIS2-…)").fill(recSecret);
  await forgot.getByPlaceholder("New v2 vault passphrase (not the recovery secret)").fill(PW3);
  await forgot.getByRole("button", { name: "Set new passphrase with Recovery Kit" }).click();
  await waitVault(page);
  rec("lost-passphrase-recovery", await page.locator(".entry-name", { hasText: "Mail" }).isVisible());
  rec(
    "lost-passphrase-same-identity",
    (await page.locator("[data-vault-id]").first().getAttribute("data-vault-id")) === liveId,
  );

  // 12. Hybrid share with a second vault
  const ctxB = await browser.newContext({ acceptDownloads: true });
  ctxB.setDefaultTimeout(TIMEOUT);
  const pageB = await ctxB.newPage();
  pageB.on("pageerror", (err) => rec("pageerror", false, String(err)));
  pageB.on("dialog", async (d) => d.accept());
  await pageB.goto(URL, { waitUntil: "networkidle" });
  await createVault(pageB, PW);
  await openSettings(pageB, "Hybrid share");
  const [idBdl] = await Promise.all([
    pageB.waitForEvent("download"),
    pageB.getByRole("button", { name: "Export my share identity" }).click(),
  ]);
  const identB = path.join(tmp, "b-identity.bin");
  await idBdl.saveAs(identB);
  await closeSettings(pageB);

  await openSettings(page, "Hybrid share");
  await page.getByPlaceholder("Entry id to share").fill(entryId || "");
  await page.locator(".settings-section-body input[type=file]").first().setInputFiles(identB);
  const [shareDl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Create share envelope" }).click(),
  ]);
  const sharePath = path.join(tmp, "share.bin");
  await shareDl.saveAs(sharePath);
  rec("create-hybrid-share", fs.statSync(sharePath).size > 32);
  await closeSettings(page);

  await openSettings(pageB, "Hybrid share");
  const filesB = pageB.locator(".settings-section-body input[type=file]");
  await filesB.nth(1).setInputFiles(sharePath);
  await filesB.nth(2).setInputFiles(identA);
  const openDlg = pageB.waitForEvent("dialog");
  await pageB.getByRole("button", { name: "Open share envelope" }).click();
  const opened = await openDlg;
  rec("open-share-dialog", /Opened share|Mail/i.test(opened.message()), opened.message());

  // 13. Rotate B, outstanding old-epoch share must fail
  await closeSettings(pageB);
  await openSettings(pageB, "Rotate cryptographic keys");
  await pageB.getByPlaceholder("Current master passphrase").fill(PW);
  await pageB.getByRole("button", { name: "Rotate keys" }).click();
  const rotNote = await waitSettingsNote(pageB, /Keys rotated \(epoch/);
  rec("rotate-keys-epoch", /epoch \d+/.test(rotNote), rotNote);
  rec(
    "rotate-without-prior-kit-has-no-secret",
    (await pageB.locator(".recovery-key-display").count()) === 0,
  );
  await closeSettings(pageB);

  await openSettings(pageB, "Hybrid share");
  const filesB2 = pageB.locator(".settings-section-body input[type=file]");
  await filesB2.nth(1).setInputFiles(sharePath);
  await filesB2.nth(2).setInputFiles(identA);
  const rejectDlg = pageB.waitForEvent("dialog");
  await pageB.getByRole("button", { name: "Open share envelope" }).click();
  const rejected = await rejectDlg;
  rec(
    "old-epoch-share-rejected",
    /error|invalid|epoch|unauthorized|cannot|identity/i.test(rejected.message()),
    rejected.message(),
  );
  await closeSettings(pageB);
  await ctxB.close();

  // Recovery handling on the original vault (which has a Recovery Kit).
  await openSettings(page, "Rotate cryptographic keys");
  await page.getByPlaceholder("Current master passphrase").fill(PW3);
  await page.getByRole("button", { name: "Rotate keys" }).click();
  const rotA = await waitSettingsNote(page, /Keys rotated \(epoch/);
  rec("rotate-original-epoch", /epoch \d+/.test(rotA), rotA);
  const minted = (await page.locator(".recovery-key-display").innerText()).trim();
  rec(
    "rotate-mints-new-recovery-secret",
    minted.startsWith("AEGIS2-") && minted !== recSecret,
    minted.slice(0, 16) + "…",
  );
  await closeSettings(page);

  await context.close();
  await browser.close();
  return version;
}

const launcher = BROWSER === "firefox" ? firefox : chromium;
let failed = false;
try {
  await run(launcher);
} catch (e) {
  rec("uncaught", false, String(e && e.stack ? e.stack : e));
  failed = true;
}
const out = path.join(os.tmpdir(), `aegis-rc-${BROWSER}.json`);
fs.writeFileSync(out, JSON.stringify({ browser: BROWSER, results }, null, 2));
console.log("wrote", out);
const nfail = results.filter((r) => !r.ok).length;
console.log(`summary ${BROWSER}: ${results.length - nfail}/${results.length} passed`);
process.exit(nfail || failed ? 1 : 0);
