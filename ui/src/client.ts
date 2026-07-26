/**
 * Select vault backend:
 *   browser — default: real crypto in WASM + IndexedDB (GitHub Pages friendly)
 *   freenet — optional: local Freenet peer + vault-delegate
 *   dev     — optional: local Rust HTTP server
 *   mock    — UI-only (legacy; weak crypto)
 */

import { BrowserVaultClient } from "./browserClient";
import { DevVaultClient } from "./devClient";
import {
  tryCreateFreenetClient,
  resolveMode,
  type ClientMode,
  type VaultClient,
} from "./freenet";
import { MockVaultClient } from "./mockVault";

class LabeledMock extends MockVaultClient implements VaultClient {
  readonly label = "mock vault";
}

export type { VaultClient, ClientMode };
export { resolveMode } from "./freenet";

export async function createVaultClient(): Promise<VaultClient> {
  const mode = resolveMode();
  console.log(`[aegis] vault mode=${mode}`);

  if (mode === "dev") {
    const ok = await DevVaultClient.probe();
    if (!ok) {
      console.warn(
        "[aegis] dev server not reachable — start with: cargo run -p aegis-dev-vault-server",
      );
    }
    return new DevVaultClient();
  }

  if (mode === "freenet") {
    const freenet = await tryCreateFreenetClient();
    if (freenet) return freenet;
    console.warn(
      "[aegis] Freenet peer unavailable — falling back to browser vault. " +
        "Start `freenet local` and reload with ?mode=freenet&register=1 to use Freenet.",
    );
    try {
      return await BrowserVaultClient.create();
    } catch (e) {
      console.warn("[aegis] browser vault also failed:", e);
      const m = new LabeledMock();
      (m as { label: string }).label = "mock (freenet offline)";
      return m;
    }
  }

  if (mode === "mock") {
    return new LabeledMock();
  }

  // Default: browser vault (works on GitHub Pages with no peer / no server)
  try {
    return await BrowserVaultClient.create();
  } catch (e) {
    console.error("[aegis] browser vault failed, falling back to mock:", e);
    return new LabeledMock();
  }
}
