/**
 * Freenet peer detection — drives which multi-device features are available.
 *
 * The peer is a native process (e.g. `freenet local`), not the website itself.
 * GitHub Pages (HTTPS) often cannot open ws://127.0.0.1 (mixed content).
 */

export type PeerReason =
  | "ok"
  | "offline"
  | "mixed_content"
  | "timeout"
  | "error"
  | "unknown";

export type PeerProbe = {
  reachable: boolean;
  host: string;
  wsUrl: string;
  reason: PeerReason;
  /** Short label for chips */
  label: string;
  /** Longer help for settings */
  detail: string;
  checkedAt: number;
};

let lastProbe: PeerProbe | null = null;
let inflight: Promise<PeerProbe> | null = null;

export function getCachedPeerProbe(): PeerProbe | null {
  return lastProbe;
}

/** Where the UI expects a Freenet peer WebSocket. */
export function resolvePeerHost(): string {
  const params = new URLSearchParams(location.search);
  const ws = params.get("ws");
  if (ws) return ws.replace(/^wss?:\/\//, "").replace(/\/.*$/, "");

  if (location.port === "5173" || location.port === "4173") {
    return "127.0.0.1:7509";
  }
  if (
    location.port === "7509" ||
    location.pathname.includes("/v1/contract/web/")
  ) {
    return location.host;
  }
  // Static hosts (GitHub Pages, etc.)
  return "127.0.0.1:7509";
}

function buildWsUrl(host: string): string {
  const secure =
    location.protocol === "https:" &&
    !/^127\.|localhost/i.test(host.split(":")[0] ?? "");
  const protocol = secure ? "wss:" : "ws:";
  return `${protocol}//${host}/v1/contract/command`;
}

function isHttpsPageToLocalPeer(host: string): boolean {
  if (location.protocol !== "https:") return false;
  const h = host.split(":")[0] ?? "";
  const pageLocal =
    location.hostname === "localhost" ||
    location.hostname === "127.0.0.1" ||
    location.hostname === "[::1]";
  const peerLocal =
    h === "localhost" || h === "127.0.0.1" || h === "[::1]";
  // HTTPS public site → local peer = mixed content
  return peerLocal && !pageLocal;
}

/**
 * Lightweight reachability check (WebSocket open).
 * Does not register a delegate.
 */
export async function probeFreenetPeer(
  opts?: { force?: boolean; timeoutMs?: number },
): Promise<PeerProbe> {
  if (!opts?.force && lastProbe && Date.now() - lastProbe.checkedAt < 8_000) {
    return lastProbe;
  }
  if (inflight && !opts?.force) return inflight;

  inflight = (async () => {
    const host = resolvePeerHost();
    const wsUrl = buildWsUrl(host);
    const timeoutMs = opts?.timeoutMs ?? 2800;

    if (isHttpsPageToLocalPeer(host)) {
      const probe: PeerProbe = {
        reachable: false,
        host,
        wsUrl,
        reason: "mixed_content",
        label: "Peer blocked",
        detail:
          "This page is served over HTTPS (e.g. GitHub Pages). Browsers block WebSockets to a local Freenet peer (ws://127.0.0.1). " +
          "For mesh Sync: run `freenet local` and open Aegis from the peer (http://127.0.0.1:7509/…) or via http://localhost. " +
          "Export/Import still works from this page without a peer.",
        checkedAt: Date.now(),
      };
      lastProbe = probe;
      return probe;
    }

    const result = await new Promise<PeerProbe>((resolve) => {
      let settled = false;
      const finish = (p: PeerProbe) => {
        if (settled) return;
        settled = true;
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        resolve(p);
      };

      let ws: WebSocket;
      try {
        ws = new WebSocket(wsUrl);
      } catch (e) {
        finish({
          reachable: false,
          host,
          wsUrl,
          reason: "error",
          label: "Peer offline",
          detail: `Could not open ${wsUrl} (${e instanceof Error ? e.message : String(e)}). Start with: freenet local`,
          checkedAt: Date.now(),
        });
        return;
      }

      const timer = setTimeout(() => {
        finish({
          reachable: false,
          host,
          wsUrl,
          reason: "timeout",
          label: "Peer offline",
          detail: `No response from ${host} within ${timeoutMs}ms. Is \`freenet local\` running?`,
          checkedAt: Date.now(),
        });
      }, timeoutMs);

      ws.onopen = () => {
        clearTimeout(timer);
        finish({
          reachable: true,
          host,
          wsUrl,
          reason: "ok",
          label: "Peer online",
          detail: `Freenet peer reachable at ${host}. Mesh Sync and Freenet mode can use this peer.`,
          checkedAt: Date.now(),
        });
      };
      ws.onerror = () => {
        clearTimeout(timer);
        finish({
          reachable: false,
          host,
          wsUrl,
          reason: "offline",
          label: "Peer offline",
          detail: `Cannot reach Freenet at ${host}. Start a peer with \`freenet local\` (default port 7509), then refresh.`,
          checkedAt: Date.now(),
        });
      };
      ws.onclose = () => {
        // if already finished via open/error/timeout, ignore
      };
    });

    lastProbe = result;
    return result;
  })();

  try {
    return await inflight;
  } finally {
    inflight = null;
  }
}

/** Human-facing capability matrix for UI. */
export function meshCapabilities(probe: PeerProbe | null, freenetClientConnected: boolean) {
  const peerOk = freenetClientConnected || !!probe?.reachable;
  const blocked = probe?.reason === "mixed_content";
  return {
    peerOk,
    blocked,
    /** Live VaultSync Put/Get over Freenet */
    canMeshSync: peerOk && !blocked,
    /** Switch to ?mode=freenet useful */
    canUseFreenetMode: peerOk && !blocked,
    /** Export always */
    canExport: true,
    reason: probe?.reason ?? "unknown",
    label: freenetClientConnected
      ? "Peer online"
      : probe?.label ?? "Checking peer…",
    detail: freenetClientConnected
      ? "Connected to Freenet for this session."
      : probe?.detail ?? "Checking for a Freenet peer…",
    host: probe?.host ?? resolvePeerHost(),
  };
}
