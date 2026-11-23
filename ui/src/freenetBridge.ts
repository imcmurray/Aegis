/**
 * Freenet web-container bridge detection.
 *
 * Freenet 0.2.16x serves a web container inside an opaque-origin sandboxed
 * iframe and injects inline scripts into the page, among them a WebSocket shim
 * that relays traffic through the parent shell (postMessage). A native
 * WebSocket from the sandbox is refused by the node's own CSP.
 *
 * Aegis's CSP allows those injected scripts only by their sha256 hashes, which
 * `scripts/publish-freenet.sh` reads from the live node at publish time. If the
 * node is upgraded and its shim changes, the hashes no longer match, the shim
 * is blocked, and every connection fails. In that case, report it plainly
 * instead of a generic "peer offline".
 */

/** True when this page is a Freenet web container (shell or sandboxed frame). */
export function inFreenetWebContainer(): boolean {
  return location.pathname.includes("/v1/contract/web/");
}

/** True when we are inside a Freenet web container but the node's WebSocket shim did not install. */
export function freenetBridgeBlocked(): boolean {
  if (!inFreenetWebContainer()) return false;
  try {
    return /\[native code\]/.test(Function.prototype.toString.call(window.WebSocket));
  } catch {
    return false;
  }
}

export const BRIDGE_BLOCKED_DETAIL =
  "Freenet's connection bridge was blocked by Aegis's Content Security Policy. " +
  "This usually means the Freenet node was upgraded after Aegis was published. " +
  "Republish Aegis to this node with ./scripts/publish-freenet.sh, then reload.";

/**
 * Save a file from inside a Freenet web container.
 *
 * The app runs in a sandboxed, opaque-origin iframe. A `blob:` download made
 * there is `blob:null/…`, which Firefox loads as a frame and the node's shell
 * CSP (`frame-src 'self'`) blocks, so nothing is saved. The shell offers a
 * download relay instead: post `{__freenet_shell__, type: "download",
 * filename, base64, mimeType}` to the parent and it saves the file from its
 * own origin. Limits (enforced by the shell): one download per 2 s, 14 MiB of
 * base64, MIME limited to octet-stream/json/text/csv.
 *
 * The message goes only to the node that serves this page (same host as our
 * URL), never to "*".
 */
export function freenetShellDownload(bytes: Uint8Array, filename: string): void {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  const nodeOrigin = new URL(location.href).origin;
  window.parent.postMessage(
    {
      __freenet_shell__: true,
      type: "download",
      filename,
      base64: btoa(bin),
      mimeType: "application/octet-stream",
    },
    nodeOrigin,
  );
}
