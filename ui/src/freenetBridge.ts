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
