/**
 * RFC 6238 TOTP (HMAC-SHA1) for live codes in the UI.
 * Prefer server `generate_totp` when available; this is a client fallback.
 */

function decodeBase32(input: string): Uint8Array {
  const cleaned = input
    .toUpperCase()
    .replace(/=+$/g, "")
    .replace(/\s+/g, "");
  if (!cleaned) throw new Error("empty secret");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let nbits = 0;
  const out: number[] = [];
  for (const c of cleaned) {
    const val = alphabet.indexOf(c);
    if (val < 0) throw new Error("invalid base32");
    bits = (bits << 5) | val;
    nbits += 5;
    if (nbits >= 8) {
      nbits -= 8;
      out.push((bits >> nbits) & 0xff);
      bits &= (1 << nbits) - 1;
    }
  }
  return new Uint8Array(out);
}

async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key.slice().buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, msg.slice().buffer as ArrayBuffer);
  return new Uint8Array(sig);
}

export async function generateTotp(
  secretBase32: string,
  timeSecs: number = Math.floor(Date.now() / 1000),
  period = 30,
  digits = 6,
): Promise<{ code: string; secondsRemaining: number }> {
  const key = decodeBase32(secretBase32);
  const counter = Math.floor(timeSecs / period);
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  // write as big-endian u64
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  view.setUint32(0, high);
  view.setUint32(4, low);

  const hash = await hmacSha1(key, msg);
  const offset = hash[hash.length - 1]! & 0x0f;
  const bin =
    ((hash[offset]! & 0x7f) << 24) |
    (hash[offset + 1]! << 16) |
    (hash[offset + 2]! << 8) |
    hash[offset + 3]!;
  const mod = 10 ** digits;
  const code = (bin % mod).toString().padStart(digits, "0");
  const secondsRemaining = period - (timeSecs % period);
  return { code, secondsRemaining };
}
