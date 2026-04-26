export async function generateAESKeyHex(length: 128 | 256 = 256): Promise<string> {
  if (!length) length = 256;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length }, true, [
    "encrypt",
    "decrypt",
  ]);
  const raw = await crypto.subtle.exportKey("raw", key);
  return Array.from(new Uint8Array(raw))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function importAESKeyFromHex(hex: string): Promise<CryptoKey> {
  if (typeof hex !== "string" || !hex) {
    throw new Error("Invalid hex string provided for AES key import.");
  }
  if (hex.length !== 32 && hex.length !== 64) {
    throw new Error("AES key hex length must be 32 (128-bit) or 64 (256-bit).");
  }
  const matches = hex.match(/.{1,2}/g);
  if (!matches) {
    throw new Error("Hex string could not be parsed into bytes.");
  }
  const bytes = new Uint8Array(matches.map((b) => parseInt(b, 16)));
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}
