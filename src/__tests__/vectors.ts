/**
 * NIST SP 800-38D Appendix B — AES-GCM test vectors
 * No AAD, 96-bit (12-byte) IV, 128-bit auth tag.
 * Source: https://csrc.nist.gov/publications/detail/sp/800-38d/final
 */

export interface NistVector {
  description: string;
  key: string;    // hex
  iv: string;     // hex (24 chars = 12 bytes)
  pt: string;     // hex, may be empty
  ct: string;     // hex, may be empty
  tag: string;    // hex (32 chars = 16 bytes)
}

export const NIST_VECTORS: NistVector[] = [
  {
    description: "AES-128-GCM, empty plaintext (Test Case 1)",
    key: "00000000000000000000000000000000",
    iv:  "000000000000000000000000",
    pt:  "",
    ct:  "",
    tag: "58e2fccefa7e3061367f1d57a4e7455a",
  },
  {
    description: "AES-128-GCM, 16-byte plaintext (Test Case 2)",
    key: "00000000000000000000000000000000",
    iv:  "000000000000000000000000",
    pt:  "00000000000000000000000000000000",
    ct:  "0388dace60b6a392f328c2b971b2fe78",
    tag: "ab6e47d42cec13bdf53a67b21257bddf",
  },
  {
    description: "AES-256-GCM, empty plaintext (Test Case 13)",
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    iv:  "000000000000000000000000",
    pt:  "",
    ct:  "",
    tag: "530f8afbc74536b9a963b4f1c4cb738b",
  },
  {
    description: "AES-256-GCM, 16-byte plaintext (Test Case 14)",
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    iv:  "000000000000000000000000",
    pt:  "00000000000000000000000000000000",
    ct:  "cea7403d4d606b6e074ec5d3baf39d18",
    tag: "d0d1c8a799996bf0265b98b5d48ab919",
  },
];

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Builds a [LOCKI:v2:...] ciphertext string from raw NIST vector fields.
 * WebCrypto concatenates ciphertext + auth-tag in its output, so we mirror
 * that by joining ct+tag, then prepend the IV, then base64-encode.
 */
export function buildLockiCiphertext(iv: string, ct: string, tag: string): string {
  const ivBytes  = hexToBytes(iv);
  const ctBytes  = hexToBytes(ct);
  const tagBytes = hexToBytes(tag);
  const payload  = new Uint8Array(ivBytes.length + ctBytes.length + tagBytes.length);
  payload.set(ivBytes, 0);
  payload.set(ctBytes, ivBytes.length);
  payload.set(tagBytes, ivBytes.length + ctBytes.length);
  const b64 = btoa(String.fromCharCode(...payload));
  return `[LOCKI:v2:${b64}]`;
}
