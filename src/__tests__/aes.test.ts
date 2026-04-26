import { describe, expect, it } from "vitest";
import { decrypt, encrypt, isEncrypted } from "../aes";
import { NIST_VECTORS, buildLockiCiphertext } from "./vectors";

// NIST SP 800-38D known-answer tests 

describe("decrypt — NIST SP 800-38D AES-GCM known-answer tests", () => {
  for (const vec of NIST_VECTORS) {
    it(vec.description, async () => {
      const ciphertext = buildLockiCiphertext(vec.iv, vec.ct, vec.tag);
      const result = await decrypt(ciphertext, vec.key);
      // pt is a hex string of raw bytes; decode as latin-1 to compare
      const expectedBytes = vec.pt ? Uint8Array.from(
        vec.pt.match(/.{2}/g)!.map((h) => parseInt(h, 16)),
      ) : new Uint8Array(0);
      const expected = new TextDecoder("latin1").decode(expectedBytes);
      expect(result).toBe(expected);
    });
  }
});

// Error handling 

describe("decrypt — error handling", () => {
  const [vec] = NIST_VECTORS.filter((v) => v.pt !== ""); // pick a vector with actual plaintext

  it("throws with a wrong key", async () => {
    const ciphertext = buildLockiCiphertext(vec.iv, vec.ct, vec.tag);
    const wrongKey = vec.key.replace(/0/g, "f"); // flip all nibbles
    await expect(decrypt(ciphertext, wrongKey)).rejects.toThrow();
  });

  it("throws when a ciphertext byte is flipped (auth tag check)", async () => {
    const ciphertext = buildLockiCiphertext(vec.iv, vec.ct, vec.tag);
    // Flip a character inside the base64 payload
    const tampered = ciphertext.replace(/[LOCKI:v2:]/g, "").slice(0, -1);
    const tamperedFull = `[LOCKI:v2:${tampered}X]`;
    await expect(decrypt(tamperedFull, vec.key)).rejects.toThrow();
  });

  it("throws when the string has no encrypted markers", async () => {
    await expect(decrypt("hello world", vec.key)).rejects.toThrow("Invalid encrypted format");
  });
});

// Round-trip tests 

describe("encrypt / decrypt round-trip", () => {
  const keyHex = "0".repeat(64); // 256-bit all-zeros key

  it("decrypts back to the original plaintext", async () => {
    const plain = "Hello, Locki!";
    const cipher = await encrypt(plain, keyHex);
    expect(await decrypt(cipher, keyHex)).toBe(plain);
  });

  it("produces [LOCKI:v2:...] format", async () => {
    const cipher = await encrypt("test", keyHex);
    expect(cipher).toMatch(/^\[LOCKI:v2:.+\]$/);
  });

  it("uses a fresh random IV each time (different ciphertext per call)", async () => {
    const plain = "same input";
    const a = await encrypt(plain, keyHex);
    const b = await encrypt(plain, keyHex);
    expect(a).not.toBe(b);
  });

  it("handles multi-line and unicode plaintext", async () => {
    const plain = "line1\nline2\n🔐 секрет";
    expect(await decrypt(await encrypt(plain, keyHex), keyHex)).toBe(plain);
  });

  it("handles empty string", async () => {
    expect(await decrypt(await encrypt("", keyHex), keyHex)).toBe("");
  });
});

// isEncrypted 

describe("isEncrypted", () => {
  it("returns true for v2 format", () => {
    expect(isEncrypted("[LOCKI:v2:abc]")).toBe(true);
  });

  it("returns true for legacy format", () => {
    expect(isEncrypted("#_-LOCKI-ENC-START_-#abc#-_LOCKI-ENC-END-_#")).toBe(true);
  });

  it("returns false for plain text", () => {
    expect(isEncrypted("hello")).toBe(false);
  });

  it("returns false for empty string", () => {
    expect(isEncrypted("")).toBe(false);
  });

  it("returns false for partial markers", () => {
    expect(isEncrypted("[LOCKI:v2:abc")).toBe(false);
    expect(isEncrypted("abc]")).toBe(false);
  });
});
