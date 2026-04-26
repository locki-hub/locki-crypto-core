import { describe, expect, it } from "vitest";
import { deriveKey } from "../derive";

// deriveKey uses 600,000 PBKDF2 iterations — functional tests only (no NIST vectors).

describe("deriveKey", () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  it("is deterministic: same password + salt produces same key material", async () => {
    const keyA = await deriveKey("correct-horse-battery-staple", salt);
    const keyB = await deriveKey("correct-horse-battery-staple", salt);

    const iv = new Uint8Array(12);
    const data = new TextEncoder().encode("probe");
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyA, data);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, keyB, cipher);
    expect(new TextDecoder().decode(plain)).toBe("probe");
  }, 30_000);

  it("is sensitive to password: different passwords produce different keys", async () => {
    const keyA = await deriveKey("passwordA", salt);
    const keyB = await deriveKey("passwordB", salt);

    const iv = new Uint8Array(12);
    const data = new TextEncoder().encode("probe");
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyA, data);
    await expect(
      crypto.subtle.decrypt({ name: "AES-GCM", iv }, keyB, cipher),
    ).rejects.toThrow();
  }, 30_000);

  it("returns a CryptoKey suitable for AES-GCM", async () => {
    const key = await deriveKey("test-password", salt);
    expect(key.type).toBe("secret");
    expect((key.algorithm as { name: string }).name).toBe("AES-GCM");
  }, 15_000);
}, );
