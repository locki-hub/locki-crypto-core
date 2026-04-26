import { describe, expect, it } from "vitest";
import { generateAESKeyHex, importAESKeyFromHex } from "../keys";

describe("generateAESKeyHex", () => {
  it("generates a 64-char hex string for 256-bit key (default)", async () => {
    const key = await generateAESKeyHex();
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generates a 32-char hex string for 128-bit key", async () => {
    const key = await generateAESKeyHex(128);
    expect(key).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generates a 64-char hex string for 256-bit key (explicit)", async () => {
    const key = await generateAESKeyHex(256);
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces different values on consecutive calls (entropy check)", async () => {
    const a = await generateAESKeyHex(256);
    const b = await generateAESKeyHex(256);
    expect(a).not.toBe(b);
  });
});

describe("importAESKeyFromHex", () => {
  it("imports a 64-char (256-bit) hex key as a CryptoKey", async () => {
    const key = await importAESKeyFromHex("0".repeat(64));
    expect(key.type).toBe("secret");
    expect((key.algorithm as { name: string }).name).toBe("AES-GCM");
  });

  it("imports a 32-char (128-bit) hex key as a CryptoKey", async () => {
    const key = await importAESKeyFromHex("0".repeat(32));
    expect(key.type).toBe("secret");
  });

  it("throws for hex strings with wrong length", async () => {
    await expect(importAESKeyFromHex("abcd1234")).rejects.toThrow();
    await expect(importAESKeyFromHex("")).rejects.toThrow();
    await expect(importAESKeyFromHex("0".repeat(63))).rejects.toThrow();
  });

  it("the imported key can encrypt and decrypt via crypto.subtle", async () => {
    const cryptoKey = await importAESKeyFromHex("0".repeat(64));
    const iv = new Uint8Array(12);
    const data = new TextEncoder().encode("test");
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, data);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe("test");
  });
});
