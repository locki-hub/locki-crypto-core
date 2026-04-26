// Requires Node.js 20+ for global File constructor.
import { describe, expect, it } from "vitest";
import { decryptFile, encryptFile } from "../file";
import { PROTECTED_FILE_EXTENSION } from "../constants";

const KEY_HEX = "0".repeat(64); // 256-bit all-zeros key
const WRONG_KEY = "f".repeat(64);

function makeFile(content: string, name: string, type = "text/plain"): File {
  return new File([content], name, { type });
}

describe("encryptFile", () => {
  it("appends .lockied to the filename", async () => {
    const file = makeFile("hello", "doc.txt");
    const encrypted = await encryptFile(file, KEY_HEX);
    expect(encrypted.name).toBe(`doc.txt${PROTECTED_FILE_EXTENSION}`);
  });

  it("sets application/x-locki MIME type", async () => {
    const file = makeFile("hello", "doc.txt");
    const encrypted = await encryptFile(file, KEY_HEX);
    expect(encrypted.type).toBe("application/x-locki");
  });

  it("produces a different payload on each call (random IV)", async () => {
    const file = makeFile("same content", "a.txt");
    const a = await encryptFile(file, KEY_HEX);
    const b = await encryptFile(file, KEY_HEX);
    const aBuf = await a.arrayBuffer();
    const bBuf = await b.arrayBuffer();
    expect(Buffer.from(aBuf).equals(Buffer.from(bBuf))).toBe(false);
  });
});

describe("decryptFile round-trip", () => {
  it("restores the original file content", async () => {
    const original = makeFile("secret data 🔐", "report.txt");
    const encrypted = await encryptFile(original, KEY_HEX);
    const decrypted = await decryptFile(encrypted, KEY_HEX);
    expect(await decrypted.text()).toBe("secret data 🔐");
  });

  it("restores the original filename", async () => {
    const original = makeFile("data", "photo.png", "image/png");
    const encrypted = await encryptFile(original, KEY_HEX);
    const decrypted = await decryptFile(encrypted, KEY_HEX);
    expect(decrypted.name).toBe("photo.png");
  });

  it("throws when the key is wrong", async () => {
    const encrypted = await encryptFile(makeFile("data", "a.txt"), KEY_HEX);
    await expect(decryptFile(encrypted, WRONG_KEY)).rejects.toThrow();
  });
});

describe("decryptFile — MIME type inference from extension", () => {
  const cases: Array<[string, string]> = [
    ["document.pdf", "application/pdf"],
    ["image.png", "image/png"],
    ["photo.jpg", "image/jpeg"],
    ["photo.jpeg", "image/jpeg"],
    ["data.json", "application/json"],
    ["notes.txt", "text/plain"],
    ["archive.zip", "application/octet-stream"],
  ];

  for (const [filename, expectedMime] of cases) {
    it(`infers ${expectedMime} for ${filename}`, async () => {
      const original = makeFile("content", filename);
      const encrypted = await encryptFile(original, KEY_HEX);
      const decrypted = await decryptFile(encrypted, KEY_HEX);
      expect(decrypted.type).toBe(expectedMime);
    });
  }
});
