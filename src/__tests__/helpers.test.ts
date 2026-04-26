import { describe, expect, it } from "vitest";
import { arrayBufferToBase64, base64ToUint8Array } from "../helpers";

describe("arrayBufferToBase64", () => {
  it("encodes known bytes to the correct base64 string", () => {
    const buf = Uint8Array.from([72, 101, 108, 108, 111]).buffer; // "Hello"
    expect(arrayBufferToBase64(buf)).toBe("SGVsbG8=");
  });

  it("encodes empty buffer to empty string", () => {
    expect(arrayBufferToBase64(new ArrayBuffer(0))).toBe("");
  });

  it("encodes single zero byte", () => {
    expect(arrayBufferToBase64(new Uint8Array([0]).buffer)).toBe("AA==");
  });
});

describe("base64ToUint8Array", () => {
  it("decodes known base64 to correct bytes", () => {
    const result = base64ToUint8Array("SGVsbG8=");
    expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
  });

  it("decodes empty string to empty array", () => {
    expect(base64ToUint8Array("").length).toBe(0);
  });

  it("decodes single zero byte", () => {
    expect(Array.from(base64ToUint8Array("AA=="))).toEqual([0]);
  });
});

describe("round-trip", () => {
  it("arrayBufferToBase64 → base64ToUint8Array restores original bytes", () => {
    const original = Uint8Array.from([1, 2, 3, 255, 0, 128, 64]);
    const b64 = arrayBufferToBase64(original.buffer);
    const restored = base64ToUint8Array(b64);
    expect(Array.from(restored)).toEqual(Array.from(original));
  });
});
