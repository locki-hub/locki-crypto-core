import {
  ENCRYPTED_END,
  ENCRYPTED_END_OLD,
  ENCRYPTED_END_RE,
  ENCRYPTED_START,
  ENCRYPTED_START_OLD,
  ENCRYPTED_START_RE,
} from "./constants";
import { importAESKeyFromHex } from "./keys";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export async function encrypt(data: string, key: string): Promise<string> {
  const cryptoKey = await importAESKeyFromHex(key);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    encoder.encode(data),
  );
  const payload = new Uint8Array(iv.byteLength + encrypted.byteLength);
  payload.set(iv, 0);
  payload.set(new Uint8Array(encrypted), iv.byteLength);
  return `${ENCRYPTED_START}${btoa(String.fromCharCode(...payload))}${ENCRYPTED_END}`;
}

export async function decrypt(encryptedData: string, key: string): Promise<string> {
  const regex = new RegExp(
    `(?:${ENCRYPTED_START_RE}|${ENCRYPTED_START_OLD})(.*)(?:${ENCRYPTED_END_RE}|${ENCRYPTED_END_OLD})`,
  );
  const match = encryptedData.match(regex);
  if (!match?.[1]) {
    throw new Error("Invalid encrypted format");
  }
  const cryptoKey = await importAESKeyFromHex(key);
  const payload = Uint8Array.from(atob(match[1]), (c) => c.charCodeAt(0));
  const iv = payload.slice(0, 12);
  const data = payload.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, data);
  return decoder.decode(decrypted);
}

export function isEncrypted(value: string): boolean {
  return (
    (value.startsWith(ENCRYPTED_START) && value.endsWith(ENCRYPTED_END)) ||
    (value.startsWith(ENCRYPTED_START_OLD) && value.endsWith(ENCRYPTED_END_OLD))
  );
}
