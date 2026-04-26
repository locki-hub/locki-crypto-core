import { PROTECTED_FILE_EXTENSION } from "./constants";
import { importAESKeyFromHex } from "./keys";

export async function encryptFile(file: File, key: string): Promise<File> {
  const cryptoKey = await importAESKeyFromHex(key);
  const arrayBuffer = await file.arrayBuffer();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, arrayBuffer);
  const payload = new Uint8Array(iv.byteLength + encrypted.byteLength);
  payload.set(iv, 0);
  payload.set(new Uint8Array(encrypted), iv.byteLength);
  const blob = new Blob([payload], { type: "application/x-locki" });
  return new File([blob], file.name + PROTECTED_FILE_EXTENSION, { type: "application/x-locki" });
}

export async function decryptFile(file: File, key: string): Promise<File> {
  const cryptoKey = await importAESKeyFromHex(key);
  const payload = new Uint8Array(await file.arrayBuffer());
  const iv = payload.slice(0, 12);
  const data = payload.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, data);
  const originalName = file.name.replace(new RegExp(`${PROTECTED_FILE_EXTENSION.replace(".", "\\.")}$`), "");
  const originalType = mimeFromFilename(originalName);
  return new File([new Blob([decrypted], { type: originalType })], originalName, {
    type: originalType,
  });
}

function mimeFromFilename(filename: string): string {
  const ext = filename.match(/\.([a-zA-Z0-9]+)$/)?.[1]?.toLowerCase();
  switch (ext) {
    case "txt":
      return "text/plain";
    case "json":
      return "application/json";
    case "png":
      return "image/png";
    case "jpg":
    case "jpeg":
      return "image/jpeg";
    case "pdf":
      return "application/pdf";
    default:
      return "application/octet-stream";
  }
}
