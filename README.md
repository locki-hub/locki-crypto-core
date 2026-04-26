# @lockisecurity/crypto-core

AES-256-GCM encryption primitives developed within [Locki](https://lockisecurity.com/) and extracted into a standalone library for reuse in other projects. Use this library to encrypt text and files in any JavaScript environment using the browser-native WebCrypto API.

> **Source:** [github.com/locki-hub/locki-crypto](https://github.com/locki-hub/locki-crypto)

---

## Features

- **AES-256-GCM** encryption with random 12-byte IV per operation
- **[LOCKI:v2:]** wire format — compact, copy-paste-safe ciphertext string
- **File encryption** — encrypt/decrypt `File` objects with `.lockied` extension
- **Key utilities** — generate and import AES keys as hex strings
- **PBKDF2 key derivation** from passwords (600,000 iterations, SHA-256)
- **Zero dependencies** — uses `crypto.subtle` (WebCrypto), available in all modern browsers and Node.js 18+
- Dual **ESM + CJS** build, minified, with TypeScript declarations
- **NIST-tested** — AES-GCM implementation verified against official **NIST SP 800-38D** test vectors

---

## Installation

```bash
npm install @lockisecurity/crypto-core
# or
yarn add @lockisecurity/crypto-core
```

---

## Quick start

```ts
import { generateAESKeyHex, encrypt, decrypt } from '@lockisecurity/crypto-core';

// 1. Generate a key with the helper function and store it securely — you will need the same key to decrypt later
// Alternatively, generate a key at Key generator* and copy the hex string
const keyHex = await generateAESKeyHex(256); // 64-char hex string
// → "a3f1...8b2c"

// 2. Encrypt — pass the hex string directly
const ciphertext = await encrypt('Hello, world!', keyHex);
// → "[LOCKI:v2:BASE64_PAYLOAD]"

// 3. Decrypt
const plaintext = await decrypt(ciphertext, keyHex);
// → "Hello, world!"
```

*[Key generator](http://lockisecurity.com/tools/key-generator)

---

## API

### Text encryption

#### `encrypt(data, key)`
```ts
function encrypt(data: string, key: string): Promise<string>
```
Encrypts `data` with AES-256-GCM. `key` is a 32- or 64-character hex string. Returns a `[LOCKI:v2:<base64>]` string containing a random 12-byte IV followed by the ciphertext.

#### `decrypt(encryptedData, key)`
```ts
function decrypt(encryptedData: string, key: string): Promise<string>
```
Decrypts a `[LOCKI:v2:]` string. `key` is a 32- or 64-character hex string. Also handles the legacy `#_-LOCKI-ENC-START_-#` format for backward compatibility.

> **Throws** if the key is wrong or the ciphertext is corrupted. AES-GCM is authenticated encryption — a bad key or any tampering causes the WebCrypto API to reject decryption rather than return garbage. Always wrap calls in `try/catch`.

#### `isEncrypted(value)`
```ts
function isEncrypted(value: string): boolean
```
Returns `true` if the string is in `[LOCKI:v2:]` or legacy format.

---

### File encryption

#### `encryptFile(file, key)`
```ts
function encryptFile(file: File, key: string): Promise<File>
```
Encrypts a `File` object. `key` is a 32- or 64-character hex string. The returned file has the `.lockied` extension appended and `application/x-locki` MIME type. The payload is `IV (12 bytes) + ciphertext`.

#### `decryptFile(file, key)`
```ts
function decryptFile(file: File, key: string): Promise<File>
```
Decrypts a `.lockied` file. `key` is a 32- or 64-character hex string. Restores the original filename and infers the MIME type from the file extension client-side when reconstructing the `File` object (no server lookup).

> **Throws** if the key is wrong or the file is corrupted — same AES-GCM authentication guarantee as `decrypt`.

---

### Key management

#### `generateAESKeyHex(length?)`
```ts
function generateAESKeyHex(length?: 128 | 256): Promise<string>
```
Generates a cryptographically random AES key and returns it as a hex string. Default is 256-bit (64 hex characters).

| `length` | Hex chars | Use case |
|----------|-----------|----------|
| `128` | 32 | Fast, broadly compatible |
| `256` | 64 | High-security, used by Locki |

You can also generate a key in your browser at **[lockisecurity.com/tools/key-generator](http://lockisecurity.com/tools/key-generator)** — generation runs entirely client-side, nothing is transmitted or stored.

#### `importAESKeyFromHex(hex)`
```ts
function importAESKeyFromHex(hex: string): Promise<CryptoKey>
```
Imports a hex key string as a native `CryptoKey`. Accepts 32-char (128-bit) or 64-char (256-bit) hex strings. Useful for advanced use cases where you need a raw `CryptoKey` — for example, combining with `deriveKey` output or calling `crypto.subtle` directly. The `encrypt`/`decrypt`/`encryptFile`/`decryptFile` functions call this internally, so you don't need it for standard usage.

---

### Key derivation

#### `deriveKey(password, salt)`
```ts
function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey>
```
Derives a 256-bit AES key from a password using **PBKDF2** (SHA-256, 600,000 iterations). Returns a raw `CryptoKey` for use directly with `crypto.subtle`. Generate a random salt with `crypto.getRandomValues(new Uint8Array(16))` and store it alongside the ciphertext.

```ts
import { deriveKey } from '@lockisecurity/crypto-core';

const salt = crypto.getRandomValues(new Uint8Array(16));
const key  = await deriveKey('my-strong-password', salt);

// Use with crypto.subtle directly:
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
// Store salt + iv + ciphertext together

// On decrypt:
const sameKey = await deriveKey('my-strong-password', salt);
const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sameKey, ciphertext);
```

---

### Helpers

#### `arrayBufferToBase64(buffer)`
```ts
function arrayBufferToBase64(buffer: ArrayBuffer): string
```

#### `base64ToUint8Array(base64)`
```ts
function base64ToUint8Array(base64: string): Uint8Array
```

---

### Constants

| Export | Value | Description |
|--------|-------|-------------|
| `ENCRYPTED_START` | `[LOCKI:v2:` | Opening marker |
| `ENCRYPTED_END` | `]` | Closing marker |
| `ENCRYPTED_START_RE` | `\[LOCKI:v2:` | Regex-safe opening marker |
| `ENCRYPTED_END_RE` | `\]` | Regex-safe closing marker |
| `ENCRYPTED_START_OLD` | `#_-LOCKI-ENC-START_-#` | Legacy opening marker |
| `ENCRYPTED_END_OLD` | `#-_LOCKI-ENC-END-_#` | Legacy closing marker |
| `PROTECTED_FILE_EXTENSION` | `.lockied` | File extension added on encryption |

---

## Ciphertext format

```
[LOCKI:v2:<base64(IV + ciphertext)>]
         └──────┬──────┘└────┬────┘
          12 bytes         AES-GCM output
          random IV        (includes 16-byte auth tag)
```

- **Algorithm:** AES-GCM
- **IV:** 12 bytes, generated fresh per encryption with `crypto.getRandomValues`
- **Auth tag:** 16 bytes (AES-GCM default), appended to ciphertext by the WebCrypto API
- **Encoding:** standard Base64 (`btoa` / `atob`)
- **Markers:** square-bracket syntax chosen to survive Markdown renderers, Slack, email clients, and most CMS systems without being escaped or linkified

---

## Compatibility

| Environment | Minimum version |
|-------------|-----------------|
| Chrome / Edge | 37+ |
| Firefox | 34+ |
| Safari | 11+ |
| Node.js | 18+ |
| Deno | 1.0+ |
| Bun | 1.0+ |

No polyfills required. The library uses only `crypto.subtle` and global `btoa`/`atob`, which are available in all supported environments.

---

## Security notes

- **Key storage is your responsibility.** This library generates and uses keys; it does not store or transmit them.
- **Store keys securely.** If an attacker obtains the key, they can decrypt all ciphertexts encrypted with it. Consider using a secure vault or key management system for production use.
- **AES-GCM is authenticated encryption.** If the key or ciphertext is tampered with, decryption will throw.
- **Do not reuse IVs.** Each call to `encrypt` / `encryptFile` generates a fresh random IV — do not bypass this.

---

## Used by

- [Locki Browser Extension](https://lockisecurity.com/) — inline AES-256 encryption across web applications, with secure key management and sharing
- Locki API Service

---

## Testing

```bash
npm test            # run all tests once
npm run test:watch  # watch mode
```

The test suite covers:

- **AES-GCM** `encrypt` / `decrypt` / `isEncrypted` — including **known-answer tests** against the official **[NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)** AES-GCM test vectors (128-bit and 256-bit keys, Test Cases 1, 2, 13, 14)
- **Key generation and import** (`generateAESKeyHex`, `importAESKeyFromHex`)
- **PBKDF2 key derivation** — determinism and password sensitivity
- **File encryption** round-trips and MIME-type inference
- **Base64 helpers** round-trips

> File tests require Node.js 20+ (for the global `File` constructor).

---

## License

MIT © [Locki](https://lockisecurity.com/)
