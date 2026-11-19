const PREFIX = "encrypted:" as const;
const PRIVATE_KEY_HEX_PATTERN = /^[0-9a-fA-F]{64}$/;
const textDecoder = new TextDecoder();

export const UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
export const NONCE_LENGTH = 16;
export const AUTH_TAG_LENGTH = 16;
export const MIN_CIPHERTEXT_LENGTH = UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_LENGTH + AUTH_TAG_LENGTH;

export type EncryptedValue = `${typeof PREFIX}${string}`;

export type DecryptErrorCode =
  | "MISSING_PRIVATE_KEY"
  | "INVALID_PRIVATE_KEY"
  | "WRONG_PRIVATE_KEY"
  | "MALFORMED_ENCRYPTED_DATA"
  | "DECRYPTION_FAILED";

export class DecryptError extends Error {
  readonly code: DecryptErrorCode;

  constructor(code: DecryptErrorCode, message: string, options?: { cause?: unknown }) {
    super(`[${code}] ${message}`, options);
    this.name = "DecryptError";
    this.code = code;
  }
}

export function isEncrypted(value: string): value is EncryptedValue {
  return value.startsWith(PREFIX);
}

function privateKeysFrom(privateKey: string): string[] {
  return privateKey
    .split(",")
    .map((key) => key.trim())
    .filter((key) => key.length > 0);
}

function parsePrivateKeyHex(key: string): Uint8Array {
  const hex = key.startsWith("0x") || key.startsWith("0X") ? key.slice(2) : key;
  if (!PRIVATE_KEY_HEX_PATTERN.test(hex)) {
    throw new DecryptError("INVALID_PRIVATE_KEY", "could not decrypt using private key");
  }

  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function decodeBase64(input: string): Uint8Array {
  try {
    const binary = atob(input);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new Uint8Array(0);
  }
}

export function createDecrypt(
  decryptRaw: (privateKeyBytes: Uint8Array, ciphertext: Uint8Array) => Uint8Array,
): (value: string, privateKey: string) => string {
  return function decrypt(value: string, privateKey: string): string {
    if (!isEncrypted(value)) {
      return value;
    }

    const privateKeys = privateKeysFrom(privateKey);
    if (privateKeys.length === 0) {
      throw new DecryptError(
        "MISSING_PRIVATE_KEY",
        "could not decrypt because private key is missing",
      );
    }

    const ciphertext = decodeBase64(value.slice(PREFIX.length));
    let lastError: DecryptError | undefined;

    for (const key of privateKeys) {
      try {
        const keyBytes = parsePrivateKeyHex(key);
        return textDecoder.decode(decryptRaw(keyBytes, ciphertext));
      } catch (error) {
        lastError =
          error instanceof DecryptError
            ? error
            : new DecryptError(
                "DECRYPTION_FAILED",
                error instanceof Error ? error.message : String(error),
                { cause: error instanceof Error ? error : undefined },
              );
      }
    }

    throw lastError ?? new DecryptError("DECRYPTION_FAILED", "could not decrypt using private key");
  };
}
