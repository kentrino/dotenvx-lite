import { ECDH, createDecipheriv, createECDH, hkdfSync } from "node:crypto";
import {
  DecryptError,
  MIN_CIPHERTEXT_LENGTH,
  NONCE_LENGTH,
  UNCOMPRESSED_PUBLIC_KEY_SIZE,
  createDecrypt,
  isEncrypted,
  type DecryptErrorCode,
  type EncryptedValue,
} from "./decrypt-shared.ts";

const SHARED_KEY_LENGTH = 32;
const EMPTY_BYTES = new Uint8Array(0);
const COMPRESSED_PREFIXES = [0x02, 0x03] as const;

function decryptRawNode(privateKeyBytes: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const ecdh = createECDH("secp256k1");
  try {
    ecdh.setPrivateKey(privateKeyBytes);
  } catch (error) {
    throw new DecryptError("INVALID_PRIVATE_KEY", "could not decrypt using private key", {
      cause: error instanceof Error ? error : undefined,
    });
  }

  if (ciphertext.length < MIN_CIPHERTEXT_LENGTH) {
    throw new DecryptError("MALFORMED_ENCRYPTED_DATA", "could not decrypt using private key");
  }

  const ephemeralPublicKey = ciphertext.subarray(0, UNCOMPRESSED_PUBLIC_KEY_SIZE);
  if (ephemeralPublicKey[0] !== 0x04) {
    throw new DecryptError("MALFORMED_ENCRYPTED_DATA", "could not decrypt using private key");
  }

  let sharedX: Uint8Array;
  try {
    sharedX = ecdh.computeSecret(ephemeralPublicKey);
  } catch (error) {
    throw new DecryptError("MALFORMED_ENCRYPTED_DATA", "could not decrypt using private key", {
      cause: error instanceof Error ? error : undefined,
    });
  }

  const nonce = ciphertext.subarray(
    UNCOMPRESSED_PUBLIC_KEY_SIZE,
    UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_LENGTH,
  );
  const authTag = ciphertext.subarray(
    UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_LENGTH,
    MIN_CIPHERTEXT_LENGTH,
  );
  const encrypted = ciphertext.subarray(MIN_CIPHERTEXT_LENGTH);

  const compressedPoint = new Uint8Array(1 + sharedX.length);
  compressedPoint.set(sharedX, 1);

  let lastAuthError: unknown;
  for (const prefix of COMPRESSED_PREFIXES) {
    compressedPoint[0] = prefix;
    const sharedPoint = ECDH.convertKey(
      compressedPoint,
      "secp256k1",
      undefined,
      undefined,
      "uncompressed",
    );
    const sharedPointBytes =
      typeof sharedPoint === "string"
        ? new Uint8Array(0)
        : new Uint8Array(sharedPoint.buffer, sharedPoint.byteOffset, sharedPoint.byteLength);

    const ikm = new Uint8Array(ephemeralPublicKey.length + sharedPointBytes.length);
    ikm.set(ephemeralPublicKey, 0);
    ikm.set(sharedPointBytes, ephemeralPublicKey.length);

    const sharedKey = new Uint8Array(
      hkdfSync("sha256", ikm, EMPTY_BYTES, EMPTY_BYTES, SHARED_KEY_LENGTH),
    );

    try {
      const decipher = createDecipheriv("aes-256-gcm", sharedKey, nonce);
      decipher.setAuthTag(authTag);
      const head = decipher.update(encrypted);
      const tail = decipher.final();
      const plaintext = new Uint8Array(head.length + tail.length);
      plaintext.set(head, 0);
      plaintext.set(tail, head.length);
      return plaintext;
    } catch (error) {
      lastAuthError = error;
    }
  }

  throw new DecryptError("WRONG_PRIVATE_KEY", "could not decrypt using private key", {
    cause: lastAuthError instanceof Error ? lastAuthError : undefined,
  });
}

export const decrypt = createDecrypt(decryptRawNode);

export { DecryptError, isEncrypted, type DecryptErrorCode, type EncryptedValue };
