import { decrypt as decryptEcies } from "eciesjs";
import {
  DecryptError,
  createDecrypt,
  isEncrypted,
  type DecryptErrorCode,
  type EncryptedValue,
} from "./decrypt-shared.ts";

function classifyEciesError(error: unknown): DecryptError {
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error ? error : undefined;

  if (message === "Invalid private key" || message.startsWith("hex string expected")) {
    return new DecryptError("INVALID_PRIVATE_KEY", "could not decrypt using private key", {
      cause,
    });
  }

  if (message === "Unsupported state or unable to authenticate data") {
    return new DecryptError("WRONG_PRIVATE_KEY", "could not decrypt using private key", { cause });
  }

  if (
    message === "second arg must be public key" ||
    message === "Invalid initialization vector" ||
    message.startsWith("Invalid authentication tag length") ||
    message.startsWith("bad point:") ||
    message.includes("was invalid. Expected 33 compressed bytes")
  ) {
    return new DecryptError("MALFORMED_ENCRYPTED_DATA", "could not decrypt using private key", {
      cause,
    });
  }

  return new DecryptError("DECRYPTION_FAILED", message, { cause });
}

function decryptRawBrowser(privateKeyBytes: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  try {
    return decryptEcies(privateKeyBytes, ciphertext);
  } catch (error) {
    throw classifyEciesError(error);
  }
}

export const decrypt = createDecrypt(decryptRawBrowser);

export { DecryptError, isEncrypted, type DecryptErrorCode, type EncryptedValue };
