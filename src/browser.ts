import { decrypt } from "./decrypt-browser.ts";
import { createDecryptEnv } from "./decrypt-env-shared.ts";

export {
  DecryptError,
  decrypt,
  isEncrypted,
  type DecryptErrorCode,
  type EncryptedValue,
} from "./decrypt-browser.ts";
export { isDotenvPublicKey, type DecryptEnvOptions } from "./decrypt-env-shared.ts";
export { parseEnv } from "./parse-env.ts";

export const decryptEnv = createDecryptEnv(decrypt);
