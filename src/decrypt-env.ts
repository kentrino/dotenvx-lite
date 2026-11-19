import { decrypt } from "./decrypt.ts";
import {
  createDecryptEnv,
  isDotenvPublicKey,
  type DecryptEnvOptions,
} from "./decrypt-env-shared.ts";

export const decryptEnv = createDecryptEnv(decrypt);

export { isDotenvPublicKey, type DecryptEnvOptions };
