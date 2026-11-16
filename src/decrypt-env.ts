import { decrypt } from "./decrypt.ts";

export interface DecryptEnvOptions {
  /**
   * Whether to omit `DOTENV_PUBLIC_KEY` and `DOTENV_PUBLIC_KEY_*` entries from the returned object.
   * @default true
   */
  omitPublicKeys?: boolean;
}

function assignOwn(target: Record<string, string>, key: string, value: string): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

export function isDotenvPublicKey(key: string): boolean {
  return key === "DOTENV_PUBLIC_KEY" || key.startsWith("DOTENV_PUBLIC_KEY_");
}

export function decryptEnv(
  parsed: Record<string, string>,
  privateKey: string,
  options?: DecryptEnvOptions,
): Record<string, string> {
  const omitPublicKeys = options?.omitPublicKeys ?? true;
  const result: Record<string, string> = {};

  for (const [key, value] of Object.entries(parsed)) {
    if (omitPublicKeys && isDotenvPublicKey(key)) {
      continue;
    }
    assignOwn(result, key, decrypt(value, privateKey));
  }

  return result;
}
