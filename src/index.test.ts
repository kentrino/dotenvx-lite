import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vite-plus/test";
import {
  DecryptError,
  decrypt,
  decryptEnv,
  isDotenvPublicKey,
  isEncrypted,
  parseEnv,
} from "./index.ts";

const fixturePrivateKey = "dc08409876f6c2da7e5123380b071b131977ffbf2aadb78945e1579514dbae4b";

describe("@kentrino/dotenvx-lib", () => {
  const parsed = parseEnv(readFileSync(join(import.meta.dirname, "__fixtures__/ci.env"), "utf8"));

  it("parses and decrypts a dotenvx env file through the public API", () => {
    const hello = parsed.HELLO ?? "";
    const plain = parsed.PLAIN ?? "";

    expect(isDotenvPublicKey("DOTENV_PUBLIC_KEY_CI")).toBe(true);
    expect(isEncrypted(hello)).toBe(true);
    expect(isEncrypted(plain)).toBe(false);
    expect(decrypt(plain, "")).toBe("visible");
    expect(decryptEnv(parsed, fixturePrivateKey)).toEqual({
      HELLO: "hello-from-ci",
      EXTRA: "should-not-leak",
      PLAIN: "visible",
    });
  });

  it("propagates DecryptError for a bad private key", () => {
    expect(() => decryptEnv(parsed, "not-a-key")).toThrow(DecryptError);
  });
});
