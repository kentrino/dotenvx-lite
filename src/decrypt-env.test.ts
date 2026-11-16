import { Buffer } from "node:buffer";
import { encrypt } from "eciesjs";
import { describe, expect, it } from "vite-plus/test";
import { DecryptError, type EncryptedValue } from "./decrypt.ts";
import { decryptEnv, isDotenvPublicKey } from "./decrypt-env.ts";
import { parseEnv } from "./parse-env.ts";

const publicKey = "02b106c30579baf896ae1fddf077cbcb4fef5e7d457932974878dcb51f42b45498";
const privateKey = "1fc1cafa954a7a2bf0a6fbff46189c9e03e3a66b4d1133108ab9fcdb9e154b70";
const wrongPrivateKey = "9c1ab41477004e68066129a8866887d316ba5d7177593dbc5e3026d6f64d32f8";

function encryptValue(value: string): EncryptedValue {
  const ciphertext = encrypt(publicKey, Buffer.from(value));
  return `encrypted:${Buffer.from(ciphertext).toString("base64")}`;
}

describe("isDotenvPublicKey", () => {
  it("returns true for dotenv public key names", () => {
    expect(isDotenvPublicKey("DOTENV_PUBLIC_KEY")).toBe(true);
    expect(isDotenvPublicKey("DOTENV_PUBLIC_KEY_CI")).toBe(true);
    expect(isDotenvPublicKey("DOTENV_PUBLIC_KEY_PRODUCTION")).toBe(true);
  });

  it("returns false for other names", () => {
    expect(isDotenvPublicKey("DOTENV_PRIVATE_KEY")).toBe(false);
    expect(isDotenvPublicKey("DOTENV_PUBLIC_KEYS")).toBe(false);
    expect(isDotenvPublicKey("HELLO")).toBe(false);
    expect(isDotenvPublicKey("")).toBe(false);
  });
});

describe("decryptEnv", () => {
  it("decrypts encrypted entries and leaves plaintext alone", () => {
    const parsed = {
      HELLO: encryptValue("hello"),
      PLAIN: "visible",
    };

    expect(decryptEnv(parsed, privateKey)).toStrictEqual({
      HELLO: "hello",
      PLAIN: "visible",
    });
    expect(decryptEnv({ PLAIN: "visible" }, "")).toStrictEqual({ PLAIN: "visible" });
  });

  it("omits DOTENV_PUBLIC_KEY entries by default", () => {
    const parsed = {
      DOTENV_PUBLIC_KEY: publicKey,
      DOTENV_PUBLIC_KEY_CI: publicKey,
      HELLO: encryptValue("hello"),
      PLAIN: "visible",
    };

    expect(decryptEnv(parsed, privateKey)).toStrictEqual({
      HELLO: "hello",
      PLAIN: "visible",
    });
  });

  it("retains public keys when omitPublicKeys is false", () => {
    const parsed = {
      DOTENV_PUBLIC_KEY: publicKey,
      DOTENV_PUBLIC_KEY_CI: publicKey,
      PLAIN: "visible",
    };

    expect(decryptEnv(parsed, privateKey, { omitPublicKeys: false })).toStrictEqual(parsed);
  });

  it("returns an empty object for empty input", () => {
    expect(decryptEnv({}, privateKey)).toStrictEqual({});
  });

  it("returns an empty object for public-key-only input", () => {
    expect(
      decryptEnv(
        {
          DOTENV_PUBLIC_KEY: publicKey,
          DOTENV_PUBLIC_KEY_PRODUCTION: publicKey,
        },
        privateKey,
      ),
    ).toStrictEqual({});
  });

  it("preserves __proto__ as an own property without changing the prototype", () => {
    const result = decryptEnv(parseEnv("__proto__=pwned\nHELLO=ok"), "");
    const expected: Record<string, string> = { HELLO: "ok" };
    Object.defineProperty(expected, "__proto__", {
      value: "pwned",
      writable: true,
      enumerable: true,
      configurable: true,
    });

    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    expect(Object.hasOwn(result, "__proto__")).toBe(true);
    expect(result.propertyIsEnumerable("__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(result, "__proto__")?.value).toBe("pwned");
    expect(result).toStrictEqual(expected);
  });

  it("propagates DecryptError when the private key cannot decrypt", () => {
    const parsed = { HELLO: encryptValue("hello") };

    expect(() => decryptEnv(parsed, "")).toThrow(DecryptError);
    expect(() => decryptEnv(parsed, "not-a-key")).toThrow(DecryptError);

    try {
      decryptEnv(parsed, wrongPrivateKey);
      throw new Error("expected DecryptError");
    } catch (error) {
      expect(error).toBeInstanceOf(DecryptError);
      if (!(error instanceof DecryptError)) {
        throw error;
      }
      expect(error.code).toBe("WRONG_PRIVATE_KEY");
    }
  });
});
