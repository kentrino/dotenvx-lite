import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PrivateKey, encrypt } from "eciesjs";
import { describe, expect, it } from "vite-plus/test";
import * as browserApi from "./browser.ts";
import type { DecryptErrorCode, EncryptedValue } from "./index.ts";
import * as nodeApi from "./index.ts";

const publicKey = "02b106c30579baf896ae1fddf077cbcb4fef5e7d457932974878dcb51f42b45498";
const privateKey = "1fc1cafa954a7a2bf0a6fbff46189c9e03e3a66b4d1133108ab9fcdb9e154b70";
const wrongPrivateKey = "9c1ab41477004e68066129a8866887d316ba5d7177593dbc5e3026d6f64d32f8";
const fixturePrivateKey = "dc08409876f6c2da7e5123380b071b131977ffbf2aadb78945e1579514dbae4b";

function encryptRaw(value: string, receiverPublicKey = publicKey): Uint8Array {
  return encrypt(receiverPublicKey, Buffer.from(value));
}

function toEncryptedValue(bytes: Uint8Array): EncryptedValue {
  return `encrypted:${Buffer.from(bytes).toString("base64")}`;
}

function encryptValue(value: string, receiverPublicKey = publicKey): EncryptedValue {
  return toEncryptedValue(encryptRaw(value, receiverPublicKey));
}

function captureError(fn: () => unknown): nodeApi.DecryptError {
  try {
    fn();
    throw new Error("expected DecryptError but function succeeded");
  } catch (error) {
    expect(error).toBeInstanceOf(nodeApi.DecryptError);
    if (!(error instanceof nodeApi.DecryptError)) {
      throw error;
    }
    return error;
  }
}

function expectEquivalentError(
  nodeFn: () => unknown,
  browserFn: () => unknown,
  expectedCode: DecryptErrorCode,
): void {
  const nodeError = captureError(nodeFn);
  const browserError = captureError(browserFn);

  expect(nodeError.code).toBe(expectedCode);
  expect(browserError.code).toBe(expectedCode);
  expect(nodeError.message).toBe(browserError.message);
}

describe("node and browser implementation equivalence", () => {
  it("exports the same public API surface", () => {
    expect(Object.keys(nodeApi).toSorted()).toStrictEqual(Object.keys(browserApi).toSorted());
    expect(nodeApi.DecryptError).toBe(browserApi.DecryptError);
    expect(nodeApi.isEncrypted).toBe(browserApi.isEncrypted);
    expect(nodeApi.isDotenvPublicKey).toBe(browserApi.isDotenvPublicKey);
    expect(nodeApi.parseEnv).toBe(browserApi.parseEnv);
  });

  it("produces identical results across many random ciphertexts and keypairs", () => {
    const payloads = [
      "",
      "a",
      "hello world",
      "line 1\nline 2\r\nline 3",
      "日本語のシークレット 🔐",
      "x".repeat(4096),
    ];

    for (let i = 0; i < 40; i++) {
      const keypair = i % 2 === 0 ? undefined : new PrivateKey();
      const pub = keypair ? keypair.publicKey.toHex() : publicKey;
      const priv = keypair ? keypair.toHex() : privateKey;
      const payload = payloads[i % payloads.length] ?? "";
      const encrypted = encryptValue(payload, pub);

      const nodeResult = nodeApi.decrypt(encrypted, priv);
      const browserResult = browserApi.decrypt(encrypted, priv);

      expect(nodeResult).toBe(payload);
      expect(browserResult).toBe(payload);
    }
  });

  it("matches on hardcoded dotenvx and @dotenvx/primitives test vectors", () => {
    const vectors: Array<[string, string, string]> = [
      [
        "encrypted:BMVCQpz/+NYDcGZhbXyqbwP8IDJSTXl4xDQsgusQHEVFAWOXQnKRBTOzRiwuYIJzjuWnKkrQJEDEi8Av9xnfx61jVTJymVWLjVmFK7CM+6lmKOnIhPMzu0Mi0dH82P81bOXjkZTHIIcA",
        privateKey,
        "expanded",
      ],
      [
        "encrypted:BC6dAYLyWtegG6SE44mf5KFegS2Wx9nhmlHhmGki0N0TV3XDpSN4Lfpz1p/pYdIlD+8rmsLTUNyDABJsGADuoDsv8caHK8yifvRly8cN2Uz9kRWATHsg6eaJ3vNSUFrzqYfs3tcsT1w=",
        "bc0abbb65ae0929b0b492035c57bd742527ad5cc0bb4f28155b62ac8c41324c8",
        "Dotenvx",
      ],
      [
        "encrypted:BE9Y7LKANx77X1pv1HnEoil93fPa5c9rpL/1ps48uaRT9zM8VR6mHx9yM+HktKdsPGIZELuZ7rr2mn1gScsmWitppAgE/1lVprNYBCqiYeaTcKXjDUXU5LfsEsflnAsDhT/kWG1l",
        "a4547dcd9d3429615a3649bb79e87edb62ee6a74b007075e9141ae44f5fb412c",
        "World",
      ],
    ];

    for (const [encrypted, key, expected] of vectors) {
      expect(nodeApi.decrypt(encrypted, key)).toBe(expected);
      expect(browserApi.decrypt(encrypted, key)).toBe(expected);
    }
  });

  it("matches on private key formatting and comma-separated fallbacks", () => {
    const encrypted = encryptValue("secret-value");
    const keys = [
      `0x${privateKey}`,
      `0X${privateKey}`,
      `  ${privateKey}\n`,
      `${wrongPrivateKey},${privateKey}`,
      `not-a-key, ${wrongPrivateKey} , 0x${privateKey}`,
      `${privateKey},${wrongPrivateKey}`,
    ];

    for (const key of keys) {
      expect(nodeApi.decrypt(encrypted, key)).toBe("secret-value");
      expect(browserApi.decrypt(encrypted, key)).toBe("secret-value");
    }
  });

  it("matches on plaintext passthrough", () => {
    for (const value of ["", "plain", "ENCRYPTED:abc", " encrypted:abc"]) {
      expect(nodeApi.decrypt(value, "")).toBe(value);
      expect(browserApi.decrypt(value, "")).toBe(value);
    }
  });

  it("matches on decryptEnv with CI fixture and options", () => {
    const parsed = nodeApi.parseEnv(
      readFileSync(join(import.meta.dirname, "__fixtures__/ci.env"), "utf8"),
    );

    expect(nodeApi.decryptEnv(parsed, fixturePrivateKey)).toStrictEqual(
      browserApi.decryptEnv(parsed, fixturePrivateKey),
    );
    expect(nodeApi.decryptEnv(parsed, fixturePrivateKey, { omitPublicKeys: false })).toStrictEqual(
      browserApi.decryptEnv(parsed, fixturePrivateKey, { omitPublicKeys: false }),
    );
  });

  it("throws identical MISSING_PRIVATE_KEY errors", () => {
    const encrypted = encryptValue("hello");
    for (const key of ["", "   ", "\n,\t"]) {
      expectEquivalentError(
        () => nodeApi.decrypt(encrypted, key),
        () => browserApi.decrypt(encrypted, key),
        "MISSING_PRIVATE_KEY",
      );
    }
  });

  it("throws identical INVALID_PRIVATE_KEY errors", () => {
    const encrypted = encryptValue("hello");
    const invalidKeys = [
      "invalid-private-key",
      "01".repeat(31),
      "01".repeat(33),
      `${privateKey}zz`,
      "00".repeat(32),
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      "ff".repeat(32),
    ];

    for (const key of invalidKeys) {
      expectEquivalentError(
        () => nodeApi.decrypt(encrypted, key),
        () => browserApi.decrypt(encrypted, key),
        "INVALID_PRIVATE_KEY",
      );
    }

    // Error precedence: invalid private key is reported before malformed ciphertext.
    expectEquivalentError(
      () => nodeApi.decrypt("encrypted:1234", "invalid-private-key"),
      () => browserApi.decrypt("encrypted:1234", "invalid-private-key"),
      "INVALID_PRIVATE_KEY",
    );
  });

  it("throws identical MALFORMED_ENCRYPTED_DATA errors", () => {
    const validBytes = encryptRaw("hello");
    const offCurvePoint = new Uint8Array(validBytes);
    offCurvePoint[0] = 0x04;
    offCurvePoint[64] = (offCurvePoint[64] ?? 0) ^ 0xff;

    const badPrefixes = [0x00, 0x02, 0x03, 0x06, 0x07].map((prefix) => {
      const copy = new Uint8Array(validBytes);
      copy[0] = prefix;
      return toEncryptedValue(copy);
    });

    const malformedValues: string[] = [
      "encrypted:",
      "encrypted:1234",
      "encrypted:!!!",
      "encrypted:ADJIvD6DxJdTcFdg1tcasYa9G1O5YVtFJs0yJgem+aGIlRJl9N1Fbq6kdPtIwfS0c6VJF4EN6H+D0JUwJ4FmoerQi0XQ4mv4AyA73KjrxVEqmSypg2InsV0e4WxdP5Qx/jVVSgxD",
      toEncryptedValue(validBytes.subarray(0, 64)),
      toEncryptedValue(validBytes.subarray(0, 65)),
      toEncryptedValue(validBytes.subarray(0, 80)),
      toEncryptedValue(validBytes.subarray(0, 81)),
      toEncryptedValue(validBytes.subarray(0, 96)),
      toEncryptedValue(offCurvePoint),
      ...badPrefixes,
    ];

    for (const malformed of malformedValues) {
      expectEquivalentError(
        () => nodeApi.decrypt(malformed, privateKey),
        () => browserApi.decrypt(malformed, privateKey),
        "MALFORMED_ENCRYPTED_DATA",
      );
    }
  });

  it("throws identical WRONG_PRIVATE_KEY errors", () => {
    const validBytes = encryptRaw("hello");

    const tamperedNonce = new Uint8Array(validBytes);
    tamperedNonce[65] = (tamperedNonce[65] ?? 0) ^ 0xff;

    const tamperedTag = new Uint8Array(validBytes);
    tamperedTag[81] = (tamperedTag[81] ?? 0) ^ 0xff;

    const tamperedCiphertext = new Uint8Array(validBytes);
    tamperedCiphertext[97] = (tamperedCiphertext[97] ?? 0) ^ 0xff;

    const cases: Array<[string, string]> = [
      [toEncryptedValue(validBytes), wrongPrivateKey],
      [toEncryptedValue(validBytes), `${wrongPrivateKey},${wrongPrivateKey}`],
      [toEncryptedValue(tamperedNonce), privateKey],
      [toEncryptedValue(tamperedTag), privateKey],
      [toEncryptedValue(tamperedCiphertext), privateKey],
    ];

    for (const [encrypted, key] of cases) {
      expectEquivalentError(
        () => nodeApi.decrypt(encrypted, key),
        () => browserApi.decrypt(encrypted, key),
        "WRONG_PRIVATE_KEY",
      );
    }
  });
});
