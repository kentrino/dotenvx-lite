# @kentrino/dotenvx-lite

Parse `.env` files and decrypt [dotenvx](https://dotenvx.com) `encrypted:` values.

## Installation

```sh
pnpm add @kentrino/dotenvx-lite
# or
npm install @kentrino/dotenvx-lite
```

## Usage

```ts
import {
  DecryptError,
  decrypt,
  decryptEnv,
  isDotenvPublicKey,
  isEncrypted,
  parseEnv,
} from "@kentrino/dotenvx-lite";

const parsed = parseEnv(source);
const env = decryptEnv(parsed, privateKey);

if (isDotenvPublicKey(key)) {
  // DOTENV_PUBLIC_KEY or DOTENV_PUBLIC_KEY_*
}

if (isEncrypted(value)) {
  const plain = decrypt(value, privateKey);
}

try {
  decrypt(value, privateKey);
} catch (error) {
  if (error instanceof DecryptError) {
    console.error(error.code);
  }
}
```

- `parseEnv(src)` parses `.env` text into a `Record<string, string>` while keeping `encrypted:` ciphertexts intact.
- `decrypt(value, privateKey)` decrypts `encrypted:` values (supporting comma-separated private keys) and returns plaintext values unchanged.
- `decryptEnv(parsed, privateKey, options?)` decrypts all entries and omits `DOTENV_PUBLIC_KEY` / `DOTENV_PUBLIC_KEY_*` keys by default (pass `{ omitPublicKeys: false }` to retain them).
- `isEncrypted(value)` checks whether a string starts with `encrypted:`.
- `isDotenvPublicKey(key)` checks whether a key is `DOTENV_PUBLIC_KEY` or `DOTENV_PUBLIC_KEY_*`.

### Browser usage

The default entrypoint uses Node.js built-in `node:crypto` with zero runtime dependencies. For browser environments, install the optional peer dependency `eciesjs` and import from `@kentrino/dotenvx-lite/browser`:

```sh
pnpm add @kentrino/dotenvx-lite eciesjs
```

```ts
import { decrypt, decryptEnv, parseEnv } from "@kentrino/dotenvx-lite/browser";
```

## Development

Requires Node.js >= 22.18.0 and pnpm 11.20.0.

```sh
pnpm install
vp run ready
```

`ready` runs `check`, `test`, and `build` in sequence.

## License

MIT. Portions are adapted from [motdotla/dotenv](https://github.com/motdotla/dotenv) (BSD-2-Clause) and [dotenvx/dotenvx](https://github.com/dotenvx/dotenvx) (BSD-3-Clause); see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
