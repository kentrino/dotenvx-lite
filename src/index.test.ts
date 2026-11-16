import { describe, expect, it } from "vite-plus/test";
import { packageName } from "./index.ts";

describe("packageName", () => {
  it("matches the package name", () => {
    expect(packageName).toBe("@kentrino/dotenvx-lib");
  });
});
