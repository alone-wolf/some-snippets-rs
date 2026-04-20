import { describe, expect, it, vi } from "vitest";

describe("resolveApiBaseUrl", () => {
  it("falls back to same-origin when env is empty", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "");
    const module = await import("@/utils/env");
    expect(module.resolveApiBaseUrl()).toBe("");
  });
});
