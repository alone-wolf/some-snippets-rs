import { describe, expect, it, vi } from "vitest";

vi.mock("element-plus", () => ({
  ElMessage: {
    error: vi.fn(),
  },
}));

describe("api client", () => {
  it("uses env base url and default timeout", async () => {
    vi.stubEnv("VITE_API_BASE_URL", "/api");
    const module = await import("@/api/client");

    expect(module.apiClient.defaults.baseURL).toBe("/api");
    expect(module.apiClient.defaults.timeout).toBe(15_000);
  });

  it("unwraps response envelope", async () => {
    const module = await import("@/api/client");

    await expect(
      module.unwrapResponse(Promise.resolve({ data: { data: { id: 1, title: "demo" } } })),
    ).resolves.toEqual({ id: 1, title: "demo" });
  });
});
