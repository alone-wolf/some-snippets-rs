import { describe, expect, it } from "vitest";

import router from "@/router";

describe("router", () => {
  it("registers the main admin routes", () => {
    const names = router.getRoutes().map((route) => route.name);
    expect(names).toContain("dashboard");
    expect(names).toContain("collections");
    expect(names).toContain("collections-management");
    expect(names).toContain("contents-management");
    expect(names).toContain("nodes-management");
    expect(names).toContain("file-metadata-management");
    expect(names).toContain("content-settings");
    expect(names).toContain("content-editor");
    expect(names).toContain("content-versions");
    expect(names).toContain("content-version-detail");
  });
});
