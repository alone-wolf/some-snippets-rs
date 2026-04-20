import { flushPromises, mount } from "@vue/test-utils";
import ElementPlus from "element-plus";
import { createPinia } from "pinia";
import { ref } from "vue";
import { describe, expect, it, vi } from "vitest";

vi.mock("vue-router", () => ({
  useRoute: () => ({ params: { contentId: "1" } }),
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/composables/useVersioning", () => ({
  useVersioning: () => ({
    latest: ref({ contentId: "1", state: "latest", version: 0, label: "latest", nodes: [] }),
    load: vi.fn(),
    loading: ref(false),
    runCommit: vi.fn(),
    runCreateVersion: vi.fn(),
    runRollback: vi.fn(),
    versions: ref([
      {
        version: 1,
        label: "v1",
        snapshotKey: "contents/1/content.000001.json",
        snapshotChecksum: "sha256:test",
        createdBy: "system",
      },
    ]),
  }),
}));

import VersionsPage from "@/views/versions/VersionsPage.vue";

describe("VersionsPage", () => {
  it("renders version list actions", async () => {
    const wrapper = mount(VersionsPage, {
      global: {
        plugins: [createPinia(), ElementPlus],
      },
    });

    await flushPromises();

    expect(wrapper.text()).toContain("版本管理");
    expect(wrapper.text()).toContain("Commit Latest");
    expect(wrapper.text()).toContain("Create Version");
    expect(wrapper.text()).toContain("latest");
    expect(wrapper.findComponent({ name: "ElTable" }).exists()).toBe(true);
  });
});
