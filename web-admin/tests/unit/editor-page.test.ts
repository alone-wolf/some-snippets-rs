import { mount } from "@vue/test-utils";
import ElementPlus from "element-plus";
import { createPinia } from "pinia";
import { computed } from "vue";
import { describe, expect, it, vi } from "vitest";

vi.mock("vue-router", () => ({
  useRoute: () => ({ params: { contentId: "1" } }),
}));

vi.mock("@/composables/useDraft", () => ({
  useDraft: () => ({
    dirty: computed(() => false),
    nodes: computed(() => [
      {
        id: 1,
        contentId: 1,
        uuid: "node-1",
        version: 0,
        kind: "text",
        lifecycleState: "committed",
        text: "hello",
        createdBy: "system",
        updatedBy: "system",
      },
    ]),
    persistOrder: vi.fn(),
    reload: vi.fn(),
    saving: computed(() => false),
  }),
}));

import EditorPage from "@/views/editor/EditorPage.vue";

describe("EditorPage", () => {
  it("renders copy-on-write guidance", () => {
    const wrapper = mount(EditorPage, {
      global: {
        plugins: [createPinia(), ElementPlus],
      },
    });

    expect(wrapper.text()).toContain("内容编辑");
    expect(wrapper.text()).toContain("copy-on-write");
    expect(wrapper.text()).toContain("hello");
  });
});
