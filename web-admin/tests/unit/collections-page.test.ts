import { flushPromises, mount } from "@vue/test-utils";
import ElementPlus from "element-plus";
import { createPinia } from "pinia";
import { describe, expect, it, vi } from "vitest";

vi.mock("vue-router", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ query: {} }),
}));

vi.mock("@/api/content", () => ({
  listCollections: vi.fn().mockResolvedValue([
    { id: 1, slug: "default", name: "Default", visibility: "private", ownerId: "system" },
  ]),
  listContents: vi.fn().mockResolvedValue([
    {
      id: 10,
      collectionId: 1,
      slug: "demo",
      title: "Demo Content",
      status: "draft",
      latestVersion: 0,
      createdBy: "system",
      updatedBy: "system",
    },
  ]),
  getContent: vi.fn().mockResolvedValue({
    id: 10,
    collectionId: 1,
    slug: "demo",
    title: "Demo Content",
    status: "draft",
    latestVersion: 0,
    createdBy: "system",
    updatedBy: "system",
  }),
  getDraft: vi.fn().mockResolvedValue({
    contentId: "10",
    state: "draft",
    nodes: [{ nodeId: 101 }],
  }),
  reorderDraft: vi.fn(),
  createCollection: vi.fn(),
  updateCollection: vi.fn(),
  createContent: vi.fn(),
  updateContent: vi.fn(),
}));

vi.mock("@/api/node", () => ({
  getNode: vi.fn().mockResolvedValue({
    id: 101,
    contentId: 10,
    uuid: "node-101",
    version: 1,
    kind: "text",
    lifecycleState: "draft_only",
    text: "Hello Node",
    createdBy: "system",
    updatedBy: "system",
  }),
  createTextNode: vi.fn(),
  createFileNode: vi.fn(),
  updateTextNode: vi.fn(),
  updateFileNode: vi.fn(),
}));

import CollectionsPage from "@/views/collections/CollectionsPage.vue";

describe("CollectionsPage", () => {
  it("renders collections and contents", async () => {
    const wrapper = mount(CollectionsPage, {
      global: {
        plugins: [createPinia(), ElementPlus],
      },
    });

    await flushPromises();

    expect(wrapper.text()).toContain("内容工作台");
    expect(wrapper.text()).toContain("Collection Explorer");
    expect(wrapper.text()).toContain("Content Board");
    expect(wrapper.text()).toContain("Node Studio");
    expect(wrapper.text()).toContain("新建");
    expect(wrapper.text()).toContain("Default");
    expect(wrapper.text()).toContain("Demo Content");
    expect(wrapper.text()).toContain("Hello Node");
  });
});
