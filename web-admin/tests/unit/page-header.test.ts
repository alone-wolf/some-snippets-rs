import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import PageHeader from "@/components/common/PageHeader.vue";

describe("PageHeader", () => {
  it("renders title, description and action slot", () => {
    const wrapper = mount(PageHeader, {
      props: {
        title: "标题",
        description: "描述",
      },
      slots: {
        default: "<button>Action</button>",
      },
    });

    expect(wrapper.text()).toContain("标题");
    expect(wrapper.text()).toContain("描述");
    expect(wrapper.text()).toContain("Action");
  });
});
