import { defineStore } from "pinia";
import { ref } from "vue";

export const useUiStore = defineStore("ui", () => {
  const collapsed = ref(false);

  function toggleMenu() {
    collapsed.value = !collapsed.value;
  }

  return {
    collapsed,
    toggleMenu,
  };
});
