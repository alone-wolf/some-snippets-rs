import { computed, ref } from "vue";
import { defineStore } from "pinia";

import type { Collection, Content } from "@/api/types";

export const useAppStore = defineStore("app", () => {
  const collections = ref<Collection[]>([]);
  const activeCollectionId = ref<number | null>(null);
  const activeContent = ref<Content | null>(null);
  const globalLoading = ref(false);

  const activeCollection = computed(
    () => collections.value.find((item) => item.id === activeCollectionId.value) ?? null,
  );

  function setCollections(next: Collection[]) {
    collections.value = next;
    if (next.length > 0 && activeCollectionId.value == null) {
      activeCollectionId.value = next[0].id;
    }
  }

  function setActiveCollection(collectionId: number | null) {
    activeCollectionId.value = collectionId;
  }

  function setActiveContent(content: Content | null) {
    activeContent.value = content;
  }

  function setGlobalLoading(value: boolean) {
    globalLoading.value = value;
  }

  return {
    activeCollection,
    activeCollectionId,
    activeContent,
    collections,
    globalLoading,
    setActiveCollection,
    setActiveContent,
    setCollections,
    setGlobalLoading,
  };
});
