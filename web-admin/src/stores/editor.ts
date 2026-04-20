import { computed, ref } from "vue";
import { defineStore } from "pinia";

import type { DraftSnapshot, NodeRecord } from "@/api/types";

export const useEditorStore = defineStore("editor", () => {
  const serverSnapshot = ref<DraftSnapshot | null>(null);
  const workingNodes = ref<NodeRecord[]>([]);
  const saving = ref(false);
  const dirty = ref(false);

  const workingNodeIds = computed(() => workingNodes.value.map((item) => item.id));

  function setSnapshot(snapshot: DraftSnapshot, nodes: NodeRecord[]) {
    serverSnapshot.value = snapshot;
    workingNodes.value = nodes;
    dirty.value = false;
  }

  function replaceNodes(nodes: NodeRecord[]) {
    workingNodes.value = nodes;
    dirty.value = true;
  }

  function setSaving(value: boolean) {
    saving.value = value;
  }

  return {
    dirty,
    saving,
    serverSnapshot,
    setSaving,
    setSnapshot,
    replaceNodes,
    workingNodeIds,
    workingNodes,
  };
});
