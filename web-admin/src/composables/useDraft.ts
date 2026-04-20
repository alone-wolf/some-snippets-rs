import { computed } from "vue";

import { getDraft, reorderDraft } from "@/api/content";
import { getNode } from "@/api/node";
import type { DraftSnapshot, NodeRecord } from "@/api/types";
import { useEditorStore } from "@/stores/editor";

export function useDraft(contentId: number) {
  const editorStore = useEditorStore();

  const nodes = computed(() => editorStore.workingNodes);
  const dirty = computed(() => editorStore.dirty);
  const saving = computed(() => editorStore.saving);

  async function reload(): Promise<{ draft: DraftSnapshot; nodes: NodeRecord[] }> {
    const draft = await getDraft(contentId);
    const nodeRecords = await Promise.all(draft.nodes.map((item) => getNode(item.nodeId)));
    editorStore.setSnapshot(draft, nodeRecords);
    return { draft, nodes: nodeRecords };
  }

  async function persistOrder(nodeIds: number[]) {
    editorStore.setSaving(true);
    try {
      await reorderDraft(contentId, nodeIds);
      await reload();
    } finally {
      editorStore.setSaving(false);
    }
  }

  return {
    dirty,
    nodes,
    persistOrder,
    reload,
    saving,
  };
}
