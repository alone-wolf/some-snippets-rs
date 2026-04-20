<template>
  <PageHeader title="内容编辑" description="编辑 draft 编排，支持节点新增、编辑、移位与移除。">
    <el-button @click="loadEditor">刷新</el-button>
    <el-button type="primary" @click="openCreateDialog = true">新增节点</el-button>
  </PageHeader>

  <el-row :gutter="16">
    <el-col :span="10">
      <el-card class="page-card" shadow="never" v-loading="loading">
        <template #header>Draft 节点顺序</template>
        <el-empty v-if="!nodes.length" description="当前 draft 没有节点" />
        <div v-for="(node, index) in nodes" :key="node.id" class="node-item">
          <div class="node-item__header">
            <div>
              <strong>#{{ node.id }}</strong>
              <el-tag size="small" :type="node.lifecycleState === 'committed' ? 'warning' : 'success'">
                {{ node.lifecycleState }}
              </el-tag>
            </div>
            <div class="page-actions">
              <el-button link @click="moveNode(index, -1)" :disabled="index === 0">上移</el-button>
              <el-button link @click="moveNode(index, 1)" :disabled="index === nodes.length - 1">下移</el-button>
              <el-button link type="primary" @click="editNode(node)">编辑</el-button>
              <el-button link type="danger" @click="removeNode(node.id)">移除</el-button>
            </div>
          </div>
          <p v-if="node.kind === 'text'">{{ node.text }}</p>
          <div v-else class="node-item__file">
            <div>{{ node.file?.filename }}</div>
            <small>{{ node.file?.objectKey }}</small>
          </div>
        </div>
      </el-card>
    </el-col>
    <el-col :span="14">
      <el-card class="page-card" shadow="never">
        <template #header>编辑说明</template>
        <el-alert
          title="committed 节点编辑会触发 copy-on-write，并在 draft 中替换为新节点。"
          type="info"
          :closable="false"
        />
        <el-descriptions :column="1" border style="margin-top: 16px">
          <el-descriptions-item label="Working State">{{ nodes.length }} 个节点</el-descriptions-item>
          <el-descriptions-item label="Dirty">{{ dirty ? "Yes" : "No" }}</el-descriptions-item>
          <el-descriptions-item label="Saving">{{ saving ? "Yes" : "No" }}</el-descriptions-item>
        </el-descriptions>
      </el-card>
    </el-col>
  </el-row>

  <NodeFormDialog
    v-model="openCreateDialog"
    mode="create"
    @submit="handleCreateNode"
  />
  <NodeFormDialog
    v-model="openEditDialog"
    mode="edit"
    :node="editingNode"
    @submit="handleEditNode"
  />
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { ElMessageBox } from "element-plus";

import PageHeader from "@/components/common/PageHeader.vue";
import NodeFormDialog from "@/components/node/NodeFormDialog.vue";
import { createFileNode, createTextNode, updateFileNode, updateTextNode } from "@/api/node";
import type { NodeRecord } from "@/api/types";
import { useDraft } from "@/composables/useDraft";

const route = useRoute();
const contentId = Number(route.params.contentId);
const { dirty, nodes, persistOrder, reload, saving } = useDraft(contentId);

const loading = ref(false);
const openCreateDialog = ref(false);
const openEditDialog = ref(false);
const editingNode = ref<NodeRecord | null>(null);

async function loadEditor() {
  loading.value = true;
  try {
    await reload();
  } finally {
    loading.value = false;
  }
}

async function handleCreateNode(payload: { kind: "text" | "file"; text?: string; file?: NodeRecord["file"] }) {
  if (payload.kind === "text") {
    await createTextNode(contentId, payload.text || "");
  } else if (payload.file) {
    await createFileNode(contentId, payload.file);
  }
  openCreateDialog.value = false;
  await loadEditor();
}

function editNode(node: NodeRecord) {
  editingNode.value = node;
  openEditDialog.value = true;
}

async function handleEditNode(payload: { kind: "text" | "file"; text?: string; file?: NodeRecord["file"] }) {
  if (!editingNode.value) {
    return;
  }
  if (editingNode.value.lifecycleState === "committed") {
    await ElMessageBox.confirm(
      "该节点已 committed，继续编辑将触发 copy-on-write 并替换 draft 引用。",
      "确认编辑",
      { type: "warning" },
    );
  }
  if (payload.kind === "text") {
    await updateTextNode(editingNode.value.id, payload.text || "");
  } else if (payload.file) {
    await updateFileNode(editingNode.value.id, payload.file);
  }
  openEditDialog.value = false;
  editingNode.value = null;
  await loadEditor();
}

async function moveNode(index: number, offset: -1 | 1) {
  const nextIndex = index + offset;
  const reordered = [...nodes.value];
  const [item] = reordered.splice(index, 1);
  reordered.splice(nextIndex, 0, item);
  await persistOrder(reordered.map((node) => node.id));
}

async function removeNode(nodeId: number) {
  const remaining = nodes.value.filter((node) => node.id !== nodeId).map((node) => node.id);
  await persistOrder(remaining);
}

onMounted(() => {
  void loadEditor();
});
</script>

<style scoped lang="scss">
.node-item {
  padding: 12px 0;
  border-bottom: 1px solid #ebeef5;

  &__header {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
  }

  &__file {
    margin-top: 8px;
  }
}
</style>
