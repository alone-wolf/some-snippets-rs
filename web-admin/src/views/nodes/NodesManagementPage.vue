<template>
  <PageHeader
    eyebrow="Nodes"
    title="Nodes Management"
    description="查看 nodes 表中的全部记录，并根据所属 content 跳到编辑工作流。"
  >
    <el-button @click="loadNodes">刷新</el-button>
  </PageHeader>

  <el-card class="page-card" shadow="never" v-loading="loading">
    <el-table :data="nodes" stripe>
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="contentId" label="Content ID" width="120" />
      <el-table-column prop="kind" label="类型" width="100" />
      <el-table-column prop="lifecycleState" label="Lifecycle" width="120" />
      <el-table-column prop="version" label="Version" width="100" />
      <el-table-column prop="uuid" label="UUID" min-width="200" />
      <el-table-column label="摘要" min-width="220">
        <template #default="{ row }">
          <span v-if="row.kind === 'text'">{{ row.text || "-" }}</span>
          <span v-else>{{ row.file?.filename || "-" }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="220">
        <template #default="{ row }">
          <el-button link type="primary" @click="goToContent(row.contentId)">内容设置</el-button>
          <el-button link type="primary" @click="goToEditor(row.contentId)">内容编辑</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import { listNodes } from "@/api/node";
import type { NodeRecord } from "@/api/types";
import PageHeader from "@/components/common/PageHeader.vue";

const router = useRouter();
const loading = ref(false);
const nodes = ref<NodeRecord[]>([]);

async function loadNodes() {
  loading.value = true;
  try {
    nodes.value = await listNodes();
  } finally {
    loading.value = false;
  }
}

function goToContent(contentId: number) {
  void router.push(`/contents/${contentId}/settings`);
}

function goToEditor(contentId: number) {
  void router.push(`/contents/${contentId}/editor`);
}

onMounted(() => {
  void loadNodes();
});
</script>
