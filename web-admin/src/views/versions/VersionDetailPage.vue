<template>
  <PageHeader title="版本详情" description="查看指定版本的完整快照内容。">
    <el-button @click="$router.back()">返回</el-button>
  </PageHeader>

  <el-card class="page-card" shadow="never" v-loading="loading">
    <el-empty v-if="!snapshot" description="未找到版本快照" />
    <template v-else>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="Content ID">{{ snapshot.contentId }}</el-descriptions-item>
        <el-descriptions-item label="Version">{{ snapshot.version }}</el-descriptions-item>
        <el-descriptions-item label="State">{{ snapshot.state }}</el-descriptions-item>
        <el-descriptions-item label="Label">{{ snapshot.label || "-" }}</el-descriptions-item>
      </el-descriptions>
      <el-divider />
      <el-table :data="snapshot.nodes" stripe>
        <el-table-column prop="nodeId" label="Node ID" width="100" />
        <el-table-column prop="uuid" label="UUID" min-width="220" />
        <el-table-column prop="version" label="Node Version" width="120" />
        <el-table-column prop="kind" label="Kind" width="100" />
        <el-table-column label="Content" min-width="240">
          <template #default="{ row }">
            <span v-if="row.kind === 'text'">{{ row.text }}</span>
            <span v-else>{{ row.file?.filename }} / {{ row.file?.objectKey }}</span>
          </template>
        </el-table-column>
      </el-table>
    </template>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import PageHeader from "@/components/common/PageHeader.vue";
import type { VersionSnapshot } from "@/api/types";
import { useVersioning } from "@/composables/useVersioning";

const route = useRoute();
const contentId = Number(route.params.contentId);
const version = Number(route.params.version);
const { loadVersionDetail } = useVersioning(contentId);
const loading = ref(false);
const snapshot = ref<VersionSnapshot | null>(null);

onMounted(async () => {
  loading.value = true;
  try {
    snapshot.value = await loadVersionDetail(version);
  } finally {
    loading.value = false;
  }
});
</script>
