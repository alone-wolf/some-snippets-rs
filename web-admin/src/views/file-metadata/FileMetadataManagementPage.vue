<template>
  <PageHeader
    eyebrow="FileMetaData"
    title="FileMetaData Management"
    description="查看 file_metadata 表中的全部记录，用于核对节点文件对象信息。"
  >
    <el-button @click="loadItems">刷新</el-button>
  </PageHeader>

  <el-card class="page-card" shadow="never" v-loading="loading">
    <el-table :data="items" stripe>
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="nodeId" label="Node ID" width="100" />
      <el-table-column prop="filename" label="文件名" min-width="180" />
      <el-table-column prop="bucket" label="Bucket" width="140" />
      <el-table-column prop="objectKey" label="Object Key" min-width="220" />
      <el-table-column prop="mimeType" label="MIME" width="160" />
      <el-table-column prop="sizeBytes" label="Size" width="120" />
      <el-table-column prop="checksum" label="Checksum" min-width="180" />
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";

import { listFileMetadata } from "@/api/file-metadata";
import type { FileMetadataRecord } from "@/api/types";
import PageHeader from "@/components/common/PageHeader.vue";

const loading = ref(false);
const items = ref<FileMetadataRecord[]>([]);

async function loadItems() {
  loading.value = true;
  try {
    items.value = await listFileMetadata();
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  void loadItems();
});
</script>
