<template>
  <PageHeader
    eyebrow="Contents"
    title="Contents Management"
    description="查看 contents 表中的全部记录，并进入对应内容的设置、编辑和版本页面。"
  >
    <el-button @click="loadContents">刷新</el-button>
  </PageHeader>

  <el-card class="page-card" shadow="never" v-loading="loading">
    <el-table :data="contents" stripe>
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="collectionId" label="Collection ID" width="120" />
      <el-table-column prop="title" label="标题" min-width="180" />
      <el-table-column prop="slug" label="Slug" min-width="150" />
      <el-table-column prop="status" label="状态" width="120" />
      <el-table-column prop="latestVersion" label="Latest Version" width="130" />
      <el-table-column label="操作" width="240">
        <template #default="{ row }">
          <el-button link type="primary" @click="goToSettings(row.id)">设置</el-button>
          <el-button link type="primary" @click="goToEditor(row.id)">编辑</el-button>
          <el-button link type="primary" @click="goToVersions(row.id)">版本</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import { listAllContents } from "@/api/content";
import type { Content } from "@/api/types";
import PageHeader from "@/components/common/PageHeader.vue";

const router = useRouter();
const loading = ref(false);
const contents = ref<Content[]>([]);

async function loadContents() {
  loading.value = true;
  try {
    contents.value = await listAllContents();
  } finally {
    loading.value = false;
  }
}

function goToSettings(contentId: number) {
  void router.push(`/contents/${contentId}/settings`);
}

function goToEditor(contentId: number) {
  void router.push(`/contents/${contentId}/editor`);
}

function goToVersions(contentId: number) {
  void router.push(`/contents/${contentId}/versions`);
}

onMounted(() => {
  void loadContents();
});
</script>
