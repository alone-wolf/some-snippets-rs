<template>
  <PageHeader title="内容设置" description="查看并编辑 Content 基础信息。">
    <el-button @click="loadContent">刷新</el-button>
    <el-button type="primary" @click="openDialog = true">编辑</el-button>
  </PageHeader>

  <el-card class="page-card" shadow="never" v-loading="loading">
    <el-descriptions :column="2" border v-if="content">
      <el-descriptions-item label="ID">{{ content.id }}</el-descriptions-item>
      <el-descriptions-item label="Collection ID">{{ content.collectionId }}</el-descriptions-item>
      <el-descriptions-item label="标题">{{ content.title }}</el-descriptions-item>
      <el-descriptions-item label="Slug">{{ content.slug }}</el-descriptions-item>
      <el-descriptions-item label="状态">{{ content.status }}</el-descriptions-item>
      <el-descriptions-item label="Schema ID">{{ content.schemaId || "-" }}</el-descriptions-item>
      <el-descriptions-item label="Draft Snapshot Key">
        {{ content.draftSnapshotKey || "-" }}
      </el-descriptions-item>
      <el-descriptions-item label="Latest Snapshot Key">
        {{ content.latestSnapshotKey || "-" }}
      </el-descriptions-item>
      <el-descriptions-item label="Latest Version">{{ content.latestVersion }}</el-descriptions-item>
      <el-descriptions-item label="Updated By">{{ content.updatedBy }}</el-descriptions-item>
    </el-descriptions>
  </el-card>

  <ContentFormDialog
    v-if="content"
    v-model="openDialog"
    mode="edit"
    :form="{
      title: content.title,
      slug: content.slug,
      status: content.status,
      schemaId: content.schemaId || ''
    }"
    @submit="handleSubmit"
  />
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import PageHeader from "@/components/common/PageHeader.vue";
import ContentFormDialog from "@/components/content/ContentFormDialog.vue";
import { getContent, updateContent } from "@/api/content";
import type { Content } from "@/api/types";
import { useAppStore } from "@/stores/app";

const route = useRoute();
const appStore = useAppStore();
const content = ref<Content | null>(null);
const openDialog = ref(false);
const loading = ref(false);

const contentId = Number(route.params.contentId);

async function loadContent() {
  loading.value = true;
  try {
    content.value = await getContent(contentId);
    appStore.setActiveContent(content.value);
  } finally {
    loading.value = false;
  }
}

async function handleSubmit(payload: {
  title: string;
  slug: string;
  status: string;
  schemaId?: string | null;
}) {
  content.value = await updateContent(contentId, {
    title: payload.title,
    status: payload.status,
    schema_id: payload.schemaId,
  });
  appStore.setActiveContent(content.value);
  openDialog.value = false;
}

onMounted(() => {
  void loadContent();
});
</script>
