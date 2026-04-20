<template>
  <PageHeader title="版本管理" description="执行 commit latest、create version、查看版本列表与 rollback。">
    <el-button @click="loadPage">刷新</el-button>
    <el-button type="warning" @click="handleCommit">Commit Latest</el-button>
    <el-button type="primary" @click="openCreateDialog = true">Create Version</el-button>
  </PageHeader>

  <el-row :gutter="16">
    <el-col :span="10">
      <el-card class="page-card" shadow="never" v-loading="loading">
        <template #header>Latest Snapshot</template>
        <el-empty v-if="!latest" description="当前还没有 latest 快照" />
        <el-descriptions v-else :column="1" border>
          <el-descriptions-item label="Version">{{ latest.version }}</el-descriptions-item>
          <el-descriptions-item label="Label">{{ latest.label || "-" }}</el-descriptions-item>
          <el-descriptions-item label="Nodes">{{ latest.nodes.length }}</el-descriptions-item>
        </el-descriptions>
      </el-card>
    </el-col>
    <el-col :span="14">
      <el-card class="page-card" shadow="never" v-loading="loading">
        <template #header>Version List</template>
        <el-table :data="versions" stripe>
          <el-table-column prop="version" label="Version" width="100" />
          <el-table-column prop="label" label="Label" min-width="160" />
          <el-table-column prop="snapshotKey" label="Snapshot Key" min-width="220" />
          <el-table-column label="操作" width="220">
            <template #default="{ row }">
              <el-button link type="primary" @click="openDetail(row.version)">查看</el-button>
              <el-button link type="danger" @click="rollback(row.version)">Rollback</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </el-col>
  </el-row>

  <VersionCreateDialog
    v-model="openCreateDialog"
    @submit="handleCreateVersion"
  />
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessageBox } from "element-plus";

import PageHeader from "@/components/common/PageHeader.vue";
import VersionCreateDialog from "@/components/version/VersionCreateDialog.vue";
import { useVersioning } from "@/composables/useVersioning";

const route = useRoute();
const router = useRouter();
const contentId = Number(route.params.contentId);
const { latest, load, loading, runCommit, runCreateVersion, runRollback, versions } =
  useVersioning(contentId);
const openCreateDialog = ref(false);

async function loadPage() {
  await load();
}

async function handleCommit() {
  await ElMessageBox.confirm("确认将当前 draft 提交为 latest 吗？", "Commit Latest", {
    type: "warning",
  });
  await runCommit();
}

async function handleCreateVersion(label?: string) {
  await runCreateVersion(label);
  openCreateDialog.value = false;
}

function openDetail(version: number) {
  void router.push(`/contents/${contentId}/versions/${version}`);
}

async function rollback(version: number) {
  await ElMessageBox.confirm(
    "Rollback 会把指定 version 恢复为新的 draft，不会直接覆盖 latest。",
    "Rollback",
    { type: "warning" },
  );
  await runRollback(version);
  void router.push(`/contents/${contentId}/editor`);
}

onMounted(() => {
  void loadPage();
});
</script>
