<template>
  <PageHeader
    eyebrow="Collections"
    title="Collections Management"
    description="查看全部 Collection，维护基础元数据，并从这里进入内容工作台。"
  >
    <el-button type="primary" @click="openCreateCollectionDialog = true">新建 Collection</el-button>
    <el-button @click="loadCollections">刷新</el-button>
  </PageHeader>

  <el-card class="page-card" shadow="never" v-loading="loading">
    <template #header>
      <div class="management-header">
        <div>
          <strong>All Collections</strong>
          <p>这里展示全部 collection，不再只截取侧栏里的前三个常用项。</p>
        </div>
        <el-tag type="info">{{ collections.length }} items</el-tag>
      </div>
    </template>

    <el-empty v-if="!collections.length" description="暂无 Collection" />
    <div v-else class="management-grid">
      <article v-for="item in collections" :key="item.id" class="management-card">
        <div class="management-card__top">
          <div>
            <strong>{{ item.name }}</strong>
            <div class="management-card__slug">{{ item.slug }}</div>
          </div>
          <el-tag size="small">{{ item.visibility }}</el-tag>
        </div>
        <p>{{ item.description || "当前 collection 没有描述。" }}</p>
        <div class="management-card__footer">
          <el-tag type="info" size="small">Owner {{ item.ownerId }}</el-tag>
          <div class="page-actions">
            <el-button link type="primary" @click="openEditCollectionDialogFor(item)">编辑</el-button>
            <el-button link type="primary" @click="openWorkspace(item.id)">打开工作台</el-button>
          </div>
        </div>
      </article>
    </div>
  </el-card>

  <CollectionFormDialog
    v-model="openCreateCollectionDialog"
    mode="create"
    :form="createCollectionForm"
    @submit="handleCreateCollection"
  />
  <CollectionFormDialog
    v-model="openEditCollectionDialog"
    mode="edit"
    :form="editCollectionForm"
    @submit="handleUpdateCollection"
  />
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";

import { createCollection, listCollections, updateCollection } from "@/api/content";
import CollectionFormDialog from "@/components/collection/CollectionFormDialog.vue";
import PageHeader from "@/components/common/PageHeader.vue";
import type { Collection } from "@/api/types";
import { useAppStore } from "@/stores/app";

const appStore = useAppStore();
const router = useRouter();

const loading = ref(false);
const openCreateCollectionDialog = ref(false);
const openEditCollectionDialog = ref(false);
const editingCollectionId = ref<number | null>(null);

const createCollectionForm = reactive({
  name: "",
  slug: "",
  description: "",
  visibility: "private",
});

const editCollectionForm = reactive({
  name: "",
  slug: "",
  description: "",
  visibility: "private",
});

const collections = computed(() => appStore.collections);

async function loadCollections() {
  loading.value = true;
  try {
    appStore.setCollections(await listCollections());
  } finally {
    loading.value = false;
  }
}

async function handleCreateCollection(payload: {
  name: string;
  slug: string;
  description?: string | null;
  visibility: string;
}) {
  const collection = await createCollection({
    name: payload.name,
    slug: payload.slug,
    description: payload.description || undefined,
    visibility: payload.visibility,
  });
  openCreateCollectionDialog.value = false;
  resetCollectionForm(createCollectionForm);
  await loadCollections();
  openWorkspace(collection.id);
}

async function handleUpdateCollection(payload: {
  name: string;
  slug: string;
  description?: string | null;
  visibility: string;
}) {
  if (editingCollectionId.value == null) {
    return;
  }

  await updateCollection(editingCollectionId.value, {
    name: payload.name,
    slug: payload.slug,
    description: payload.description || null,
    visibility: payload.visibility,
  });
  openEditCollectionDialog.value = false;
  editingCollectionId.value = null;
  resetCollectionForm(editCollectionForm);
  await loadCollections();
}

function openEditCollectionDialogFor(collection: Collection) {
  editingCollectionId.value = collection.id;
  editCollectionForm.name = collection.name;
  editCollectionForm.slug = collection.slug;
  editCollectionForm.description = collection.description || "";
  editCollectionForm.visibility = collection.visibility;
  openEditCollectionDialog.value = true;
}

function openWorkspace(collectionId: number) {
  appStore.setActiveCollection(collectionId);
  void router.push({
    name: "collections",
    query: { collectionId: String(collectionId) },
  });
}

function resetCollectionForm(target: {
  name: string;
  slug: string;
  description: string;
  visibility: string;
}) {
  target.name = "";
  target.slug = "";
  target.description = "";
  target.visibility = "private";
}

onMounted(() => {
  void loadCollections();
});
</script>

<style scoped lang="scss">
.management-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;

  strong {
    color: #2d2013;
    font-size: 16px;
  }

  p {
    margin: 6px 0 0;
    color: #6c6156;
    font-size: 12px;
  }
}

.management-grid {
  display: grid;
  gap: 10px;
}

.management-card {
  padding: 14px;
  border: 1px solid rgba(82, 62, 39, 0.11);
  border-radius: 14px;
  background: rgba(255, 252, 248, 0.86);

  &__top {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    align-items: flex-start;
  }

  &__slug {
    margin-top: 4px;
    color: #8a7354;
    font-size: 12px;
  }

  p {
    margin: 10px 0 0;
    color: #655b50;
    font-size: 12px;
    line-height: 1.5;
  }

  &__footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-top: 12px;
  }
}
</style>
