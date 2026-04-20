<template>
  <PageHeader
    eyebrow="Workspace"
    title="内容工作台"
    description="统一处理 Collection、Content、Node。左侧选 Collection，中间选 Content，右侧直接维护 draft Node。"
  >
    <el-button @click="loadWorkspace">刷新工作台</el-button>
  </PageHeader>

  <section class="workspace-grid">
    <el-card class="page-card workspace-panel" shadow="never" v-loading="loadingCollections">
      <template #header>
        <div class="panel-header">
          <div>
            <h3>Collection Explorer</h3>
            <p>管理内容空间与基础元数据。</p>
          </div>
          <div class="page-actions">
            <el-button size="small" type="primary" @click="openCreateCollectionDialog = true">
              新建
            </el-button>
            <el-button size="small" :disabled="!activeCollection" @click="openEditCollectionDialogForActive">
              编辑
            </el-button>
          </div>
        </div>
      </template>

      <el-empty v-if="!collections.length" description="暂无 Collection" />
      <div v-else class="entity-list">
        <button
          v-for="item in collections"
          :key="item.id"
          type="button"
          class="entity-card"
          :class="{ 'is-active': item.id === activeCollection?.id }"
          @click="handleCollectionSelect(item.id)"
        >
          <div class="entity-card__top">
            <strong>{{ item.name }}</strong>
            <el-tag size="small" effect="dark">{{ item.visibility }}</el-tag>
          </div>
          <div class="entity-card__meta">{{ item.slug }}</div>
          <p>{{ item.description || "无描述" }}</p>
        </button>
      </div>
    </el-card>

    <el-card class="page-card workspace-panel" shadow="never" v-loading="loadingContents">
      <template #header>
        <div class="panel-header">
          <div>
            <h3>Content Board</h3>
            <p>{{ activeCollection ? `当前 collection: ${activeCollection.name}` : "先从左侧选择 collection" }}</p>
          </div>
          <div class="page-actions">
            <el-button size="small" type="primary" :disabled="!activeCollection" @click="openCreateContentDialog = true">
              新建
            </el-button>
            <el-button size="small" :disabled="!activeContent" @click="openEditContentDialogForActive">
              编辑
            </el-button>
            <el-button size="small" :disabled="!activeContent" @click="activeContent && goToSettings(activeContent.id)">
              详情页
            </el-button>
            <el-button
              size="small"
              type="primary"
              plain
              :disabled="!activeContent"
              @click="activeContent && goToVersions(activeContent.id)"
            >
              版本
            </el-button>
          </div>
        </div>
      </template>

      <el-empty v-if="!activeCollection" description="请选择 Collection" />
      <el-empty v-else-if="!contents.length" description="当前 Collection 下暂无 Content" />
      <div v-else class="entity-list">
        <button
          v-for="item in contents"
          :key="item.id"
          type="button"
          class="entity-card entity-card--content"
          :class="{ 'is-active': item.id === selectedContentId }"
          @click="selectContent(item.id)"
        >
          <div class="entity-card__top">
            <strong>{{ item.title }}</strong>
            <el-tag size="small" :type="item.status === 'published' ? 'success' : 'info'">
              {{ item.status }}
            </el-tag>
          </div>
          <div class="entity-card__meta">#{{ item.id }} · {{ item.slug }}</div>
          <div class="entity-card__footer">
            <span>Latest v{{ item.latestVersion }}</span>
            <div class="page-actions entity-card__actions">
              <el-button link type="primary" @click.stop="openEditContentDialog(item)">编辑</el-button>
              <el-button link type="primary" @click.stop="goToVersions(item.id)">版本</el-button>
            </div>
          </div>
        </button>
      </div>

      <div v-if="activeContent" class="detail-card detail-card--content">
        <div class="detail-card__label">Selected Content</div>
        <h4>{{ activeContent.title }}</h4>
        <div class="detail-card__chips">
          <el-tag>{{ activeContent.slug }}</el-tag>
          <el-tag type="success">{{ activeContent.status }}</el-tag>
          <el-tag type="info">Schema {{ activeContent.schemaId || "-" }}</el-tag>
        </div>
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="Content ID">{{ activeContent.id }}</el-descriptions-item>
          <el-descriptions-item label="Collection ID">{{ activeContent.collectionId }}</el-descriptions-item>
          <el-descriptions-item label="Latest Version">{{ activeContent.latestVersion }}</el-descriptions-item>
          <el-descriptions-item label="Updated By">{{ activeContent.updatedBy }}</el-descriptions-item>
        </el-descriptions>
      </div>
    </el-card>

    <el-card class="page-card workspace-panel" shadow="never" v-loading="loadingNodes">
      <template #header>
        <div class="panel-header">
          <div>
            <h3>Node Studio</h3>
            <p>{{ activeContent ? `当前 content: ${activeContent.title}` : "先从中间选择 content" }}</p>
          </div>
          <div class="page-actions">
            <el-button size="small" type="primary" :disabled="!activeContent" @click="openCreateNodeDialog = true">
              新建
            </el-button>
            <el-button size="small" :disabled="!activeContent" @click="activeContent && goToEditor(activeContent.id)">
              全屏编辑
            </el-button>
          </div>
        </div>
      </template>

      <el-empty v-if="!activeContent" description="请选择 Content" />
      <template v-else>
        <div class="detail-card detail-card--node">
          <div class="detail-card__label">Draft Snapshot</div>
          <h4>{{ nodes.length }} 个节点</h4>
          <p>直接在工作台中进行新增、编辑、重排与从 draft 移除。</p>
        </div>

        <el-empty v-if="!nodes.length" description="当前 draft 没有节点" />
        <div v-else class="node-list">
          <article v-for="(node, index) in nodes" :key="node.id" class="node-card">
            <div class="node-card__header">
              <div class="node-card__title">
                <strong>#{{ node.id }}</strong>
                <el-tag size="small" effect="plain">{{ node.kind }}</el-tag>
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
            <div v-if="node.kind === 'text'" class="node-card__body">
              {{ node.text || "空文本节点" }}
            </div>
            <div v-else class="node-card__body">
              <strong>{{ node.file?.filename || "未命名文件" }}</strong>
              <small>{{ node.file?.objectKey || "-" }}</small>
              <small>{{ node.file?.mimeType || "unknown mime" }} · {{ node.file?.sizeBytes || 0 }} bytes</small>
            </div>
          </article>
        </div>
      </template>
    </el-card>
  </section>

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
  <ContentFormDialog
    v-model="openCreateContentDialog"
    mode="create"
    :form="createContentForm"
    @submit="handleCreateContent"
  />
  <ContentFormDialog
    v-model="openEditContentDialogVisible"
    mode="edit"
    :form="editContentForm"
    @submit="handleUpdateContent"
  />
  <NodeFormDialog
    v-model="openCreateNodeDialog"
    mode="create"
    @submit="handleCreateNode"
  />
  <NodeFormDialog
    v-model="openEditNodeDialog"
    mode="edit"
    :node="editingNode"
    @submit="handleEditNode"
  />
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { ElMessageBox } from "element-plus";
import { useRoute, useRouter } from "vue-router";

import PageHeader from "@/components/common/PageHeader.vue";
import CollectionFormDialog from "@/components/collection/CollectionFormDialog.vue";
import ContentFormDialog from "@/components/content/ContentFormDialog.vue";
import NodeFormDialog from "@/components/node/NodeFormDialog.vue";
import {
  createCollection,
  createContent,
  getContent,
  getDraft,
  listCollections,
  listContents,
  reorderDraft,
  updateCollection,
  updateContent,
} from "@/api/content";
import { createFileNode, createTextNode, getNode, updateFileNode, updateTextNode } from "@/api/node";
import type { Collection, Content, NodeRecord } from "@/api/types";
import { useAppStore } from "@/stores/app";

const appStore = useAppStore();
const route = useRoute();
const router = useRouter();

const contents = ref<Content[]>([]);
const nodes = ref<NodeRecord[]>([]);
const selectedContentId = ref<number | null>(null);

const loadingCollections = ref(false);
const loadingContents = ref(false);
const loadingNodes = ref(false);

const openCreateCollectionDialog = ref(false);
const openEditCollectionDialog = ref(false);
const openCreateContentDialog = ref(false);
const openEditContentDialogVisible = ref(false);
const openCreateNodeDialog = ref(false);
const openEditNodeDialog = ref(false);

const editingNode = ref<NodeRecord | null>(null);

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

const createContentForm = reactive({
  title: "",
  slug: "",
  status: "draft",
  schemaId: "",
});

const editContentForm = reactive({
  title: "",
  slug: "",
  status: "draft",
  schemaId: "",
});

const collections = computed(() => appStore.collections);
const activeCollection = computed(() => appStore.activeCollection);
const activeContent = computed(() => appStore.activeContent);
const routeCollectionId = computed(() => parseCollectionId(route.query.collectionId));

async function loadWorkspace() {
  await loadCollections(routeCollectionId.value ?? appStore.activeCollectionId, selectedContentId.value);
}

async function loadCollections(
  preferredCollectionId: number | null = appStore.activeCollectionId,
  preferredContentId: number | null = selectedContentId.value,
) {
  loadingCollections.value = true;
  try {
    const collectionList = await listCollections();
    appStore.setCollections(collectionList);

    const nextCollectionId =
      preferredCollectionId != null && collectionList.some((item) => item.id === preferredCollectionId)
        ? preferredCollectionId
        : collectionList[0]?.id ?? null;

    appStore.setActiveCollection(nextCollectionId);

    if (nextCollectionId != null) {
      await loadContentsForCollection(nextCollectionId, preferredContentId);
    } else {
      resetContentWorkspace();
    }
  } finally {
    loadingCollections.value = false;
  }
}

async function loadContentsForCollection(collectionId: number, preferredContentId: number | null = selectedContentId.value) {
  loadingContents.value = true;
  try {
    const contentList = await listContents(collectionId);
    contents.value = contentList;

    const nextContentId =
      preferredContentId != null && contentList.some((item) => item.id === preferredContentId)
        ? preferredContentId
        : contentList[0]?.id ?? null;

    selectedContentId.value = nextContentId;
    if (nextContentId != null) {
      await loadContentWorkspace(nextContentId);
    } else {
      appStore.setActiveContent(null);
      nodes.value = [];
    }
  } finally {
    loadingContents.value = false;
  }
}

async function loadContentWorkspace(contentId: number) {
  loadingNodes.value = true;
  try {
    const [content, draft] = await Promise.all([getContent(contentId), getDraft(contentId)]);
    const nodeRecords = await Promise.all(draft.nodes.map((item) => getNode(item.nodeId)));
    appStore.setActiveContent(content);
    selectedContentId.value = content.id;
    nodes.value = nodeRecords;
  } finally {
    loadingNodes.value = false;
  }
}

async function handleCollectionSelect(collectionId: number) {
  appStore.setActiveCollection(collectionId);
  await loadContentsForCollection(collectionId, null);
}

async function selectContent(contentId: number) {
  await loadContentWorkspace(contentId);
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
  await loadCollections(collection.id, null);
}

async function handleUpdateCollection(payload: {
  name: string;
  slug: string;
  description?: string | null;
  visibility: string;
}) {
  if (!activeCollection.value) {
    return;
  }

  await updateCollection(activeCollection.value.id, {
    name: payload.name,
    slug: payload.slug,
    description: payload.description || null,
    visibility: payload.visibility,
  });
  openEditCollectionDialog.value = false;
  resetCollectionForm(editCollectionForm);
  await loadCollections(activeCollection.value.id, selectedContentId.value);
}

async function handleCreateContent(payload: {
  title: string;
  slug: string;
  status: string;
  schemaId?: string | null;
}) {
  if (!activeCollection.value) {
    return;
  }

  const content = await createContent(activeCollection.value.id, {
    slug: payload.slug,
    title: payload.title,
    status: payload.status,
    schema_id: payload.schemaId || undefined,
  });
  openCreateContentDialog.value = false;
  resetContentForm(createContentForm);
  await loadContentsForCollection(activeCollection.value.id, content.id);
}

async function handleUpdateContent(payload: {
  title: string;
  slug: string;
  status: string;
  schemaId?: string | null;
}) {
  if (!activeContent.value || !activeCollection.value) {
    return;
  }

  await updateContent(activeContent.value.id, {
    title: payload.title,
    status: payload.status,
    schema_id: payload.schemaId || null,
  });
  openEditContentDialogVisible.value = false;
  resetContentForm(editContentForm);
  await loadContentsForCollection(activeCollection.value.id, activeContent.value.id);
}

async function handleCreateNode(payload: { kind: "text" | "file"; text?: string; file?: NodeRecord["file"] }) {
  if (!activeContent.value) {
    return;
  }

  if (payload.kind === "text") {
    await createTextNode(activeContent.value.id, payload.text || "");
  } else if (payload.file) {
    await createFileNode(activeContent.value.id, payload.file);
  }
  openCreateNodeDialog.value = false;
  await loadContentWorkspace(activeContent.value.id);
}

function editNode(node: NodeRecord) {
  editingNode.value = node;
  openEditNodeDialog.value = true;
}

async function handleEditNode(payload: { kind: "text" | "file"; text?: string; file?: NodeRecord["file"] }) {
  if (!editingNode.value || !activeContent.value) {
    return;
  }

  if (editingNode.value.lifecycleState === "committed") {
    await ElMessageBox.confirm(
      "该节点已 committed，继续编辑将触发 copy-on-write 并替换当前 draft 引用。",
      "确认编辑节点",
      { type: "warning" },
    );
  }

  if (payload.kind === "text") {
    await updateTextNode(editingNode.value.id, payload.text || "");
  } else if (payload.file) {
    await updateFileNode(editingNode.value.id, payload.file);
  }

  openEditNodeDialog.value = false;
  editingNode.value = null;
  await loadContentWorkspace(activeContent.value.id);
}

async function moveNode(index: number, offset: -1 | 1) {
  if (!activeContent.value) {
    return;
  }

  const reordered = [...nodes.value];
  const [item] = reordered.splice(index, 1);
  reordered.splice(index + offset, 0, item);
  await persistNodeOrder(reordered.map((node) => node.id));
}

async function removeNode(nodeId: number) {
  if (!activeContent.value) {
    return;
  }

  const remaining = nodes.value.filter((node) => node.id !== nodeId).map((node) => node.id);
  await persistNodeOrder(remaining);
}

async function persistNodeOrder(nodeIds: number[]) {
  if (!activeContent.value) {
    return;
  }

  loadingNodes.value = true;
  try {
    await reorderDraft(activeContent.value.id, nodeIds);
    await loadContentWorkspace(activeContent.value.id);
  } finally {
    loadingNodes.value = false;
  }
}

function openEditCollectionDialogForActive() {
  if (!activeCollection.value) {
    return;
  }

  syncCollectionForm(editCollectionForm, activeCollection.value);
  openEditCollectionDialog.value = true;
}

function openEditContentDialogForActive() {
  if (!activeContent.value) {
    return;
  }

  openEditContentDialog(activeContent.value);
}

function openEditContentDialog(content: Content) {
  syncContentForm(editContentForm, content);
  openEditContentDialogVisible.value = true;
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

function resetContentWorkspace() {
  contents.value = [];
  nodes.value = [];
  selectedContentId.value = null;
  appStore.setActiveContent(null);
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

function resetContentForm(target: {
  title: string;
  slug: string;
  status: string;
  schemaId: string;
}) {
  target.title = "";
  target.slug = "";
  target.status = "draft";
  target.schemaId = "";
}

function syncCollectionForm(
  target: {
    name: string;
    slug: string;
    description: string;
    visibility: string;
  },
  collection: Collection,
) {
  target.name = collection.name;
  target.slug = collection.slug;
  target.description = collection.description || "";
  target.visibility = collection.visibility;
}

function syncContentForm(
  target: {
    title: string;
    slug: string;
    status: string;
    schemaId: string;
  },
  content: Content,
) {
  target.title = content.title;
  target.slug = content.slug;
  target.status = content.status;
  target.schemaId = content.schemaId || "";
}

onMounted(() => {
  void loadWorkspace();
});

watch(routeCollectionId, (nextCollectionId) => {
  if (nextCollectionId == null || nextCollectionId === activeCollection.value?.id) {
    return;
  }

  void loadCollections(nextCollectionId, null);
});

function parseCollectionId(value: unknown): number | null {
  const raw = Array.isArray(value) ? value[0] : value;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}
</script>

<style scoped lang="scss">
.workspace-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.workspace-panel {
  min-height: 620px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 10px;

  h3 {
    margin: 0;
    color: #2e2013;
    font-size: 17px;
  }

  p {
    margin: 6px 0 0;
    color: #6d6257;
    font-size: 12px;
    line-height: 1.45;
  }
}

.entity-list {
  display: grid;
  gap: 8px;
}

.entity-card {
  padding: 12px;
  border: 1px solid rgba(82, 62, 39, 0.11);
  border-radius: 14px;
  background: rgba(255, 252, 248, 0.84);
  text-align: left;
  cursor: pointer;
  transition:
    transform 140ms ease,
    box-shadow 140ms ease,
    border-color 140ms ease;

  &:hover {
    transform: translateY(-1px);
    box-shadow: 0 10px 20px rgba(74, 58, 40, 0.07);
    border-color: rgba(169, 122, 59, 0.28);
  }

  &.is-active {
    border-color: rgba(171, 120, 46, 0.42);
    background:
      radial-gradient(circle at top right, rgba(215, 163, 84, 0.18), transparent 30%),
      linear-gradient(135deg, #fffaf1, #f4ead9);
    box-shadow: 0 12px 22px rgba(102, 76, 36, 0.08);
  }

  &__top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;

    strong {
      color: #2b1d11;
      font-size: 14px;
      line-height: 1.4;
    }
  }

  &__meta {
    margin-bottom: 8px;
    color: #8a7354;
    font-size: 12px;
  }

  p {
    margin: 0;
    color: #655b50;
    font-size: 12px;
    line-height: 1.5;
  }

  &__footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-top: 10px;
    color: #7a6447;
    font-size: 12px;
  }

  &__actions {
    gap: 6px;
  }
}

.detail-card {
  margin-top: 12px;
  padding: 14px;
  border: 1px solid rgba(82, 62, 39, 0.11);
  border-radius: 16px;
  background: rgba(251, 247, 240, 0.78);

  &__label {
    margin-bottom: 8px;
    color: #876c49;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  h4 {
    margin: 0;
    color: #2a1c11;
    font-size: 18px;
  }

  p {
    margin: 8px 0 0;
    color: #6b6155;
    font-size: 12px;
    line-height: 1.5;
  }

  &__chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 10px 0 12px;
  }
}

.node-list {
  display: grid;
  gap: 8px;
}

.node-card {
  padding: 12px;
  border: 1px solid rgba(82, 62, 39, 0.12);
  border-radius: 14px;
  background: rgba(255, 252, 248, 0.86);

  &__header {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    align-items: flex-start;
  }

  &__title {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  &__body {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 8px;
    color: #5f554a;
    font-size: 12px;
    line-height: 1.55;
    white-space: pre-wrap;

    strong {
      color: #2d2014;
    }

    small {
      color: #7c6e61;
      font-size: 11px;
    }
  }
}

@media (max-width: 1280px) {
  .workspace-grid {
    grid-template-columns: 1fr;
  }

  .workspace-panel {
    min-height: auto;
  }
}
</style>
