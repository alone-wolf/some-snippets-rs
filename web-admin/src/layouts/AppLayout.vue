<template>
  <el-container class="app-layout">
    <el-aside width="248px" class="app-layout__aside">
      <div class="app-layout__brand">
        <div class="app-layout__brand-badge">CMS OPS</div>
        <div class="app-layout__brand-title">Some Snippets Admin</div>
        <div class="app-layout__brand-copy">面向 Collection、Content、Node 的单站式管理台。</div>
      </div>

      <el-menu :default-active="activePath" class="app-layout__menu" router>
        <el-menu-item index="/">
          <span>概览</span>
        </el-menu-item>
        <el-menu-item index="/collections/management">
          <span>Collections</span>
        </el-menu-item>
        <el-menu-item index="/contents/management">
          <span>Contents</span>
        </el-menu-item>
        <el-menu-item index="/nodes/management">
          <span>Nodes</span>
        </el-menu-item>
        <el-menu-item index="/file-metadata/management">
          <span>FileMetaData</span>
        </el-menu-item>
        <el-menu-item index="/collections">
          <span>内容工作台</span>
        </el-menu-item>
      </el-menu>

      <div class="app-layout__quick">
        <div class="app-layout__context-label">常用 Collections</div>
        <button
          v-for="item in quickCollections"
          :key="item.id"
          type="button"
          class="app-layout__quick-item"
          :class="{ 'is-active': item.id === activeCollection?.id && activePath === '/collections' }"
          @click="openWorkspaceForCollection(item.id)"
        >
          <strong>{{ item.name }}</strong>
          <small>{{ item.slug }}</small>
        </button>
        <button type="button" class="app-layout__quick-more" @click="openCollectionsManagement">
          Show More
        </button>
      </div>
    </el-aside>
    <el-container>
      <el-main class="app-layout__main">
        <slot />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute, useRouter } from "vue-router";

import { listCollections } from "@/api/content";
import { useAppStore } from "@/stores/app";

const route = useRoute();
const router = useRouter();
const appStore = useAppStore();

const activePath = computed(() =>
  route.path.startsWith("/collections/management")
    ? "/collections/management"
    : route.path.startsWith("/contents/management")
      ? "/contents/management"
      : route.path.startsWith("/nodes/management")
        ? "/nodes/management"
        : route.path.startsWith("/file-metadata/management")
          ? "/file-metadata/management"
          : route.path.startsWith("/collections") || route.path.startsWith("/contents")
            ? "/collections"
            : route.path,
);
const quickCollections = computed(() => appStore.collections.slice(0, 3));
const activeCollection = computed(() => appStore.activeCollection);
async function hydrateCollections() {
  if (appStore.collections.length > 0) {
    return;
  }

  try {
    appStore.setCollections(await listCollections());
  } catch {
    // Ignore sidebar hydration failures and let feature pages retry with full-page affordances.
  }
}

function openWorkspaceForCollection(collectionId: number) {
  appStore.setActiveCollection(collectionId);
  void router.push({
    name: "collections",
    query: { collectionId: String(collectionId) },
  });
}

function openCollectionsManagement() {
  void router.push({ name: "collections-management" });
}

onMounted(() => {
  void hydrateCollections();
});
</script>

<style scoped lang="scss">
.app-layout {
  min-height: 100vh;
  background:
    radial-gradient(circle at top left, rgba(199, 145, 74, 0.13), transparent 25%),
    linear-gradient(180deg, #f7f1e6 0%, #f2ede4 40%, #f5f4f0 100%);

  &__aside {
    padding: 16px 14px;
    background:
      linear-gradient(180deg, rgba(42, 31, 21, 0.98), rgba(23, 18, 12, 0.98)),
      #1a130d;
    color: #f8f1e8;
    border-right: 1px solid rgba(255, 255, 255, 0.06);
  }

  &__brand {
    padding: 6px 8px 14px;
    margin-bottom: 14px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  }

  &__brand-badge {
    display: inline-flex;
    margin-bottom: 10px;
    padding: 4px 8px;
    border-radius: 999px;
    background: rgba(229, 186, 125, 0.14);
    color: #f7cf91;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.1em;
  }

  &__brand-title {
    font-size: 20px;
    font-weight: 700;
    line-height: 1.2;
  }

  &__brand-copy {
    margin-top: 8px;
    color: rgba(248, 241, 232, 0.74);
    font-size: 12px;
    line-height: 1.5;
  }

  &__menu {
    border-right: none;
    background: transparent;
  }
  &__quick {
    margin-top: 12px;
    display: grid;
    gap: 6px;
  }

  &__context-label {
    margin-bottom: 10px;
    color: rgba(248, 241, 232, 0.66);
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  &__quick-item,
  &__quick-more {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.04);
    color: #fff7ef;
    text-align: left;
    cursor: pointer;
  }

  &__quick-item {
    display: flex;
    flex-direction: column;
    gap: 3px;

    strong {
      font-size: 13px;
      font-weight: 700;
    }

    small {
      color: rgba(248, 241, 232, 0.66);
      font-size: 11px;
      line-height: 1.4;
    }

    &.is-active {
      border-color: rgba(241, 199, 124, 0.28);
      background: linear-gradient(135deg, rgba(237, 194, 127, 0.18), rgba(255, 255, 255, 0.06));
    }
  }

  &__quick-more {
    color: rgba(248, 241, 232, 0.78);
    font-size: 12px;
    font-weight: 700;
  }

  &__main {
    padding: 14px;
  }

  :deep(.el-menu) {
    background: transparent;
  }

  :deep(.el-menu-item) {
    margin-bottom: 4px;
    border-radius: 10px;
    color: rgba(248, 241, 232, 0.76);
    height: 42px;
    line-height: 42px;
    font-size: 13px;
  }

  :deep(.el-menu-item:hover) {
    background: rgba(255, 255, 255, 0.06);
    color: #fff7ef;
  }

  :deep(.el-menu-item.is-active) {
    background: linear-gradient(135deg, rgba(237, 194, 127, 0.18), rgba(255, 255, 255, 0.06));
    color: #fff7ef;
  }

  @media (max-width: 960px) {
    display: block;

    &__aside {
      width: auto !important;
      border-right: none;
    }

    &__header {
      margin-top: 0;
      border-radius: 0;
    }
  }
}
</style>
