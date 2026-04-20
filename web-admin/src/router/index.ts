import { createRouter, createWebHistory } from "vue-router";

import { appTitle } from "@/utils/env";

const routes = [
  {
    path: "/",
    name: "dashboard",
    component: () => import("@/views/dashboard/DashboardPage.vue"),
    meta: { title: "概览", layout: "app" },
  },
  {
    path: "/collections",
    name: "collections",
    component: () => import("@/views/collections/CollectionsPage.vue"),
    meta: { title: "内容工作台", layout: "app" },
  },
  {
    path: "/collections/management",
    name: "collections-management",
    component: () => import("@/views/collections/CollectionsManagementPage.vue"),
    meta: { title: "Collections Management", layout: "app" },
  },
  {
    path: "/contents/management",
    name: "contents-management",
    component: () => import("@/views/contents/ContentsManagementPage.vue"),
    meta: { title: "Contents Management", layout: "app" },
  },
  {
    path: "/nodes/management",
    name: "nodes-management",
    component: () => import("@/views/nodes/NodesManagementPage.vue"),
    meta: { title: "Nodes Management", layout: "app" },
  },
  {
    path: "/file-metadata/management",
    name: "file-metadata-management",
    component: () => import("@/views/file-metadata/FileMetadataManagementPage.vue"),
    meta: { title: "FileMetaData Management", layout: "app" },
  },
  {
    path: "/contents/:contentId/settings",
    name: "content-settings",
    component: () => import("@/views/contents/ContentSettingsPage.vue"),
    meta: { title: "内容设置", layout: "app" },
  },
  {
    path: "/contents/:contentId/editor",
    name: "content-editor",
    component: () => import("@/views/editor/EditorPage.vue"),
    meta: { title: "内容编辑", layout: "app" },
  },
  {
    path: "/contents/:contentId/versions",
    name: "content-versions",
    component: () => import("@/views/versions/VersionsPage.vue"),
    meta: { title: "版本管理", layout: "app" },
  },
  {
    path: "/contents/:contentId/versions/:version",
    name: "content-version-detail",
    component: () => import("@/views/versions/VersionDetailPage.vue"),
    meta: { title: "版本详情", layout: "app" },
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("@/views/not-found/NotFoundPage.vue"),
    meta: { title: "页面不存在", layout: "app" },
  },
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
});

router.afterEach((to) => {
  const title = typeof to.meta.title === "string" ? to.meta.title : "控制台";
  document.title = `${title} - ${appTitle}`;
});

export default router;
