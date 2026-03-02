<template>
  <el-container class="app-layout">
    <el-aside :width="uiStore.collapsed ? '64px' : '220px'" class="app-aside">
      <div class="logo">Snippets</div>
      <el-menu :default-active="route.path" :collapse="uiStore.collapsed" router>
        <el-menu-item index="/">Dashboard</el-menu-item>
        <el-menu-item v-for="item in menuItems" :key="item.resource" :index="item.path">
          {{ item.label }}
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="app-header">
        <el-button text @click="uiStore.toggleMenu">Toggle Menu</el-button>
        <span class="header-title">some-snippets Web Panel</span>
      </el-header>
      <el-main class="app-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { RESOURCE_NAV_ITEMS } from "../config/resources";
import { useRoute } from "vue-router";
import { useUiStore } from "../stores/ui";

const route = useRoute();
const uiStore = useUiStore();
const menuItems = RESOURCE_NAV_ITEMS;
</script>

<style scoped>
.app-layout {
  min-height: 100vh;
}

.app-aside {
  background: #fff;
  border-right: 1px solid #ebeef5;
}

.logo {
  box-sizing: border-box;
  height: 56px;
  padding: 16px;
  font-weight: 600;
}

.app-header {
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid #ebeef5;
  background: #fff;
}

.header-title {
  font-weight: 600;
}

.app-main {
  background: #f5f7fa;
}
</style>
