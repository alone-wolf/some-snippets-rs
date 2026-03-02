<template>
  <el-card>
    <template #header>
      <div class="header">
        <span>Dashboard</span>
      </div>
    </template>

    <p class="summary">
      Web Panel for managing all snippet resources. Use the navigation menu to open a CRUD page.
    </p>

    <div class="quick-links">
      <el-button
        v-for="item in links"
        :key="item.path"
        type="primary"
        plain
        @click="router.push(item.path)"
      >
        {{ item.label }}
      </el-button>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { RESOURCE_NAV_ITEMS } from "../config/resources";
import { useRouter } from "vue-router";

const router = useRouter();

const links = RESOURCE_NAV_ITEMS.map((item) => ({ path: item.path, label: item.label }));
</script>

<style scoped>
.header {
  font-weight: 600;
}

.summary {
  margin-bottom: 16px;
}

.quick-links {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
</style>
