<template>
  <el-result icon="warning" title="页面不存在" sub-title="请检查地址，或从左侧导航重新进入。">
    <template #extra>
      <el-button type="primary" @click="$router.push('/')">返回首页</el-button>
    </template>
  </el-result>
</template>

<script setup lang="ts">
</script>
