<template>
  <el-dialog v-model="open" title="创建版本" width="420px" @closed="onClosed">
    <el-form label-position="top">
      <el-form-item label="版本标签">
        <el-input v-model="label" placeholder="例如：release-candidate" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="open = false">取消</el-button>
      <el-button type="primary" @click="submit">创建</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";

const props = defineProps<{
  modelValue: boolean;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  submit: [label?: string];
}>();

const label = ref("");
const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit("update:modelValue", value),
});

watch(
  () => props.modelValue,
  (value) => {
    if (value) {
      label.value = "";
    }
  },
);

function submit() {
  emit("submit", label.value || undefined);
}

function onClosed() {
  emit("update:modelValue", false);
}
</script>
