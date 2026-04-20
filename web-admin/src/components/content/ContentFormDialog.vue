<template>
  <el-dialog v-model="open" :title="title" width="480px" @closed="onClosed">
    <el-form label-position="top">
      <el-form-item label="标题">
        <el-input v-model="localForm.title" />
      </el-form-item>
      <el-form-item label="Slug">
        <el-input v-model="localForm.slug" :disabled="mode === 'edit'" />
      </el-form-item>
      <el-form-item label="状态">
        <el-input v-model="localForm.status" />
      </el-form-item>
      <el-form-item label="Schema ID">
        <el-input v-model="localForm.schemaId" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="open = false">取消</el-button>
      <el-button type="primary" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, watch } from "vue";

const props = defineProps<{
  modelValue: boolean;
  mode: "create" | "edit";
  form: {
    title: string;
    slug: string;
    status: string;
    schemaId?: string | null;
  };
}>();

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  submit: [payload: { title: string; slug: string; status: string; schemaId?: string | null }];
}>();

const localForm = reactive({
  title: "",
  slug: "",
  status: "draft",
  schemaId: "",
});

const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit("update:modelValue", value),
});

const title = computed(() => (props.mode === "create" ? "新建 Content" : "编辑 Content"));

watch(
  () => props.form,
  (value) => {
    localForm.title = value.title;
    localForm.slug = value.slug;
    localForm.status = value.status;
    localForm.schemaId = value.schemaId || "";
  },
  { deep: true, immediate: true },
);

function submit() {
  emit("submit", {
    title: localForm.title,
    slug: localForm.slug,
    status: localForm.status,
    schemaId: localForm.schemaId || null,
  });
}

function onClosed() {
  emit("update:modelValue", false);
}
</script>
