<template>
  <el-dialog v-model="open" :title="dialogTitle" width="480px" @closed="onClosed">
    <el-form label-position="top">
      <el-form-item label="名称">
        <el-input v-model="localForm.name" />
      </el-form-item>
      <el-form-item label="Slug">
        <el-input v-model="localForm.slug" />
      </el-form-item>
      <el-form-item label="描述">
        <el-input v-model="localForm.description" type="textarea" :rows="3" />
      </el-form-item>
      <el-form-item label="可见性">
        <el-select v-model="localForm.visibility" style="width: 100%">
          <el-option label="Private" value="private" />
          <el-option label="Public" value="public" />
        </el-select>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="open = false">取消</el-button>
      <el-button type="primary" @click="submit">{{ submitLabel }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, watch } from "vue";

const props = defineProps<{
  modelValue: boolean;
  mode: "create" | "edit";
  form: {
    name: string;
    slug: string;
    description?: string | null;
    visibility: string;
  };
}>();

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  submit: [
    payload: {
      name: string;
      slug: string;
      description?: string | null;
      visibility: string;
    },
  ];
}>();

const localForm = reactive({
  name: "",
  slug: "",
  description: "",
  visibility: "private",
});

const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit("update:modelValue", value),
});

const dialogTitle = computed(() => (props.mode === "edit" ? "修改 Collection" : "新建 Collection"));
const submitLabel = computed(() => (props.mode === "edit" ? "保存" : "创建"));

watch(
  () => props.form,
  (value) => {
    localForm.name = value.name;
    localForm.slug = value.slug;
    localForm.description = value.description || "";
    localForm.visibility = value.visibility;
  },
  { deep: true, immediate: true },
);

function submit() {
  emit("submit", {
    name: localForm.name,
    slug: localForm.slug,
    description: localForm.description || null,
    visibility: localForm.visibility,
  });
}

function onClosed() {
  emit("update:modelValue", false);
}
</script>
