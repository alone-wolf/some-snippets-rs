<template>
  <el-dialog v-model="open" :title="title" width="560px" @closed="onClosed">
    <el-form label-position="top">
      <el-form-item label="节点类型">
        <el-segmented v-model="localKind" :options="kindOptions" :disabled="mode === 'edit'" />
      </el-form-item>

      <template v-if="localKind === 'text'">
        <el-form-item label="文本内容">
          <el-input v-model="localText" type="textarea" :rows="8" />
        </el-form-item>
      </template>

      <template v-else>
        <el-form-item label="文件名">
          <el-input v-model="fileForm.filename" />
        </el-form-item>
        <el-form-item label="Bucket">
          <el-input v-model="fileForm.bucket" />
        </el-form-item>
        <el-form-item label="Object Key">
          <el-input v-model="fileForm.objectKey" />
        </el-form-item>
        <el-form-item label="MIME Type">
          <el-input v-model="fileForm.mimeType" />
        </el-form-item>
        <el-form-item label="大小（bytes）">
          <el-input-number v-model="fileForm.sizeBytes" :min="0" />
        </el-form-item>
        <el-form-item label="Checksum">
          <el-input v-model="fileForm.checksum" />
        </el-form-item>
      </template>
    </el-form>
    <template #footer>
      <el-button @click="open = false">取消</el-button>
      <el-button type="primary" @click="submit">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";

import type { FilePayload, NodeRecord } from "@/api/types";

const props = defineProps<{
  modelValue: boolean;
  mode: "create" | "edit";
  node?: NodeRecord | null;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
  submit: [payload: { kind: "text" | "file"; text?: string; file?: FilePayload }];
}>();

const localKind = ref<"text" | "file">("text");
const localText = ref("");
const fileForm = reactive<FilePayload>({
  filename: "",
  bucket: "content-assets",
  objectKey: "",
  mimeType: "",
  sizeBytes: 0,
  checksum: "",
});

const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit("update:modelValue", value),
});

const kindOptions = [
  { label: "Text", value: "text" },
  { label: "File", value: "file" },
];

const title = computed(() => (props.mode === "create" ? "新增节点" : "编辑节点"));

watch(
  () => props.node,
  (value) => {
    localKind.value = value?.kind ?? "text";
    localText.value = value?.text ?? "";
    fileForm.filename = value?.file?.filename ?? "";
    fileForm.bucket = value?.file?.bucket ?? "content-assets";
    fileForm.objectKey = value?.file?.objectKey ?? "";
    fileForm.mimeType = value?.file?.mimeType ?? "";
    fileForm.sizeBytes = value?.file?.sizeBytes ?? 0;
    fileForm.checksum = value?.file?.checksum ?? "";
  },
  { immediate: true },
);

function submit() {
  emit(
    "submit",
    localKind.value === "text"
      ? { kind: "text", text: localText.value }
      : {
          kind: "file",
          file: {
            filename: fileForm.filename,
            bucket: fileForm.bucket,
            objectKey: fileForm.objectKey,
            mimeType: fileForm.mimeType || undefined,
            sizeBytes: fileForm.sizeBytes,
            checksum: fileForm.checksum || undefined,
          },
        },
  );
}

function onClosed() {
  emit("update:modelValue", false);
}
</script>
