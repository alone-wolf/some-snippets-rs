<template>
  <el-card>
    <template #header>
      <div class="card-header">
        <span>{{ config.title }}</span>
        <div class="card-actions">
          <el-button v-if="isFileResource" :loading="uploading" @click="triggerFilePicker">
            Upload File
          </el-button>
          <el-button type="primary" @click="openCreateDialog">New</el-button>
        </div>
      </div>
      <input
        v-if="isFileResource"
        ref="fileInputRef"
        type="file"
        class="hidden-file-input"
        @change="onFileSelected"
      />
    </template>

    <el-table :data="tableData" border v-loading="listLoading">
      <el-table-column
        v-for="column in config.tableColumns"
        :key="column"
        :prop="column"
        :label="column"
        min-width="140"
        show-overflow-tooltip
      >
        <template #default="scope">
          {{ formatValue(scope.row[column]) }}
        </template>
      </el-table-column>
      <el-table-column label="Actions" fixed="right" width="160">
        <template #default="scope">
          <el-button link type="primary" @click="openEditDialog(scope.row)">Edit</el-button>
          <el-button link type="danger" @click="removeRow(scope.row)">Delete</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination-row">
      <el-select v-model="pageSize" style="width: 120px" @change="onPageSizeChange">
        <el-option v-for="size in [10, 20, 50, 100]" :key="size" :label="`${size}/page`" :value="size" />
      </el-select>
      <el-button :disabled="page <= 1" @click="goPrevPage">Prev</el-button>
      <span>Page {{ page }}</span>
      <el-button :disabled="tableData.length < pageSize" @click="goNextPage">Next</el-button>
      <el-button @click="loadList">Refresh</el-button>
    </div>
  </el-card>

  <el-dialog v-model="dialogVisible" :title="dialogTitle" width="680px" @closed="resetDialogState">
    <el-form ref="formRef" :model="formModel" :rules="formRules" label-width="140px">
      <el-form-item v-for="field in config.fields" :key="field.key" :label="field.label" :prop="field.key">
        <el-input
          v-if="field.type === 'text'"
          v-model="formModel[field.key]"
          :placeholder="field.placeholder ?? `Please input ${field.label}`"
        />

        <el-input
          v-else-if="field.type === 'textarea'"
          v-model="formModel[field.key]"
          type="textarea"
          :rows="3"
          :placeholder="field.placeholder ?? `Please input ${field.label}`"
        />

        <el-input-number
          v-else-if="field.type === 'number'"
          v-model="formModel[field.key]"
          controls-position="right"
          style="width: 100%"
        />

        <el-select
          v-else
          v-model="formModel[field.key]"
          clearable
          filterable
          style="width: 100%"
          :disabled="isFieldDisabled(field.key)"
          :placeholder="field.placeholder ?? `Please select ${field.label}`"
        >
          <el-option
            v-for="option in getFieldOptions(field)"
            :key="String(option.value)"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="dialogVisible = false">Cancel</el-button>
      <el-button type="primary" :loading="submitLoading" @click="submitForm">Submit</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import type { FormInstance, FormRules } from "element-plus";
import { RESOURCE_CONFIGS } from "../config/resources";
import type { OptionItem, ResourceField, ResourceName } from "../types/resource";
import type { ResourceRecord } from "../services/resource-service";
import {
  createRecord,
  deleteRecord,
  getRecord,
  listRecords,
  uploadFileRecord,
  updateRecord,
} from "../services/resource-service";
import { getErrorMessage } from "../utils/error";

const props = defineProps<{
  resource: ResourceName;
}>();

const config = computed(() => RESOURCE_CONFIGS[props.resource]);

const listLoading = ref(false);
const submitLoading = ref(false);
const dialogVisible = ref(false);
const dialogMode = ref<"create" | "edit">("create");
const currentIdentifier = ref<string | number | null>(null);
const uploading = ref(false);
const fileInputRef = ref<HTMLInputElement>();

const page = ref(1);
const pageSize = ref(20);
const tableData = ref<ResourceRecord[]>([]);
const isFileResource = computed(() => props.resource === "files");

const relationOptions = reactive<Record<string, OptionItem[]>>({});
const formModel = reactive<Record<string, unknown>>({});
const formRef = ref<FormInstance>();

const dialogTitle = computed(() =>
  dialogMode.value === "create" ? `Create ${config.value.title}` : `Edit ${config.value.title}`,
);

const formRules = computed<FormRules>(() => {
  const rules: FormRules = {};
  for (const field of config.value.fields) {
    if (field.required) {
      rules[field.key] = [
        {
          validator: (_rule, value, callback) => {
            if (value === null || value === undefined) {
              callback(new Error(`${field.label} is required`));
              return;
            }
            if (typeof value === "string" && value.trim().length === 0) {
              callback(new Error(`${field.label} is required`));
              return;
            }
            callback();
          },
          trigger: ["blur", "change"],
        },
      ];
    }
  }

  if (props.resource === "nodes") {
    rules.text_id = [
      {
        validator: (_rule, value, callback) => {
          if (formModel.kind === "text" && (value === null || value === undefined || value === "")) {
            callback(new Error("text_id is required when kind=text"));
            return;
          }
          callback();
        },
        trigger: "change",
      },
    ];
    rules.file_id = [
      {
        validator: (_rule, value, callback) => {
          if (formModel.kind === "file" && (value === null || value === undefined || value === "")) {
            callback(new Error("file_id is required when kind=file"));
            return;
          }
          callback();
        },
        trigger: "change",
      },
    ];
  }

  return rules;
});

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function clearFormModel() {
  for (const key of Object.keys(formModel)) {
    delete formModel[key];
  }
}

function resetFormModel(record?: ResourceRecord) {
  clearFormModel();
  for (const field of config.value.fields) {
    const currentValue = record?.[field.key];
    if (currentValue !== undefined && currentValue !== null) {
      formModel[field.key] = currentValue;
      continue;
    }
    formModel[field.key] = field.type === "text" || field.type === "textarea" ? "" : null;
  }
}

function resetDialogState() {
  currentIdentifier.value = null;
  formRef.value?.clearValidate();
}

function isFieldDisabled(fieldKey: string): boolean {
  if (props.resource !== "nodes") {
    return false;
  }
  if (fieldKey === "text_id") {
    return formModel.kind === "file";
  }
  if (fieldKey === "file_id") {
    return formModel.kind === "text";
  }
  return false;
}

function getFieldOptions(field: ResourceField): OptionItem[] {
  if (field.staticOptions) {
    return field.staticOptions;
  }
  return relationOptions[field.key] ?? [];
}

function getRecordIdentifier(row: ResourceRecord): string | number | null {
  const key = config.value.itemKey ?? "id";
  const raw = row[key];
  if (typeof raw === "number" || typeof raw === "string") {
    const value = raw.toString().trim();
    return value.length === 0 ? null : raw;
  }
  return null;
}

function toDisplayIdentifier(value: string | number): string {
  return typeof value === "string" ? value : String(value);
}

function toPathIdentifier(value: string | number): string {
  if (typeof value === "number") {
    return String(value);
  }
  return value;
}

async function loadRelationOptions() {
  const entries = config.value.fields.filter((field) => field.optionsResource);
  for (const field of entries) {
    try {
      const resource = field.optionsResource as ResourceName;
      const data = await listRecords(resource, 1, 200);
      const labelKey = field.optionLabel ?? "id";
      const valueKey = field.optionValue ?? "id";
      relationOptions[field.key] = data.items.map((item) => ({
        label: String(item[labelKey] ?? item.id ?? "-"),
        value: (item[valueKey] as string | number) ?? String(item.id ?? ""),
      }));
    } catch (error) {
      relationOptions[field.key] = [];
      ElMessage.error(getErrorMessage(error));
    }
  }
}

async function loadList() {
  listLoading.value = true;
  try {
    const data = await listRecords(props.resource, page.value, pageSize.value);
    tableData.value = data.items;
  } catch (error) {
    ElMessage.error(getErrorMessage(error));
  } finally {
    listLoading.value = false;
  }
}

function openCreateDialog() {
  dialogMode.value = "create";
  currentIdentifier.value = null;
  resetFormModel();
  dialogVisible.value = true;
}

function triggerFilePicker() {
  fileInputRef.value?.click();
}

function formatFileSize(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

async function onFileSelected(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) {
    return;
  }

  ElMessage.info(`Selected: ${file.name} (${formatFileSize(file.size)}, ${file.type || "unknown"})`);

  try {
    uploading.value = true;
    const created = await uploadFileRecord(file);
    const fileUuid = String(created.file_uuid ?? "-");
    ElMessage.success(`Uploaded successfully (uuid: ${fileUuid})`);
    await loadList();
  } catch (error) {
    ElMessage.error(getErrorMessage(error));
  } finally {
    uploading.value = false;
    input.value = "";
  }
}

async function openEditDialog(row: ResourceRecord) {
  const identifier = getRecordIdentifier(row);
  if (identifier === null) {
    ElMessage.error("Invalid resource identifier");
    return;
  }

  dialogMode.value = "edit";
  currentIdentifier.value = identifier;
  try {
    const record = await getRecord(props.resource, toPathIdentifier(identifier));
    resetFormModel(record);
    dialogVisible.value = true;
  } catch (error) {
    ElMessage.error(getErrorMessage(error));
  }
}

function normalizePayload(): ResourceRecord {
  const payload: ResourceRecord = {};
  for (const field of config.value.fields) {
    const value = formModel[field.key];
    if (field.type === "text" || field.type === "textarea") {
      const text = typeof value === "string" ? value.trim() : "";
      payload[field.key] = text.length > 0 ? text : null;
      continue;
    }
    if (field.type === "number") {
      payload[field.key] = value === null || value === undefined || value === "" ? null : Number(value);
      continue;
    }
    payload[field.key] = value === undefined || value === "" ? null : value;
  }
  return payload;
}

async function submitForm() {
  try {
    await formRef.value?.validate();
    const payload = normalizePayload();

    submitLoading.value = true;
    if (dialogMode.value === "create") {
      await createRecord(props.resource, payload);
      ElMessage.success("Created successfully");
    } else {
      if (!currentIdentifier.value) {
        throw new Error("Missing resource identifier");
      }
      await updateRecord(props.resource, toPathIdentifier(currentIdentifier.value), payload);
      ElMessage.success("Updated successfully");
    }
    dialogVisible.value = false;
    await loadList();
  } catch (error) {
    ElMessage.error(getErrorMessage(error));
  } finally {
    submitLoading.value = false;
  }
}

async function removeRow(row: ResourceRecord) {
  const identifier = getRecordIdentifier(row);
  if (identifier === null) {
    ElMessage.error("Invalid resource identifier");
    return;
  }

  try {
    await ElMessageBox.confirm(
      `Delete this record (${toDisplayIdentifier(identifier)})?`,
      "Confirm",
      { type: "warning" },
    );
    await deleteRecord(props.resource, toPathIdentifier(identifier));
    ElMessage.success("Deleted successfully");

    if (tableData.value.length === 1 && page.value > 1) {
      page.value -= 1;
    }
    await loadList();
  } catch (error) {
    if (String(error).includes("cancel")) {
      return;
    }
    ElMessage.error(getErrorMessage(error));
  }
}

async function goPrevPage() {
  if (page.value <= 1) {
    return;
  }
  page.value -= 1;
  await loadList();
}

async function goNextPage() {
  if (tableData.value.length < pageSize.value) {
    return;
  }
  page.value += 1;
  await loadList();
}

async function onPageSizeChange() {
  page.value = 1;
  await loadList();
}

watch(
  () => props.resource,
  async () => {
    page.value = 1;
    resetFormModel();
    await loadRelationOptions();
    await loadList();
  },
);

watch(
  () => formModel.kind,
  (kind) => {
    if (props.resource !== "nodes") {
      return;
    }
    if (kind === "text") {
      formModel.file_id = null;
      return;
    }
    if (kind === "file") {
      formModel.text_id = null;
    }
  },
);

onMounted(async () => {
  resetFormModel();
  await loadRelationOptions();
  await loadList();
});
</script>

<style scoped>
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.pagination-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 16px;
}

.hidden-file-input {
  display: none;
}
</style>
