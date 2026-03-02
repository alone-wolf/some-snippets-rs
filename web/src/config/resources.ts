import { RESOURCE_NAMES, type ResourceConfig, type ResourceName } from "../types/resource";

export const RESOURCE_CONFIGS: Record<ResourceName, ResourceConfig> = {
  collections: {
    resource: "collections",
    title: "Collections",
    itemKey: "key",
    tableColumns: ["key", "label", "description", "created_at", "updated_at"],
    fields: [
      { key: "label", label: "Label", type: "text", required: true },
      { key: "key", label: "Key", type: "text", required: true },
      { key: "description", label: "Description", type: "textarea" },
    ],
  },
  files: {
    resource: "files",
    title: "Files",
    tableColumns: [
      "id",
      "file_uuid",
      "storage_path",
      "original_filename",
      "mime_type",
      "byte_size",
      "sha256",
      "created_at",
    ],
    fields: [
      { key: "storage_path", label: "Storage Path", type: "text", required: true },
      {
        key: "original_filename",
        label: "Original Filename",
        type: "text",
        required: true,
      },
      { key: "mime_type", label: "Mime Type", type: "text" },
      { key: "byte_size", label: "Byte Size", type: "number" },
      { key: "sha256", label: "SHA256", type: "text" },
    ],
  },
  histories: {
    resource: "histories",
    title: "Histories",
    tableColumns: [
      "id",
      "snippet_id",
      "version_number",
      "message",
      "created_at",
      "updated_at",
    ],
    fields: [
      {
        key: "snippet_id",
        label: "Snippet",
        type: "select",
        required: true,
        optionsResource: "snippets",
        optionLabel: "title",
      },
      { key: "version_number", label: "Version", type: "number", required: true },
      { key: "message", label: "Message", type: "textarea" },
    ],
  },
  nodes: {
    resource: "nodes",
    title: "Nodes",
    tableColumns: [
      "id",
      "kind",
      "snippet_id",
      "text_id",
      "file_id",
      "meta_json",
      "created_at",
    ],
    fields: [
      {
        key: "kind",
        label: "Kind",
        type: "select",
        required: true,
        staticOptions: [
          { label: "Text", value: "text" },
          { label: "File", value: "file" },
        ],
      },
      {
        key: "snippet_id",
        label: "Snippet",
        type: "select",
        required: true,
        optionsResource: "snippets",
        optionLabel: "title",
      },
      {
        key: "text_id",
        label: "Text",
        type: "select",
        optionsResource: "texts",
        optionLabel: "id",
      },
      {
        key: "file_id",
        label: "File",
        type: "select",
        optionsResource: "files",
        optionLabel: "original_filename",
      },
      { key: "meta_json", label: "Meta JSON", type: "textarea" },
    ],
  },
  snippets: {
    resource: "snippets",
    title: "Snippets",
    tableColumns: [
      "id",
      "connection_id",
      "title",
      "description",
      "current_history_id",
      "created_at",
      "updated_at",
    ],
    fields: [
      {
        key: "connection_id",
        label: "Collection",
        type: "select",
        required: true,
        optionsResource: "collections",
        optionLabel: "label",
      },
      { key: "title", label: "Title", type: "text", required: true },
      { key: "description", label: "Description", type: "textarea" },
      {
        key: "current_history_id",
        label: "Current History",
        type: "select",
        optionsResource: "histories",
        optionLabel: "id",
      },
    ],
  },
  tags: {
    resource: "tags",
    title: "Tags",
    tableColumns: ["id", "name", "created_at"],
    fields: [{ key: "name", label: "Name", type: "text", required: true }],
  },
  texts: {
    resource: "texts",
    title: "Texts",
    tableColumns: ["id", "kind", "content", "created_at"],
    fields: [
      { key: "kind", label: "Kind", type: "text", required: true },
      { key: "content", label: "Content", type: "textarea", required: true },
    ],
  },
};

export const RESOURCE_NAV_ITEMS: Array<{
  resource: ResourceName;
  path: string;
  label: string;
}> = RESOURCE_NAMES.map((resource) => ({
  resource,
  path: `/${resource}`,
  label: RESOURCE_CONFIGS[resource].title,
}));
