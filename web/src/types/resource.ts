export const RESOURCE_NAMES = [
  "collections",
  "files",
  "histories",
  "nodes",
  "snippets",
  "tags",
  "texts",
] as const;

export type ResourceName = (typeof RESOURCE_NAMES)[number];

export interface OptionItem {
  label: string;
  value: string | number;
}

export type FieldType = "text" | "textarea" | "number" | "select";

export interface ResourceField {
  key: string;
  label: string;
  type: FieldType;
  required?: boolean;
  placeholder?: string;
  optionsResource?: ResourceName;
  optionLabel?: string;
  optionValue?: string;
  staticOptions?: OptionItem[];
}

export interface ResourceConfig {
  resource: ResourceName;
  title: string;
  itemKey?: string;
  tableColumns: string[];
  fields: ResourceField[];
}
