import type { ApiResponse, ListData } from "../types/api";
import type { ResourceName } from "../types/resource";
import { http } from "./http";

export type ResourceRecord = Record<string, unknown>;

function ensureSuccess<T>(response: ApiResponse<T>): T {
  if (!response.success || response.data === undefined) {
    throw new Error(response.error ?? "Request failed");
  }
  return response.data;
}

export async function listRecords(
  resource: ResourceName,
  page: number,
  pageSize: number,
): Promise<ListData<ResourceRecord>> {
  const response = await http.get<ApiResponse<ListData<ResourceRecord>>>(`/api/v1/${resource}`, {
    params: {
      page,
      page_size: pageSize,
    },
  });
  return ensureSuccess(response.data);
}

export async function getRecord(
  resource: ResourceName,
  id: string | number,
): Promise<ResourceRecord> {
  const encoded = encodeURIComponent(String(id));
  const response = await http.get<ApiResponse<ResourceRecord>>(`/api/v1/${resource}/${encoded}`);
  return ensureSuccess(response.data);
}

export async function createRecord(
  resource: ResourceName,
  payload: ResourceRecord,
): Promise<ResourceRecord> {
  const response = await http.post<ApiResponse<ResourceRecord>>(`/api/v1/${resource}`, payload);
  return ensureSuccess(response.data);
}

export async function updateRecord(
  resource: ResourceName,
  id: string | number,
  payload: ResourceRecord,
): Promise<ResourceRecord> {
  const encoded = encodeURIComponent(String(id));
  const response = await http.put<ApiResponse<ResourceRecord>>(
    `/api/v1/${resource}/${encoded}`,
    payload,
  );
  return ensureSuccess(response.data);
}

export async function deleteRecord(resource: ResourceName, id: string | number): Promise<void> {
  const encoded = encodeURIComponent(String(id));
  await http.delete(`/api/v1/${resource}/${encoded}`);
}

export async function uploadFileRecord(file: File): Promise<ResourceRecord> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await http.post<ApiResponse<ResourceRecord>>("/api/v1/files/upload", formData);
  return ensureSuccess(response.data);
}
