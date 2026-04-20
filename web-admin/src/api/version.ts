import { apiClient, unwrapResponse } from "./client";
import type { ContentVersionRecord, LatestSnapshot, VersionSnapshot } from "./types";

export function commitLatest(contentId: number) {
  return unwrapResponse<LatestSnapshot>(apiClient.post(`/contents/${contentId}/commit`));
}

export function createVersion(contentId: number, label?: string) {
  return unwrapResponse<VersionSnapshot>(
    apiClient.post(`/contents/${contentId}/versions`, { label }),
  );
}

export function listVersions(contentId: number) {
  return unwrapResponse<ContentVersionRecord[]>(apiClient.get(`/contents/${contentId}/versions`));
}

export function getLatest(contentId: number) {
  return unwrapResponse<LatestSnapshot>(apiClient.get(`/latest/contents/${contentId}`));
}

export function getVersion(contentId: number, version: number) {
  return unwrapResponse<{ snapshot: VersionSnapshot }>(
    apiClient.get(`/versions/contents/${contentId}/${version}`),
  );
}

export function rollbackVersion(contentId: number, version: number) {
  return unwrapResponse(apiClient.post(`/contents/${contentId}/rollback`, { version }));
}
