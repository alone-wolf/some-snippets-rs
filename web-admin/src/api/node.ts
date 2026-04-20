import { apiClient, unwrapResponse } from "./client";
import type { FilePayload, NodeRecord } from "./types";

export function listNodes() {
  return unwrapResponse<NodeRecord[]>(apiClient.get("/nodes"));
}

export function getNode(nodeId: number) {
  return unwrapResponse<NodeRecord>(apiClient.get(`/nodes/${nodeId}`));
}

export function createTextNode(contentId: number, text: string) {
  return unwrapResponse<NodeRecord>(
    apiClient.post(`/contents/${contentId}/nodes`, { kind: "text", text }),
  );
}

export function createFileNode(contentId: number, file: FilePayload) {
  return unwrapResponse<NodeRecord>(
    apiClient.post(`/contents/${contentId}/nodes`, { kind: "file", file }),
  );
}

export function updateTextNode(nodeId: number, text: string) {
  return unwrapResponse<NodeRecord>(apiClient.patch(`/nodes/${nodeId}`, { text }));
}

export function updateFileNode(nodeId: number, file: FilePayload) {
  return unwrapResponse<NodeRecord>(apiClient.patch(`/nodes/${nodeId}`, { file }));
}
