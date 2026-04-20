import { apiClient, unwrapResponse } from "./client";
import type { Collection, Content, DraftSnapshot } from "./types";

export interface CreateCollectionPayload {
  slug: string;
  name: string;
  description?: string | null;
  visibility: string;
}

export interface UpdateCollectionPayload {
  slug?: string;
  name?: string;
  description?: string | null;
  visibility?: string;
}

export interface CreateContentPayload {
  slug: string;
  title: string;
  status: string;
  schema_id?: string | null;
}

export interface UpdateContentPayload {
  title?: string;
  status?: string;
  schema_id?: string | null;
}

export function listCollections() {
  return unwrapResponse<Collection[]>(apiClient.get("/collections"));
}

export function createCollection(payload: CreateCollectionPayload) {
  return unwrapResponse<Collection>(apiClient.post("/collections", payload));
}

export function updateCollection(collectionId: number, payload: UpdateCollectionPayload) {
  return unwrapResponse<Collection>(apiClient.patch(`/collections/${collectionId}`, payload));
}

export function listContents(collectionId: number) {
  return unwrapResponse<Content[]>(apiClient.get(`/collections/${collectionId}/contents`));
}

export function createContent(collectionId: number, payload: CreateContentPayload) {
  return unwrapResponse<Content>(apiClient.post(`/collections/${collectionId}/contents`, payload));
}

export function getContent(contentId: number) {
  return unwrapResponse<Content>(apiClient.get(`/contents/${contentId}`));
}

export function listAllContents() {
  return unwrapResponse<Content[]>(apiClient.get("/contents"));
}

export function updateContent(contentId: number, payload: UpdateContentPayload) {
  return unwrapResponse<Content>(apiClient.patch(`/contents/${contentId}`, payload));
}

export function getDraft(contentId: number) {
  return unwrapResponse<DraftSnapshot>(apiClient.get(`/draft/contents/${contentId}`));
}

export function reorderDraft(contentId: number, nodeIds: number[]) {
  return unwrapResponse<Content>(
    apiClient.patch(`/draft/contents/${contentId}`, { node_ids: nodeIds }),
  );
}
