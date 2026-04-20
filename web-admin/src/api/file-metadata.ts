import { apiClient, unwrapResponse } from "./client";
import type { FileMetadataRecord } from "./types";

export function listFileMetadata() {
  return unwrapResponse<FileMetadataRecord[]>(apiClient.get("/file-metadata"));
}
