export interface Collection {
  id: number;
  slug: string;
  name: string;
  description?: string | null;
  visibility: string;
  ownerId: string;
}

export interface Content {
  id: number;
  collectionId: number;
  slug: string;
  title: string;
  status: string;
  schemaId?: string | null;
  draftSnapshotKey?: string | null;
  latestSnapshotKey?: string | null;
  latestVersion: number;
  createdBy: string;
  updatedBy: string;
}

export interface DraftNodeRef {
  nodeId: number;
}

export interface DraftSnapshot {
  contentId: string;
  state: "draft";
  label?: string;
  nodes: DraftNodeRef[];
}

export interface FilePayload {
  filename: string;
  bucket: string;
  objectKey: string;
  mimeType?: string | null;
  sizeBytes: number;
  checksum?: string | null;
}

export interface NodeRecord {
  id: number;
  contentId: number;
  uuid: string;
  version: number;
  kind: "text" | "file";
  lifecycleState: "draft_only" | "committed";
  text?: string | null;
  prevNodeId?: number | null;
  meta?: Record<string, unknown> | null;
  createdBy: string;
  updatedBy: string;
  file?: FilePayload | null;
}

export interface FileMetadataRecord {
  id: number;
  nodeId: number;
  fileUuid: string;
  bucket: string;
  objectKey: string;
  filename: string;
  mimeType?: string | null;
  sizeBytes: number;
  checksum?: string | null;
  meta?: Record<string, unknown> | null;
}

export interface SnapshotNode {
  nodeId: number;
  uuid: string;
  version: number;
  kind: "text" | "file";
  text?: string | null;
  file?: FilePayload | null;
  meta?: Record<string, unknown> | null;
}

export interface LatestSnapshot {
  contentId: string;
  state: "latest";
  version: number;
  label?: string;
  nodes: SnapshotNode[];
}

export interface VersionSnapshot {
  contentId: string;
  state: "version";
  version: number;
  label?: string;
  nodes: SnapshotNode[];
}

export interface ContentVersionRecord {
  version: number;
  label?: string | null;
  snapshotKey: string;
  snapshotChecksum: string;
  createdBy: string;
}
