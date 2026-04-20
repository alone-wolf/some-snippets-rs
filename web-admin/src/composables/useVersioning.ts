import { ref } from "vue";

import {
  commitLatest,
  createVersion,
  getLatest,
  getVersion,
  listVersions,
  rollbackVersion,
} from "@/api/version";
import type { ContentVersionRecord, LatestSnapshot, VersionSnapshot } from "@/api/types";

export function useVersioning(contentId: number) {
  const versions = ref<ContentVersionRecord[]>([]);
  const latest = ref<LatestSnapshot | null>(null);
  const loading = ref(false);

  async function load() {
    loading.value = true;
    try {
      versions.value = await listVersions(contentId);
      latest.value = await getLatest(contentId).catch(() => null);
    } finally {
      loading.value = false;
    }
  }

  async function runCommit() {
    const result = await commitLatest(contentId);
    latest.value = result;
    versions.value = await listVersions(contentId);
    return result;
  }

  async function runCreateVersion(label?: string) {
    const snapshot = await createVersion(contentId, label);
    versions.value = await listVersions(contentId);
    latest.value = await getLatest(contentId).catch(() => latest.value);
    return snapshot;
  }

  async function runRollback(version: number) {
    await rollbackVersion(contentId, version);
  }

  async function loadVersionDetail(version: number): Promise<VersionSnapshot> {
    const response = await getVersion(contentId, version);
    return response.snapshot;
  }

  return {
    latest,
    load,
    loadVersionDetail,
    loading,
    runCommit,
    runCreateVersion,
    runRollback,
    versions,
  };
}
