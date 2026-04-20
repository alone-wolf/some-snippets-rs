export const appTitle = import.meta.env.VITE_APP_TITLE || "Some Snippets Admin";

export function resolveApiBaseUrl(): string {
  return import.meta.env.VITE_API_BASE_URL || "";
}
