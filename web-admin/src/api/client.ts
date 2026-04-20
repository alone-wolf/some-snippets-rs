import axios from "axios";
import { ElMessage } from "element-plus";

import { resolveApiBaseUrl } from "@/utils/env";

export interface ApiEnvelope<T> {
  data: T;
}

export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
  };
}

export const apiClient = axios.create({
  baseURL: resolveApiBaseUrl(),
  timeout: 15_000,
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error?.response?.data?.error?.message ||
      error?.message ||
      "请求失败，请稍后重试";
    ElMessage.error(message);
    return Promise.reject(error);
  },
);

export async function unwrapResponse<T>(request: Promise<{ data: ApiEnvelope<T> }>): Promise<T> {
  const response = await request;
  return response.data.data;
}
