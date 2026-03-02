export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  request_id?: string;
  status_code?: number;
}

export interface ListData<T> {
  items: T[];
  page: number;
  page_size: number;
}
