export interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T;
}

export interface PaginationInfo {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  itemsPerPage: number;
  hasNextPage: boolean;
  hasPrevPage: boolean;
}

export interface PaginatedResponse<T> {
  success: boolean;
  message: string;
  data: T;
  pagination: PaginationInfo;
}

export interface BaseFilters {
  search?: string;
  page?: number;
  limit?: number;
  sort?: string;
  isActive?: boolean;
}

export interface BaseMetadata {
  createdBy?: string;
  updatedBy?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface BaseEntity {
  _id: string;
  createdAt?: string;
  updatedAt?: string;
  metadata?: BaseMetadata;
}