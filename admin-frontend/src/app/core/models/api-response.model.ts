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

// Common filter base interface
export interface BaseFilters {
  search?: string;
  page?: number;
  limit?: number;
  sort?: string;
  isActive?: boolean;
}

// Common metadata interface
export interface BaseMetadata {
  createdBy?: string;
  updatedBy?: string;
  ipAddress?: string;
  userAgent?: string;
}

// Common base entity
export interface BaseEntity {
  _id: string;
  createdAt?: string;
  updatedAt?: string;
  metadata?: BaseMetadata;
}