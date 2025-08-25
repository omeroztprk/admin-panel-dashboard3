export interface PermissionMetadata {
  createdBy?: string;
  updatedBy?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface Permission {
  _id: string;
  name: string;
  displayName?: string;
  resource: string;
  action: string;
  description?: string;
  category?: string;
  isActive: boolean;
  isSystem: boolean;
  createdAt?: string;
  updatedAt?: string;
  metadata?: PermissionMetadata;
}

export interface PermissionFilters {
  search?: string;
  resource?: string;
  action?: string;
  category?: string;
  isActive?: boolean;
  page?: number;
  limit?: number;
  sort?: string;
}

// Create/Update için minimal interface
export interface CreatePermissionRequest {
  name?: string; // Otomatik generate edilebilir
  displayName: string;
  resource: string;
  action: string;
  description?: string;
  category?: string;
  isActive?: boolean;
}

export interface UpdatePermissionRequest {
  name?: string;
  displayName?: string;
  resource?: string;
  action?: string;
  description?: string;
  category?: string;
  isActive?: boolean;
}

// Meta data interfaces
export interface PermissionResourcesResponse {
  resources: string[];
}

export interface PermissionActionsResponse {
  actions: string[];
}

export interface PermissionCategoriesResponse {
  categories: string[];
}