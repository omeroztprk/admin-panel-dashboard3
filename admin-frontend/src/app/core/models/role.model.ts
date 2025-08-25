import { Permission } from './permission.model';

export interface RoleMetadata {
  createdBy?: string;
  updatedBy?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface Role {
  _id: string;
  name: string;
  displayName: string;
  description?: string;
  priority: number;
  permissions: Permission[] | string[];
  isActive: boolean;
  isSystem: boolean;
  createdAt?: string;
  updatedAt?: string;
  metadata?: RoleMetadata;
  userCount?: number;
}

export interface RoleFilters {
  search?: string;
  isActive?: boolean;
  includePermissions?: boolean;
  page?: number;
  limit?: number;
  sort?: string;
}

export interface CreateRoleRequest {
  name: string;
  displayName: string;
  description?: string;
  permissions?: string[];
  priority?: number;
  isActive?: boolean;
}

export interface UpdateRoleRequest {
  name?: string;
  displayName?: string;
  description?: string;
  permissions?: string[];
  priority?: number;
  isActive?: boolean;
}

export interface RoleUser {
  _id: string;
  id?: string;
  firstName: string;
  lastName: string;
  email: string;
  isActive: boolean;
  lastLogin?: string;
  createdAt: string;
  fullName?: string;
  isLocked?: boolean;
  lockoutUntil?: string;
}