export interface UserProfile {
  language?: string;
  phone?: string;
  timezone?: string;
  avatar?: string;
  address?: string;
}

export interface UserMetadata {
  createdBy?: string;
  updatedBy?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface UserPermission {
  _id?: string;
  name?: string;
  displayName?: string;
  resource?: string;
  action?: string;
  description?: string;
  category?: string;
  granted?: boolean;
  permission?: {
    _id: string;
    name: string;
    displayName?: string;
    resource: string;
    action: string;
    description?: string;
    category?: string;
    isActive: boolean;
  };
}

export interface UserSSO {
  provider?: 'keycloak';
  keycloakId?: string;
}

export interface User {
  _id: string;
  id?: string;
  firstName: string;
  lastName: string;
  email: string;
  password?: string;
  isActive: boolean;
  roles: string[] | any[];
  permissions: UserPermission[];
  profile?: UserProfile;
  lastLogin?: string;
  createdAt: string;
  updatedAt?: string;
  loginAttempts?: number;
  lockoutUntil?: string;
  isEmailVerified?: boolean;
  authMethod?: 'jwt' | 'sso';
  metadata?: UserMetadata;
  fullName?: string;
  isLocked?: boolean;
  sso?: UserSSO;
}

export interface UserFilters {
  search?: string;
  role?: string;
  isActive?: boolean;
  startDate?: string;
  endDate?: string;
  page?: number;
  limit?: number;
  sort?: string;
}

export interface UserSecurityProfile {
  loginCount: number;
  failedLogins: number;
  lastActivity?: Date;
  lastIP?: string;
  uniqueIPs: number;
  riskScore: number;
}

export interface CreateUserRequest {
  firstName: string;
  lastName: string;
  email: string;
  password?: string;
  roles?: string[];
  permissions?: { permission: string; granted: boolean }[];
  profile?: UserProfile;
  isActive?: boolean;
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
  password?: string;
  roles?: string[];
  permissions?: { permission: string; granted: boolean }[];
  profile?: UserProfile;
  isActive?: boolean;
}