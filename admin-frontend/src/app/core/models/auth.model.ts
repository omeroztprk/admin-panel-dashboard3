import { User, UserPermission } from './user.model';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  profile?: {
    language?: string;
  };
}

export interface LoginResponse {
  user: User;
  accessToken: string;
  refreshToken: string;
}

export interface TfaLoginResponse {
  requiresTfa: true;
  email: string;
  expiresIn: number;
  maxAttempts: number;
}

export interface TfaVerifyRequest {
  email: string;
  tfaCode: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  profile?: {
    language?: string;
    phone?: string;
    timezone?: string;
    avatar?: string;
    address?: string;
  };
}

export interface SessionInfo {
  _id: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
  lastActivity: string;
  createdAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export interface AuthUser {
  _id?: string;
  id?: string;
  email: string;
  firstName?: string;
  lastName?: string;
  roles?: any[];
  permissions?: UserPermission[];
  profile?: { 
    language?: string; 
    phone?: string; 
    timezone?: string;
    avatar?: string;
    address?: string;
  };
  createdAt?: string;
  lastLogin?: string;
  isActive?: boolean;
  authMethod?: 'jwt' | 'sso';
}

export type LoginDecision =
  | { requiresTfa: true; email: string }
  | { requiresTfa: false };