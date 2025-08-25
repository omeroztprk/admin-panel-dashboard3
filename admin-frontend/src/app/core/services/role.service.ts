import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../../environments/environment.development';
import { 
  Role, 
  RoleFilters, 
  CreateRoleRequest, 
  UpdateRoleRequest, 
  RoleUser,
  Permission,
  PaginatedResponse,
  ApiResponse
} from '../models';

@Injectable({
  providedIn: 'root'
})
export class RoleService {
  private apiUrl = `${environment.apiBase}/roles`;

  constructor(private http: HttpClient) {}

  getRoles(filters: RoleFilters = {}): Observable<PaginatedResponse<{ roles: Role[] }>> {
    const params: any = {};
    Object.keys(filters).forEach(key => {
      const value = (filters as any)[key];
      if (value !== undefined && value !== null) {
        if (typeof value === 'boolean') {
          params[key] = value.toString();
        } else {
          params[key] = String(value);
        }
      }
    });
    
    return this.http.get<PaginatedResponse<{ roles: Role[] }>>(this.apiUrl, { params })
      .pipe(
        catchError(error => {
          console.error('Get roles error:', error);
          return throwError(() => error);
        })
      );
  }

  getRoleById(id: string, includePermissions = true): Observable<ApiResponse<{ role: Role }>> {
    return this.http.get<ApiResponse<{ role: Role }>>(`${this.apiUrl}/${id}`, { 
      params: { includePermissions: includePermissions.toString() } 
    }).pipe(
      catchError(error => {
        console.error('Get role by ID error:', error);
        return throwError(() => error);
      })
    );
  }

  createRole(roleData: CreateRoleRequest): Observable<ApiResponse<{ role: Role }>> {
    return this.http.post<ApiResponse<{ role: Role }>>(this.apiUrl, roleData)
      .pipe(
        catchError(error => {
          console.error('Create role error:', error);
          return throwError(() => error);
        })
      );
  }

  updateRole(id: string, roleData: UpdateRoleRequest): Observable<ApiResponse<{ role: Role }>> {
    return this.http.patch<ApiResponse<{ role: Role }>>(`${this.apiUrl}/${id}`, roleData)
      .pipe(
        catchError(error => {
          console.error('Update role error:', error);
          return throwError(() => error);
        })
      );
  }

  deleteRole(id: string): Observable<ApiResponse<any>> {
    return this.http.delete<ApiResponse<any>>(`${this.apiUrl}/${id}`)
      .pipe(
        catchError(error => {
          console.error('Delete role error:', error);
          return throwError(() => error);
        })
      );
  }

  toggleRoleStatus(id: string, isActive: boolean): Observable<ApiResponse<{ role: Role }>> {
    return this.http.patch<ApiResponse<{ role: Role }>>(`${this.apiUrl}/${id}/status`, { isActive })
      .pipe(
        catchError(error => {
          console.error('Toggle role status error:', error);
          return throwError(() => error);
        })
      );
  }

  getRoleUsers(id: string, options: { page?: number; limit?: number; sort?: string } = {}): Observable<PaginatedResponse<{ users: RoleUser[] }>> {
    const params: any = {};
    Object.keys(options).forEach(key => {
      const value = (options as any)[key];
      if (value !== undefined && value !== null) {
        params[key] = String(value);
      }
    });
    
    return this.http.get<PaginatedResponse<{ users: RoleUser[] }>>(`${this.apiUrl}/${id}/users`, { params })
      .pipe(
        catchError(error => {
          console.error('Get role users error:', error);
          return throwError(() => error);
        })
      );
  }

  assignPermissions(id: string, permissions: string[]): Observable<ApiResponse<{ role: Role }>> {
    return this.http.patch<ApiResponse<{ role: Role }>>(`${this.apiUrl}/${id}/permissions`, { permissions });
  }

  removePermissions(id: string, permissions: string[]): Observable<ApiResponse<{ role: Role }>> {
    return this.http.delete<ApiResponse<{ role: Role }>>(`${this.apiUrl}/${id}/permissions`, { body: { permissions } });
  }

  getAllPermissions(): Observable<ApiResponse<{ permissions: Permission[] }>> {
    return this.http.get<ApiResponse<{ permissions: Permission[] }>>(`${environment.apiBase}/permissions`)
      .pipe(
        catchError(error => {
          console.error('Get all permissions error:', error);
          return throwError(() => error);
        })
      );
  }
}