import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { environment } from '../../../environments/environment.development';
import { 
  Permission, 
  PermissionFilters, 
  CreatePermissionRequest, 
  UpdatePermissionRequest,
  PermissionResourcesResponse,
  PermissionActionsResponse,
  PermissionCategoriesResponse,
  PaginatedResponse,
  ApiResponse
} from '../models';

@Injectable({
  providedIn: 'root'
})
export class PermissionService {
  private apiUrl = `${environment.apiBase}/permissions`;

  constructor(private http: HttpClient, private authService: AuthService) {}

  getPermissions(filters: PermissionFilters = {}): Observable<PaginatedResponse<{ permissions: Permission[] }>> {
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
    
    return this.http.get<PaginatedResponse<{ permissions: Permission[] }>>(this.apiUrl, { params })
      .pipe(
        catchError(error => {
          console.error('Get permissions error:', error);
          return throwError(() => error);
        })
      );
  }

  getPermissionById(id: string): Observable<ApiResponse<{ permission: Permission }>> {
    return this.http.get<ApiResponse<{ permission: Permission }>>(`${this.apiUrl}/${id}`)
      .pipe(
        catchError(error => {
          console.error('Get permission by ID error:', error);
          return throwError(() => error);
        })
      );
  }

  createPermission(permissionData: CreatePermissionRequest): Observable<ApiResponse<{ permission: Permission }>> {
    return this.http.post<ApiResponse<{ permission: Permission }>>(this.apiUrl, permissionData)
      .pipe(
        catchError(error => {
          console.error('Create permission error:', error);
          return throwError(() => error);
        })
      );
  }

  updatePermission(id: string, permissionData: UpdatePermissionRequest): Observable<ApiResponse<{ permission: Permission }>> {
    return this.http.patch<ApiResponse<{ permission: Permission }>>(`${this.apiUrl}/${id}`, permissionData)
      .pipe(
        catchError(error => {
          console.error('Update permission error:', error);
          return throwError(() => error);
        })
      );
  }

  deletePermission(id: string): Observable<ApiResponse<any>> {
    return this.http.delete<ApiResponse<any>>(`${this.apiUrl}/${id}`)
      .pipe(
        catchError(error => {
          console.error('Delete permission error:', error);
          return throwError(() => error);
        })
      );
  }

  togglePermissionStatus(id: string, isActive: boolean): Observable<ApiResponse<{ permission: Permission }>> {
    return this.http.patch<ApiResponse<{ permission: Permission }>>(`${this.apiUrl}/${id}/status`, { isActive })
      .pipe(
        catchError(error => {
          console.error('Toggle permission status error:', error);
          return throwError(() => error);
        })
      );
  }

  getAvailableResources(): Observable<ApiResponse<PermissionResourcesResponse>> {
    return this.http.get<ApiResponse<PermissionResourcesResponse>>(`${this.apiUrl}/meta/resources`)
      .pipe(
        catchError(error => {
          console.error('Get available resources error:', error);
          return throwError(() => error);
        })
      );
  }

  getAvailableActions(): Observable<ApiResponse<PermissionActionsResponse>> {
    return this.http.get<ApiResponse<PermissionActionsResponse>>(`${this.apiUrl}/meta/actions`)
      .pipe(
        catchError(error => {
          console.error('Get available actions error:', error);
          return throwError(() => error);
        })
      );
  }

  getPermissionCategories(): Observable<ApiResponse<PermissionCategoriesResponse>> {
    return this.http.get<ApiResponse<PermissionCategoriesResponse>>(`${this.apiUrl}/meta/categories`)
      .pipe(
        catchError(error => {
          console.error('Get permission categories error:', error);
          return throwError(() => error);
        })
      );
  }

  getPermissionsByResource(resource: string): Observable<ApiResponse<{ permissions: Permission[] }>> {
    return this.http.get<ApiResponse<{ permissions: Permission[] }>>(`${this.apiUrl}/resource/${resource}`)
      .pipe(
        catchError(error => {
          console.error('Get permissions by resource error:', error);
          return throwError(() => error);
        })
      );
  }
}