import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, throwError, tap } from 'rxjs';
import { environment } from '../../../environments/environment.development';
import { 
  User, 
  UserFilters, 
  CreateUserRequest, 
  UpdateUserRequest,
  UserPermission,
  UserSecurityProfile,
  PaginatedResponse,
  ApiResponse
} from '../models';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = `${environment.apiBase}/users`;

  constructor(private http: HttpClient, private authService: AuthService) {}

  getUsers(filters: UserFilters = {}): Observable<PaginatedResponse<{ users: User[] }>> {
    const params: any = {};
    Object.keys(filters).forEach(key => {
      const value = (filters as any)[key];
      if (value !== undefined && value !== null) {
        params[key] = String(value);
      }
    });
    
    return this.http.get<PaginatedResponse<{ users: User[] }>>(this.apiUrl, { params })
      .pipe(
        catchError(error => {
          console.error('Get users error:', error);
          return throwError(() => error);
        })
      );
  }

  getUserById(id: string): Observable<ApiResponse<{ user: User }>> {
    return this.http.get<ApiResponse<{ user: User }>>(`${this.apiUrl}/${id}`);
  }

  getUserPermissions(id: string): Observable<ApiResponse<{ permissions: UserPermission[] }>> {
    return this.http.get<ApiResponse<{ permissions: UserPermission[] }>>(`${this.apiUrl}/${id}/permissions`)
      .pipe(
        catchError(error => {
          console.error('Get user permissions error:', error);
          return throwError(() => error);
        })
      );
  }

  createUser(userData: CreateUserRequest): Observable<ApiResponse<{ user: User }>> {
    // Client-side validation - backend ile uyumlu
    if (userData.password && typeof userData.password === 'string') {
      const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;
      
      if (!strongPasswordRegex.test(userData.password)) {
        return throwError(() => ({
          error: {
            message: 'Şifre en az 8 karakter, büyük/küçük harf, rakam ve özel karakter içermelidir'
          }
        }));
      }
    }
    
    return this.http.post<ApiResponse<{ user: User }>>(this.apiUrl, userData)
      .pipe(
        catchError(error => {
          console.error('Create user error:', error);
          return throwError(() => error);
        })
      );
  }

  updateUser(id: string, userData: UpdateUserRequest): Observable<ApiResponse<{ user: User }>> {
    return this.http.patch<ApiResponse<{ user: User }>>(`${this.apiUrl}/${id}`, userData).pipe(
      tap((response) => {
        const currentUser = this.authService.user;
        if (currentUser && (currentUser._id === id || (currentUser as any).id === id)) {
          const updatedUser = response?.data?.user || (response as any)?.user || userData;
          // Local state'i kritik alanları koruyarak güncelle
          this.authService.updateUserInObservable(updatedUser as any);

          // DEFAULT/HYBRID'de tam ve normalize izin/rolleri tazele
          if (!this.authService.isSsoSessionActive) {
            this.authService.me(true).subscribe({ next: () => {}, error: () => {} });
          }
        }
      })
    );
  }

  deleteUser(id: string): Observable<ApiResponse<any>> {
    return this.http.delete<ApiResponse<any>>(`${this.apiUrl}/${id}`);
  }

  toggleUserStatus(id: string, isActive: boolean): Observable<ApiResponse<{ user: User }>> {
    return this.http.patch<ApiResponse<{ user: User }>>(`${this.apiUrl}/${id}/status`, { isActive })
      .pipe(
        catchError(error => {
          console.error('Toggle user status error:', error);
          return throwError(() => error);
        })
      );
  }

  assignRoles(userId: string, roleIds: string[]) {
    return this.http.put<ApiResponse<any>>(`${this.apiUrl}/${userId}/roles`, { roles: roleIds });
  }

  assignPermissions(id: string, permissions: { permission: string; granted: boolean }[]): Observable<ApiResponse<{ user: User }>> {
    return this.http.patch<ApiResponse<{ user: User }>>(`${this.apiUrl}/${id}/permissions`, { permissions });
  }

  resetPassword(userId: string, newPassword: string) {
    // users.js -> router.patch('/:id/reset-password', ...)
    return this.http.patch<ApiResponse<true>>(
      `${this.apiUrl}/${userId}/reset-password`,
      { newPassword },
      { withCredentials: true } // SSO oturumunda session cookie'yi gönder
    );
  }

  unlockUser(id: string): Observable<ApiResponse<any>> {
    return this.http.patch<ApiResponse<any>>(`${this.apiUrl}/${id}/unlock`, {})
      .pipe(
        catchError(error => {
          console.error('Unlock user error:', error);
          return throwError(() => error);
        })
      );
  }

  getUserSecurityProfile(id: string): Observable<ApiResponse<{ securityProfile: UserSecurityProfile }>> {
    return this.http.get<ApiResponse<{ securityProfile: UserSecurityProfile }>>(`${this.apiUrl}/${id}/security-profile`)
      .pipe(
        catchError(error => {
          console.error('Get user security profile error:', error);
          return throwError(() => error);
        })
      );
  }
}