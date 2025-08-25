import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of, throwError, Subject } from 'rxjs';
import { catchError, map, tap, switchMap, shareReplay, finalize, takeUntil } from 'rxjs/operators';
import { environment } from '../../../environments/environment.development';
import { 
  AuthUser, 
  LoginResponse, 
  TokenPair, 
  LoginDecision,
  UserPermission,
  User,
  ApiResponse
} from '../models';

interface ApiMeResponse {
  success: boolean;
  message: string;
  data: { user: AuthUser };
}

@Injectable({ providedIn: 'root' })
export class AuthService implements OnDestroy {
  private api = environment.apiBase;
  private _user$ = new BehaviorSubject<AuthUser | null>(this.readUser());
  user$ = this._user$.asObservable();
  private _lastLoginEmail: string | null = null;
  private _userPermissions: string[] = [];
  private meInFlight$?: Observable<AuthUser | null>;
  private destroyed$ = new Subject<void>();

  constructor(private http: HttpClient) { 
    const user = this.readUser();
    if (user?.permissions) {
      this._userPermissions = this.extractPermissionNames(user.permissions);
    }
  }

  private readUser(): AuthUser | null {
    const raw = localStorage.getItem('ap.user');
    try { return raw ? JSON.parse(raw) as AuthUser : null; } catch { return null; }
  }
  
  private writeUser(u: AuthUser | null) {
    if (!u) {
      localStorage.removeItem('ap.user');
      this._userPermissions = [];
    } else {
      localStorage.setItem('ap.user', JSON.stringify(u));
      this._userPermissions = this.extractPermissionNames(u.permissions || []);
    }
    this._user$.next(u);
  }

  private extractPermissionNames(permissions: UserPermission[]): string[] {
    if (!permissions || permissions.length === 0) return [];
    
    return permissions.map(p => {
      if (p && typeof p === 'object' && p.permission) {
        const perm = p.permission;
        return perm.name || `${perm.resource}:${perm.action}`;
      }
      if (p && typeof p === 'object' && p.name) {
        return p.name || `${p.resource}:${p.action}`;
      }
      return null;
    }).filter(Boolean) as string[];
  }

  get accessToken(): string | null { return localStorage.getItem('ap.at'); }
  get refreshToken(): string | null { return localStorage.getItem('ap.rt'); }
  
  private setTokens(tp: TokenPair) {
    if (tp.accessToken) localStorage.setItem('ap.at', tp.accessToken);
    if (tp.refreshToken) localStorage.setItem('ap.rt', tp.refreshToken);
  }
  
  private clearTokens() {
    localStorage.removeItem('ap.at');
    localStorage.removeItem('ap.rt');
  }

  get isAuthenticated(): boolean {
    const mode = environment.authMode;
    if (mode === 'DEFAULT') return !!this.accessToken;
    if (mode === 'SSO') return !!this._user$.value;
    return !!this.accessToken || !!this._user$.value;
  }

  get user(): AuthUser | null {
    return this._user$.value;
  }

  get userPermissions(): string[] {
    return this._userPermissions;
  }

  hasPermission(required: string): boolean {
    return this.checkPermission(this._userPermissions, required);
  }

  hasAnyPermission(requiredPermissions: string[]): boolean {
    return requiredPermissions?.some(perm => this.hasPermission(perm));
  }

  private checkPermission(userPermissions: string[], required: string): boolean {
    if (!userPermissions || !required) return false;

    if (userPermissions.includes(required)) return true;

    if (userPermissions.includes('*:*')) return true;

    const [resource, action] = required.split(':');
    if (!resource || !action) return false;

    if (userPermissions.includes(`${resource}:*`)) return true;

    if (userPermissions.includes(`*:${action}`)) return true;

    if (userPermissions.includes(`${resource}:manage`)) {
      const managedActions = ['create', 'read', 'update', 'delete'];
      if (managedActions.includes(action)) {
        return true;
      }
    }

    return false;
  }

  get lastLoginEmail(): string | null { return this._lastLoginEmail; }
  set lastLoginEmail(v: string | null) {
    this._lastLoginEmail = v;
    if (v) sessionStorage.setItem('ap.lastEmail', v);
    else sessionStorage.removeItem('ap.lastEmail');
  }

  register(payload: { firstName: string; lastName: string; email: string; password: string; profile?: { language?: string } }) {
    return this.http.post<{ success: boolean; message: string; data: { user: User } }>(`${this.api}/auth/register`, payload);
  }

  login(email: string, password: string): Observable<LoginDecision> {
    const mode = environment.authMode;
    if (mode === 'SSO') {
      window.location.href = environment.sso.loginUrl;
      return of<LoginDecision>({ requiresTfa: false });
    }

    this.lastLoginEmail = email;
    return this.http.post<{ success: boolean; message: string; data: LoginResponse }>(
      `${this.api}/auth/login`, { email, password }, { observe: 'response' }
    ).pipe(
      switchMap((resp) => {
        const body = resp.body?.data as LoginResponse;
        if (resp.status === 202 || (body as any)?.requiresTfa) {
          return of<LoginDecision>({ requiresTfa: true, email: (body as any).email });
        }
        const ok = body as { user: User; accessToken: string; refreshToken: string };
        this.setTokens({ accessToken: ok.accessToken, refreshToken: ok.refreshToken });
        this.writeUser({ ...(ok.user || {}), authMethod: 'jwt' });
        this.lastLoginEmail = null;

        return this.me().pipe(
          map(() => ({ requiresTfa: false } as LoginDecision))
        );
      }),
      catchError(error => {
        // İyileştirme: Daha spesifik error handling
        let errorMessage = 'Giriş başarısız';
        
        if (error.status === 423) {
          const retryAfter = error?.headers?.get?.('Retry-After');
          if (retryAfter) {
            const seconds = parseInt(retryAfter);
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = seconds % 60;
            errorMessage = `Hesap kilitlendi. ${minutes} dakika ${remainingSeconds} saniye sonra tekrar deneyin.`;
          } else {
            errorMessage = 'Hesap geçici olarak kilitlendi.';
          }
        } else if (error.status === 401) {
          errorMessage = 'Email veya şifre hatalı';
        } else if (error.status === 404) {
          errorMessage = 'Kullanıcı bulunamadı';
        } else if (error.status === 400) {
          errorMessage = error?.error?.message || 'Geçersiz giriş bilgileri';
        } else {
          errorMessage = error?.error?.message || error?.error?.data?.message || 'Giriş başarısız';
        }
        
        return throwError(() => ({ ...error, error: { ...error.error, message: errorMessage } }));
      })
    );
  }

  ssoLogin() {
    window.location.href = environment.sso.loginUrl;
  }

  verifyTfa(code: string, email?: string) {
    if (environment.authMode === 'SSO') {
      return throwError(() => new Error('SSO modunda TFA bu uygulamada devre dışıdır'));
    }
    const e = email || this.lastLoginEmail || sessionStorage.getItem('ap.lastEmail') || '';
    return this.http.post<{ success: boolean; message: string; data: { user: User; accessToken: string; refreshToken: string } }>(
      `${this.api}/auth/verify-tfa`, { email: e, tfaCode: code }
    ).pipe(
      switchMap(res => {
        const d = res.data;
        // Tokenları kaydet
        this.setTokens({ accessToken: d.accessToken, refreshToken: d.refreshToken });

        // TFA akışında eksik izinlerle state yazmayalım; direkt normalize kullanıcıyı çekelim
        this.lastLoginEmail = null;
        sessionStorage.removeItem('ap.lastEmail');

        // Flatten edilmiş permissions için fresh me()
        return this.me(true).pipe(
          // Çağıran tarafın beklediği response yapısını koru
          map(() => res)
        );
      })
    );
  }

  refresh(): Observable<TokenPair> {
    if (environment.authMode === 'SSO') {
      return throwError(() => new Error('SSO modunda refresh token kullanılmaz'));
    }
    const rt = this.refreshToken;
    if (!rt) return throwError(() => new Error('No refresh token'));
    return this.http.post<{ success: boolean; message: string; data: TokenPair }>(`${this.api}/auth/refresh-token`, { refreshToken: rt })
      .pipe(
        map(res => res.data),
        tap(tp => this.setTokens(tp))
      );
  }

  me(forceRefresh: boolean = false) {
    if (forceRefresh) this.meInFlight$ = undefined;
    if (this.meInFlight$ && !forceRefresh) return this.meInFlight$;

    const mode = environment.authMode;
    const useJwt = mode === 'DEFAULT' || (mode === 'HYBRID' && !!this.accessToken);
    const url = useJwt ? `${this.api}/auth/me` : environment.sso.meUrl;

    const req$ = this.http.get<ApiMeResponse | any>(url, { withCredentials: !useJwt }).pipe(
      takeUntil(this.destroyed$),
      map((res) => {
        let user: User | null = null;
        if (useJwt && res?.data?.user) {
          user = { ...res.data.user, authMethod: 'jwt' };
        } else if (!useJwt && res) {
          user = { ...res, authMethod: 'sso' };
        }

        // SSO: kısa süreli stale override koruması
        if (user && (user as any).authMethod === 'sso') {
          const lockUntil = Number(localStorage.getItem('ap.sso.lockUntil') || 0);
          const now = Date.now();
          if (lockUntil && now < lockUntil) {
            const cur: any = this._user$.value;
            if (cur) {
              user = {
                ...user,
                // Profil alanlarını local state'teki en güncel değerlerle koru
                firstName: cur.firstName ?? (user as any).firstName,
                lastName: cur.lastName ?? (user as any).lastName,
                email: cur.email ?? (user as any).email,
                profile: { ...(user as any).profile, ...(cur as any).profile },
                // Rol ve izinleri de koru (rol değişimi Users ekranında zaten state'e yazılıyor)
                roles: cur.roles ?? (user as any).roles,
                permissions: cur.permissions ?? (user as any).permissions
              } as any;
            }
          } else if (lockUntil) {
            localStorage.removeItem('ap.sso.lockUntil');
          }
        }

        if (user) {
          if ((user as any).permissions && Array.isArray((user as any).permissions)) {
            this._userPermissions = this.extractPermissionNames((user as any).permissions);
          }
          this.writeUser(user as any);
        }
        return user;
      }),
      shareReplay(1),
      finalize(() => { this.meInFlight$ = undefined; })
    );

    this.meInFlight$ = req$;
    return req$;
  }

  ngOnDestroy() {
    this.destroyed$.next();
    this.destroyed$.complete();
  }
  
  logout() {
    const mode = environment.authMode;

    if (mode !== 'DEFAULT' && !this.accessToken) {
      this.hardLogout();
      try {
        window.location.replace(environment.sso.logoutUrl);
      } catch {}
      setTimeout(() => {
        if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
          window.location.replace('/login');
        }
      }, 1000);
      return of(true);
    }

    if (mode === 'SSO') {
      this.hardLogout();
      try {
        window.location.replace(environment.sso.logoutUrl);
      } catch {}
      setTimeout(() => {
        if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
          window.location.replace('/login');
        }
      }, 1000);
      return of(true);
    }

    const rt = this.refreshToken;
    if (!rt) {
      this.hardLogout();
      return of(true);
    }
    return this.http.post<{ success: boolean; message: string }>(`${this.api}/auth/logout`, { refreshToken: rt }).pipe(
      tap(() => this.hardLogout()),
      catchError(() => { this.hardLogout(); return of(true); }),
      map(() => true)
    );
  }

  get isSsoSessionActive(): boolean {
    const u: any = this._user$.value;
    return !!(u && (u.authMethod === 'sso' || u?.sso?.provider === 'keycloak'));
  }

  getSessions(): Observable<ApiResponse<{ sessions: any[] }>> {
    const isSso = this.isSsoSessionActive;
    const mode = environment.authMode;    
    const headers: any = {};
    
    // Refresh token'ı header'a ekle (DEFAULT/HYBRID modunda)
    if (!isSso && mode !== 'SSO') {
      const rt = this.refreshToken;
      if (rt) headers['X-Refresh-Token'] = rt;
    }
    
    return this.http.get<ApiResponse<{ sessions: any[] }>>(
      `${this.api}/auth/sessions`, 
      { 
        withCredentials: true, // Tüm modlarda cookie gönder (hybrid için önemli)
        headers 
      }
    ).pipe(
      catchError(err => {
        console.error('getSessions error:', err); // Bu error log'u koru
        return throwError(() => err);
      })
    );
  }

  revokeSession(id: string): Observable<ApiResponse<{ revoked: boolean }>> {
    return this.http.delete<ApiResponse<{ revoked: boolean }>>(
      `${this.api}/auth/sessions/${id}`, 
      { withCredentials: true } // Tüm modlarda cookie gönder
    );
  }

  logoutAll(): Observable<ApiResponse<{ success: boolean }>> {
    const withCreds = this.isSsoSessionActive;
    return this.http.post<ApiResponse<{ success: boolean }>>(
      `${this.api}/auth/logout-all`, 
      {}, 
      { withCredentials: withCreds }
    ).pipe(tap(() => this.hardLogout()));
  }

  hardLogout() {
    this.clearTokens();
    this.writeUser(null);
    this.lastLoginEmail = null;
    sessionStorage.removeItem('ap.lastEmail');
    
    this._user$.next(null);
    this._userPermissions = [];
    
    sessionStorage.clear();
    
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('ap.') || key.startsWith('admin-panel')) {
        localStorage.removeItem(key);
      }
    });
  }

  get isDefaultSessionActive(): boolean {
    const user = this._user$.value;
    if (!user) return !!this.accessToken;
    if (user.authMethod) return user.authMethod === 'jwt';
    return environment.authMode === 'DEFAULT' || !!this.accessToken;
  }

  // SSO: kendi profilini /users/:id üzerinden günceller (backend Keycloak Admin API'ye proxy'ler)
  updateProfile(payload: Partial<AuthUser>) {
    const isSso = this.isSsoSessionActive;

    const preserveCriticalFields = (currentUser: AuthUser, updated: any): AuthUser => {
      const merged = {
        ...currentUser,
        ...updated,
        profile: {
          ...(currentUser as any).profile,
          ...(updated?.profile || {})
        }
      } as AuthUser;

      const updatedHasRoles = Array.isArray((updated as any)?.roles) && (updated as any).roles.length > 0;
      const updatedHasPerms = Array.isArray((updated as any)?.permissions) && (updated as any).permissions.length > 0;

      merged.roles = updatedHasRoles ? (updated as any).roles : currentUser.roles;
      merged.permissions = updatedHasPerms ? (updated as any).permissions : currentUser.permissions;

      (merged as any).authMethod = (currentUser as any).authMethod;
      (merged as any).id = (currentUser as any).id || (currentUser as any)._id;

      return merged;
    };

    if (isSso) {
      const u: any = this._user$.value;
      const userId = u?._id || u?.id;

      return this.http.patch(`${this.api}/users/${userId}`, payload, { withCredentials: true }).pipe(
        tap((res: any) => {
          const updated = res?.data?.user || res?.user || payload;
          const currentUser = this._user$.value;
          if (currentUser) {
            const mergedUser = preserveCriticalFields(currentUser, updated);
            this.writeUser(mergedUser);
          }
        })
        // ÖNEMLİ: SSO için me(true) çağrısını kaldırdık, stale profile ile overwrite olmasın
      );
    }

    // DEFAULT/HYBRID (JWT) flow
    return this.http.patch(`${this.api}/auth/profile`, payload).pipe(
      switchMap((res: any) => {
        const updated = res?.data?.user || res?.user || payload;
        const currentUser = this._user$.value;
        if (currentUser) {
          const mergedUser = preserveCriticalFields(currentUser, updated);
          this.writeUser(mergedUser);
        }
        // DEFAULT'ta tam ve normalize izin/roller için fresh çek
        return this.me(true);
      })
    );
  }

  changePassword(currentPassword: string, newPassword: string) {
    if (!this.isDefaultSessionActive) {
      return throwError(() => new Error('SSO modunda şifre değiştirme devre dışıdır'));
    }
    return this.http.patch<{ success: boolean; message: string }>(
      `${this.api}/auth/change-password`, { currentPassword, newPassword }
    );
  }

  // Helper method: External service'lerden user observable'ını güncelleme
  updateUserInObservable(partial: Partial<AuthUser>) {
    const current: any = this._user$.value;
    if (!current) {
      this.writeUser(partial as AuthUser);
      return;
    }

    const merged: any = {
      ...current,
      ...partial,
      profile: { ...(current.profile || {}), ...(partial as any)?.profile || {} }
    };

    // roles/permissions alanları yok veya boş geldiyse mevcutları koru
    if (!('roles' in (partial as any)) || (Array.isArray((partial as any).roles) && (partial as any).roles.length === 0)) {
      merged.roles = current.roles;
    }
    if (!('permissions' in (partial as any)) || (Array.isArray((partial as any).permissions) && (partial as any).permissions.length === 0)) {
      merged.permissions = current.permissions;
    }

    // authMethod/id/sso gibi kritik alanları koru
    merged.authMethod = current.authMethod;
    merged.id = current.id || current._id;
    if (current.sso) merged.sso = current.sso;

    // SSO ve aynı kullanıcı ise: kısa süreli stale override kilidi koy (5 dk)
    const isSame = (current._id && merged._id && current._id === merged._id) || (current.id && merged.id && current.id === merged.id);
    if (this.isSsoSessionActive && isSame) {
      const until = Date.now() + 5 * 60 * 1000;
      localStorage.setItem('ap.sso.lockUntil', String(until));
    }

    this.writeUser(merged as AuthUser);
  }
}
