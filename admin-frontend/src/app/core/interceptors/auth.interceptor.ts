import { Injectable } from '@angular/core';
import {
  HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse
} from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { catchError, filter, switchMap, take } from 'rxjs/operators';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment.development';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private refreshing = false;
  private refreshSubj = new BehaviorSubject<boolean>(false);

  constructor(private auth: AuthService, private router: Router) { }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const mode = environment.authMode;
    const at = this.auth.accessToken;

    // Hybrid mod için withCredentials her zaman true olmalı
    const needsCookies = mode === 'HYBRID' || mode === 'SSO';

    let cloned = req.clone({
      setHeaders: { 'Accept-Language': 'tr' },
      withCredentials: needsCookies
    });

    const isAuthPath = cloned.url.includes('/auth/login')
      || cloned.url.includes('/auth/register')
      || cloned.url.includes('/auth/verify-tfa')
      || cloned.url.includes('/auth/refresh-token')
      || cloned.url.includes('/auth/keycloak');

    // Eksik olan değişkeni tanımlama
    const isLogoutPath = cloned.url.includes('/auth/logout')
      || cloned.url.includes('/auth/logout-all')
      || cloned.url.includes('/auth/keycloak/logout');

    // Token varsa ve auth path değilse ekle
    if (at && !isAuthPath && mode !== 'SSO') {
      cloned = cloned.clone({ setHeaders: { Authorization: `Bearer ${at}` } });
    }

    return next.handle(cloned).pipe(
      catchError((err: HttpErrorResponse) => {
        if ((mode === 'SSO' || (mode === 'HYBRID' && !at)) && err.status === 401 && !isAuthPath) {
          this.auth.hardLogout();
          this.router.navigate(['/login']);
          return throwError(() => err);
        }

        // DEFAULT modda veya HYBRID+token'da refresh deneme
        if (err.status !== 401 || isAuthPath || isLogoutPath || !at || mode === 'SSO') {
          return throwError(() => err);
        }

        if (!this.refreshing) {
          this.refreshing = true;
          this.refreshSubj.next(false);

          return this.auth.refresh().pipe(
            switchMap(tp => {
              this.refreshing = false;
              this.refreshSubj.next(true);
              const retry = req.clone({
                setHeaders: { Authorization: `Bearer ${tp.accessToken}` },
                withCredentials: mode !== 'DEFAULT'
              });
              return next.handle(retry);
            }),
            catchError(e => {
              this.refreshing = false;
              this.auth.hardLogout();
              this.router.navigate(['/login']);
              return throwError(() => e);
            })
          );
        } else {
          return this.refreshSubj.pipe(
            filter(v => v === true),
            take(1),
            switchMap(() => {
              const at2 = this.auth.accessToken;
              const retry = at2
                ? req.clone({
                  setHeaders: { Authorization: `Bearer ${at2}` },
                  withCredentials: mode !== 'DEFAULT'
                })
                : req.clone({ withCredentials: mode !== 'DEFAULT' });
              return next.handle(retry);
            })
          );
        }
      })
    );
  }
}
