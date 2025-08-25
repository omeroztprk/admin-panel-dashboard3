import { Injectable } from '@angular/core';
import { CanActivate, Router, UrlTree, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { AuthService } from '../services/auth.service';
import { environment } from '../../../environments/environment.development';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(private auth: AuthService, private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean | UrlTree | Observable<boolean | UrlTree> {
    const mode = environment.authMode;

    // Token veya SSO user varsa geç
    if (this.auth.isAuthenticated) return true;

    // HYBRID/SSO: backend'e sor
    if (mode !== 'DEFAULT') {
      return this.auth.me().pipe(
        map(() => true),
        catchError(() => of(this.router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } })))
      );
    }

    // DEFAULT
    return this.router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
  }
}
