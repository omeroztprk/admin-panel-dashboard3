import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { Observable, of } from 'rxjs';
import { map, catchError, take, switchMap } from 'rxjs/operators';
import { AuthService } from '../services/auth.service';

@Injectable({ providedIn: 'root' })
export class PermissionGuard implements CanActivate {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> {
    const requiredPermission = route.data['permission'];
    
    if (!requiredPermission) {
      return of(true);
    }

    return this.authService.user$.pipe(
      take(1),
      switchMap(user => {
        if (!user || (!user._id && !user.id)) {
          this.router.navigate(['/dashboard']);
          return of(false);
        }

        if (this.authService.hasPermission(requiredPermission)) {
          return of(true);
        }

        return this.authService.me().pipe(
          map(() => {
            const hasPermission = this.authService.hasPermission(requiredPermission);
            if (!hasPermission) {
              this.router.navigate(['/dashboard']);
              return false;
            }
            return true;
          }),
          catchError(() => {
            this.router.navigate(['/dashboard']);
            return of(false);
          })
        );
      })
    );
  }
}