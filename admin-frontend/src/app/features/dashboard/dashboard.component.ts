import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../core/services/auth.service';
import { environment } from '../../../environments/environment.development';
import { take } from 'rxjs/operators';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  user: any;
  isSSO = environment.authMode === 'SSO';

  constructor(private auth: AuthService) { }

  ngOnInit(): void {
    this.auth.user$.subscribe(u => { this.user = u; });

    if (!this.auth.user) {
      this.auth.me().pipe(take(1)).subscribe({ next: () => {}, error: () => {} });
    }
  }

  get userRoles(): string {
    if (!this.user?.roles || this.user.roles.length === 0) return '';
    return this.user.roles.map((r: any) => r.displayName || r.name).join(', ');
  }
  
  get isDefaultSessionActive(): boolean {
    return this.auth.isDefaultSessionActive;
  }

  getUserInitials(): string {
    if (!this.user) return '';
    const first = this.user.firstName || '';
    const last = this.user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }
}
