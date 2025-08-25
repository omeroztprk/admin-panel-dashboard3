import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { AuthUser } from '../../core/models';
import { environment } from '../../../environments/environment.development';

@Component({
  selector: 'app-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrls: ['./sidebar.component.scss']
})
export class SidebarComponent implements OnInit {
  @Input() isOpen = false;
  @Input() isCollapsed = false;
  @Output() close = new EventEmitter<void>();
  @Output() toggleCollapse = new EventEmitter<void>();

  user: AuthUser | null = null;
  loggingOut = false;

  hasUserManagementAccess = false;
  showAccountSection = false;

  constructor(
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit() {
    this.authService.user$.subscribe(user => {
      this.user = user;
      this.checkPermissions();
      this.showAccountSection = !!user;
    });
  }

  private checkPermissions() {
    if (!this.user) {
      this.hasUserManagementAccess = false;
      return;
    }

    const userManagementPermissions = [
      'user:read', 'user:create', 'user:update', 'user:delete', 'user:manage',
      'role:read', 'role:create', 'role:update', 'role:delete', 'role:manage',
      'permission:read', 'permission:create', 'permission:update', 'permission:delete', 'permission:manage'
    ];

    this.hasUserManagementAccess = this.authService.hasAnyPermission(userManagementPermissions);
  }

  closeSidebar() {
    this.close.emit();
  }

  onToggleCollapse() {
    this.toggleCollapse.emit();
  }

  logout() {
    if (this.loggingOut) return;
    this.loggingOut = true;

    this.authService.logout().subscribe({
      next: () => {
        this.loggingOut = false;
        this.router.navigate(['/login']);
      },
      error: () => {
        this.loggingOut = false;
        this.authService.hardLogout();
        this.router.navigate(['/login']);
      }
    });
  }

  getUserInitials(): string {
    if (!this.user) return '';
    const first = this.user.firstName || '';
    const last = this.user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }

  getUserRoles(): string {
    if (!this.user?.roles || this.user.roles.length === 0) return '';
    return this.user.roles.map((r: any) => r.displayName || r.name).slice(0, 1).join(', ');
  }
}