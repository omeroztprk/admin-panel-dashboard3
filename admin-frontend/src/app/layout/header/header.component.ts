import { Component, OnInit, Output, EventEmitter, HostListener } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { AuthUser } from '../../core/models';
import { environment } from '../../../environments/environment.development';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent implements OnInit {
  @Output() sidebarToggle = new EventEmitter<void>();
  
  user: AuthUser | null = null;
  loggingOut = false;
  userMenuOpen = false;
  notificationsOpen = false;
  
  // Configuration
  showSearch = false;
  showNotifications = false;
  searchQuery = '';
  
  // Mock notifications
  notifications: any[] = [];
  notificationCount = 0;

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit() {
    this.authService.user$.subscribe(user => {
      this.user = user;
    });
  }

  toggleSidebar() {
    this.sidebarToggle.emit();
  }

  toggleUserMenu() {
    this.userMenuOpen = !this.userMenuOpen;
    this.notificationsOpen = false;
  }

  toggleNotifications() {
    this.notificationsOpen = !this.notificationsOpen;
    this.userMenuOpen = false;
  }

  closeUserMenu() {
    this.userMenuOpen = false;
  }

  closeNotifications() {
    this.notificationsOpen = false;
  }

  logout() {
    if (this.loggingOut) return;
    this.loggingOut = true;
    
    this.authService.logout().subscribe({
      next: () => {
        this.loggingOut = false;
        // Moddan bağımsız: her zaman login'e yönlendir (IdP redirect geldiyse bunu override edecektir)
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
    return this.user.roles.map((r: any) => r.displayName || r.name).slice(0, 2).join(', ');
  }

  markAllAsRead() {
    this.notifications.forEach(n => n.read = true);
    this.notificationCount = 0;
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: Event) {
    const target = event.target as HTMLElement;
    
    if (!target.closest('.user-dropdown')) {
      this.userMenuOpen = false;
    }
    if (!target.closest('.notification-dropdown')) {
      this.notificationsOpen = false;
    }
  }
}