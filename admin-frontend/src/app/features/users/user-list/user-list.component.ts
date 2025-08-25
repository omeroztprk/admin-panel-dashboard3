import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { UserService } from '../../../core/services/user.service';
import { RoleService } from '../../../core/services/role.service';
import { PermissionService } from '../../../core/services/permission.service';
import { AuthService } from '../../../core/services/auth.service';
import { User, UserFilters, Role } from '../../../core/models';
import { environment } from '../../../../environments/environment.development';

@Component({
  selector: 'app-user-list',
  templateUrl: './user-list.component.html',
  styleUrls: ['./user-list.component.scss']
})
export class UserListComponent implements OnInit {
  users: User[] = [];
  roles: Role[] = [];
  loading = false;
  error = '';

  Math = Math;

  currentPage = 1;
  totalPages = 0;
  totalItems = 0;
  itemsPerPage = 10;

  filters: UserFilters = {
    page: 1,
    limit: 10,
    sort: '-createdAt'
  };

  searchTerm = '';
  selectedRole = '';
  selectedStatus = '';

  canCreate = false;
  canUpdate = false;
  canDelete = false;
  canManage = false;

  constructor(
    private userService: UserService,
    private roleService: RoleService,
    private permissionService: PermissionService,
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit() {
    this.checkPermissions();
    this.loadRoles();
    this.loadUsers();
  }

  private checkPermissions() {
    this.canCreate = this.authService.hasPermission('user:create');
    this.canUpdate = this.authService.hasPermission('user:update');
    this.canDelete = this.authService.hasPermission('user:delete');
    this.canManage = this.authService.hasPermission('user:manage');
  }

  loadRoles() {
    this.roleService.getRoles({ includePermissions: false, isActive: true, limit: 100 }).subscribe({
      next: (response) => {
        this.roles = response.data?.roles || [];
      },
      error: (error) => {
        console.error('Failed to load roles:', error);
        this.error = 'Roller yüklenirken hata oluştu';

        if (error.status === 401 && !this.authService.isDefaultSessionActive) {
          this.authService.hardLogout();
          this.router.navigate(['/login']);
        }
      }
    });
  }

  loadUsers() {
    this.loading = true;
    this.error = '';

    this.userService.getUsers(this.filters).subscribe({
      next: (response) => {
        this.users = response.data?.users || [];
        this.currentPage = response.pagination?.currentPage || 1;
        this.totalPages = response.pagination?.totalPages || 0;
        this.totalItems = response.pagination?.totalItems || 0;
        this.itemsPerPage = response.pagination?.itemsPerPage || 10;
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'Kullanıcılar yüklenirken hata oluştu';
        this.loading = false;

        if (error.status === 401 && !this.authService.isDefaultSessionActive) {
          this.authService.hardLogout();
          this.router.navigate(['/login']);
        }
      }
    });
  }

  private buildFiltersFromQuery(): UserFilters {
    const filters: UserFilters = {
      page: this.currentPage,
      limit: this.itemsPerPage,
      sort: this.filters.sort || '-createdAt'
    };

    if (this.searchTerm?.trim()) {
      filters.search = this.searchTerm.trim();
    }

    if (this.selectedRole) {
      filters.role = this.selectedRole;
    }

    if (this.selectedStatus !== '') {
      filters.isActive = this.selectedStatus === 'true';
    }

    return filters;
  }

  onSearch() {
    this.filters = this.buildFiltersFromQuery();
    this.filters.page = 1;
    this.currentPage = 1;
    this.loadUsers();
  }

  onPageChange(page: number) {
    this.filters = { ...this.filters, page };
    this.currentPage = page;
    this.loadUsers();
  }

  onSort(sort: string) {
    let newSort = sort;
    if (this.filters.sort === sort) {
      newSort = `-${sort}`;
    } else if (this.filters.sort === `-${sort}`) {
      newSort = sort;
    }

    this.filters = { ...this.filters, sort: newSort, page: 1 };
    this.currentPage = 1;
    this.loadUsers();
  }

  createUser() {
    if (!this.canCreate) return;
    this.router.navigate(['/users/new']);
  }

  viewUser(user: User) {
    this.router.navigate(['/users', user._id]);
  }

  editUser(user: User) {
    if (!this.canUpdate) return;
    this.router.navigate(['/users', user._id, 'edit']);
  }

  toggleUserStatus(user: User) {
    if (!this.canManage) return;

    this.userService.toggleUserStatus(user._id, !user.isActive).subscribe({
      next: () => {
        this.loadUsers();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Durum değiştirilirken hata oluştu';
      }
    });
  }

  deleteUser(user: User) {
    if (!this.canDelete) return;

    if (confirm(`${user.firstName} ${user.lastName} kullanıcısını silmek istediğinizden emin misiniz?`)) {
      this.userService.deleteUser(user._id).subscribe({
        next: () => {
          this.loadUsers();
        },
        error: (error) => {
          this.error = error?.error?.message || 'Kullanıcı silinirken hata oluştu';
        }
      });
    }
  }

  getUserRoles(user: User): string {
    if (!user.roles || user.roles.length === 0) return 'Rol atanmamış';

    return user.roles
      .map(role => {
        if (typeof role === 'string') return role;
        return role.displayName || role.name || '';
      })
      .filter(Boolean)
      .join(', ');
  }

  getUserInitials(user: User): string {
    const first = user.firstName || '';
    const last = user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }

  getUserStatus(user: User): string {
    if (user.lockoutUntil && new Date(user.lockoutUntil) > new Date()) {
      return 'Kilitli';
    }

    return user.isActive ? 'Aktif' : 'Pasif';
  }

  getStatusClass(user: User): string {
    if (user.lockoutUntil && new Date(user.lockoutUntil) > new Date()) {
      return 'locked';
    }

    return user.isActive ? 'active' : 'inactive';
  }

  clearFilters() {
    this.searchTerm = '';
    this.selectedRole = '';
    this.selectedStatus = '';
    this.currentPage = 1;
    this.filters = {
      page: 1,
      limit: 10,
      sort: '-createdAt'
    };
    this.loadUsers();
  }

  trackByUserId(index: number, user: User): string {
    return user._id || user.id || index.toString();
  }

  trackByRoleId(index: number, role: Role): string {
    return role._id || index.toString();
  }

  getPageNumbers(): number[] {
    const pages: number[] = [];
    const maxVisible = 5;

    let start = Math.max(1, this.currentPage - Math.floor(maxVisible / 2));
    let end = Math.min(this.totalPages, start + maxVisible - 1);

    if (end - start + 1 < maxVisible) {
      start = Math.max(1, end - maxVisible + 1);
    }

    for (let i = start; i <= end; i++) {
      pages.push(i);
    }

    return pages;
  }

  getRoleDisplayName(roles: any[]): string {
    if (!roles || !Array.isArray(roles) || roles.length === 0) {
      return 'Rol Atanmamış';
    }

    return roles
      .map((role: Role | string) => {
        if (typeof role === 'string') return role;
        if (typeof role === 'object' && role.displayName) {
          return role.displayName;
        }
        return role || 'Bilinmeyen Rol';
      })
      .join(', ');
  }
}