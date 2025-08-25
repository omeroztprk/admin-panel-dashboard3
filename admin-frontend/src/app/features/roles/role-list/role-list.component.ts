import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { RoleService } from '../../../core/services/role.service';
import { AuthService } from '../../../core/services/auth.service';
import { Role, RoleFilters } from '../../../core/models';

@Component({
  selector: 'app-role-list',
  templateUrl: './role-list.component.html',
  styleUrls: ['./role-list.component.scss']
})
export class RoleListComponent implements OnInit {
  roles: Role[] = [];
  loading = false;
  error = '';
  
  // Math helper
  Math = Math;
  
  // Pagination
  currentPage = 1;
  totalPages = 0;
  totalItems = 0;
  itemsPerPage = 10;
  
  // Filters
  filters: RoleFilters = {
    page: 1,
    limit: 10,
    sort: 'priority',
    includePermissions: false
  };
  
  // Search
  searchTerm = '';
  selectedStatus = '';

  // Permissions
  canCreate = false;
  canUpdate = false;
  canDelete = false;
  canManage = false;

  constructor(
    private roleService: RoleService,
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit() {
    this.checkPermissions();
    this.loadRoles();
  }

  private checkPermissions() {
    this.canCreate = this.authService.hasPermission('role:create');
    this.canUpdate = this.authService.hasPermission('role:update');
    this.canDelete = this.authService.hasPermission('role:delete');
    this.canManage = this.authService.hasPermission('role:manage');
  }

  loadRoles() {
    this.loading = true;
    this.error = '';
    
    this.roleService.getRoles(this.filters).subscribe({
      next: (response) => {
        this.roles = response.data?.roles || [];
        this.currentPage = response.pagination?.currentPage || 1;
        this.totalPages = response.pagination?.totalPages || 0;
        this.totalItems = response.pagination?.totalItems || 0;
        this.itemsPerPage = response.pagination?.itemsPerPage || 10;
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'Roller yüklenirken hata oluştu';
        this.loading = false;
        
        // 401 hatası alıyorsak ve SSO/HYBRID tokensız modda isek login'e yönlendir
        if (error.status === 401 && !this.authService.isDefaultSessionActive) {
          this.authService.hardLogout();
          this.router.navigate(['/login']);
        }
      }
    });
  }

  private buildFiltersFromQuery(): RoleFilters {
    const filters: RoleFilters = {
      page: this.currentPage,
      limit: this.itemsPerPage,
      sort: this.filters.sort || 'priority',
      includePermissions: false
    };

    if (this.searchTerm?.trim()) {
      filters.search = this.searchTerm.trim();
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
    this.loadRoles();
  }

  onPageChange(page: number) {
    this.filters = { ...this.filters, page };
    this.currentPage = page;
    this.loadRoles();
  }

  onSort(sort: string) {
    // Mevcut sıralama ile aynı ise ters çevir
    let newSort = sort;
    if (this.filters.sort === sort) {
      newSort = `-${sort}`;
    } else if (this.filters.sort === `-${sort}`) {
      newSort = sort;
    }
    
    this.filters = { ...this.filters, sort: newSort, page: 1 };
    this.currentPage = 1;
    this.loadRoles();
  }

  createRole() {
    if (!this.canCreate) return;
    this.router.navigate(['/roles/new']);
  }

  viewRole(role: Role) {
    this.router.navigate(['/roles', role._id]);
  }

  editRole(role: Role) {
    if (!this.canUpdate) return;
    this.router.navigate(['/roles', role._id, 'edit']);
  }

  toggleRoleStatus(role: Role) {
    if (!this.canManage || role.isSystem) return;
    
    // Backend'e toggle isteği gönder
    this.roleService.toggleRoleStatus(role._id, !role.isActive).subscribe({
      next: () => {
        this.loadRoles();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Durum değiştirilirken hata oluştu';
      }
    });
  }

  deleteRole(role: Role) {
    if (!this.canDelete || role.isSystem) return;
    
    if (confirm(`${role.displayName || role.name} rolünü silmek istediğinizden emin misiniz?`)) {
      this.roleService.deleteRole(role._id).subscribe({
        next: () => {
          this.loadRoles();
        },
        error: (error) => {
          this.error = error?.error?.message || 'Rol silinirken hata oluştu';
        }
      });
    }
  }

  getRoleStatus(role: Role): string {
    return role.isActive ? 'Aktif' : 'Pasif';
  }

  getStatusClass(role: Role): string {
    return role.isActive ? 'active' : 'inactive';
  }

  getRoleType(role: Role): string {
    return role.isSystem ? 'Sistem Rolü' : 'Özel Rol';
  }

  getRoleTypeClass(role: Role): string {
    return role.isSystem ? 'system' : 'custom';
  }

  clearFilters() {
    this.searchTerm = '';
    this.selectedStatus = '';
    this.currentPage = 1;
    this.filters = {
      page: 1,
      limit: 10,
      sort: 'priority',
      includePermissions: false
    };
    this.loadRoles();
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
}