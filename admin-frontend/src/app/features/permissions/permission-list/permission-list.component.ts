import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { PermissionService } from '../../../core/services/permission.service';
import { AuthService } from '../../../core/services/auth.service';
import { Permission, PermissionFilters } from '../../../core/models';

@Component({
  selector: 'app-permission-list',
  templateUrl: './permission-list.component.html',
  styleUrls: ['./permission-list.component.scss']
})
export class PermissionListComponent implements OnInit {
  permissions: Permission[] = [];
  resources: string[] = [];
  actions: string[] = [];
  categories: string[] = [];
  loading = false;
  error = '';

  Math = Math;

  currentPage = 1;
  totalPages = 0;
  totalItems = 0;
  itemsPerPage = 25;

  filters: PermissionFilters = {
    page: 1,
    limit: 25,
    sort: 'resource'
  };

  searchTerm = '';
  selectedResource = '';
  selectedAction = '';
  selectedCategory = '';
  selectedStatus = '';

  canCreate = false;
  canUpdate = false;
  canDelete = false;
  canManage = false;

  constructor(
    private permissionService: PermissionService,
    private authService: AuthService,
    private router: Router
  ) { }

  ngOnInit() {
    this.checkPermissions();
    this.loadMetadata();
    this.loadPermissions();
  }

  private checkPermissions() {
    this.canCreate = this.authService.hasPermission('permission:create');
    this.canUpdate = this.authService.hasPermission('permission:update');
    this.canDelete = this.authService.hasPermission('permission:delete');
    this.canManage = this.authService.hasPermission('permission:manage');
  }

  private loadMetadata() {
    this.permissionService.getAvailableResources().subscribe({
      next: (response) => {
        this.resources = response.data?.resources || [];
      },
      error: (error) => {
        console.warn('Resources yüklenirken hata:', error);
      }
    });

    this.permissionService.getAvailableActions().subscribe({
      next: (response) => {
        this.actions = response.data?.actions || [];
      },
      error: (error) => {
        console.warn('Actions yüklenirken hata:', error);
      }
    });

    this.permissionService.getPermissionCategories().subscribe({
      next: (response) => {
        this.categories = response.data?.categories || [];
      },
      error: (error) => {
        console.warn('Categories yüklenirken hata:', error);
      }
    });
  }

  loadPermissions() {
    this.loading = true;
    this.error = '';

    this.permissionService.getPermissions(this.filters).subscribe({
      next: (response) => {
        this.permissions = response.data?.permissions || [];
        this.currentPage = response.pagination?.currentPage || 1;
        this.totalPages = response.pagination?.totalPages || 0;
        this.totalItems = response.pagination?.totalItems || 0;
        this.itemsPerPage = response.pagination?.itemsPerPage || 25;
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'İzinler yüklenirken hata oluştu';
        this.loading = false;

        if (error.status === 401 && !this.authService.isDefaultSessionActive) {
          this.authService.hardLogout();
          this.router.navigate(['/login']);
        }
      }
    });
  }

  private buildFiltersFromQuery(): PermissionFilters {
    const filters: PermissionFilters = {
      page: this.currentPage,
      limit: this.itemsPerPage,
      sort: this.filters.sort || 'resource'
    };

    if (this.searchTerm?.trim()) {
      filters.search = this.searchTerm.trim();
    }

    if (this.selectedResource) {
      filters.resource = this.selectedResource;
    }

    if (this.selectedAction) {
      filters.action = this.selectedAction;
    }

    if (this.selectedCategory) {
      filters.category = this.selectedCategory;
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
    this.loadPermissions();
  }

  onPageChange(page: number) {
    this.filters = { ...this.filters, page };
    this.currentPage = page;
    this.loadPermissions();
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
    this.loadPermissions();
  }

  createPermission() {
    if (!this.canCreate) return;
    this.router.navigate(['/permissions/new']);
  }

  viewPermission(permission: Permission) {
    this.router.navigate(['/permissions', permission._id]);
  }

  editPermission(permission: Permission) {
    if (!this.canUpdate) return;
    this.router.navigate(['/permissions', permission._id, 'edit']);
  }

  togglePermissionStatus(permission: Permission) {
    if (!this.canManage || permission.isSystem) return;

    this.permissionService.togglePermissionStatus(permission._id, !permission.isActive).subscribe({
      next: () => {
        this.loadPermissions();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Durum değiştirilirken hata oluştu';
      }
    });
  }

  deletePermission(permission: Permission) {
    if (!this.canDelete || permission.isSystem) return;

    if (confirm(`${permission.displayName || permission.name} iznini silmek istediğinizden emin misiniz?`)) {
      this.permissionService.deletePermission(permission._id).subscribe({
        next: () => {
          this.loadPermissions();
        },
        error: (error) => {
          this.error = error?.error?.message || 'İzin silinirken hata oluştu';
        }
      });
    }
  }

  getPermissionStatus(permission: Permission): string {
    return permission.isActive ? 'Aktif' : 'Pasif';
  }

  getStatusClass(permission: Permission): string {
    return permission.isActive ? 'active' : 'inactive';
  }

  getPermissionType(permission: Permission): string {
    return permission.isSystem ? 'Sistem İzni' : 'Özel İzin';
  }

  getPermissionTypeClass(permission: Permission): string {
    return permission.isSystem ? 'system' : 'custom';
  }

  formatCategory(category: string): string {
    if (!category) return 'Diğer';
    return category
      .split('_')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  clearFilters() {
    this.searchTerm = '';
    this.selectedResource = '';
    this.selectedAction = '';
    this.selectedCategory = '';
    this.selectedStatus = '';
    this.currentPage = 1;
    this.filters = {
      page: 1,
      limit: 25,
      sort: 'resource'
    };
    this.loadPermissions();
  }

  trackByPermissionId(index: number, permission: Permission): string {
    return permission._id || index.toString();
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