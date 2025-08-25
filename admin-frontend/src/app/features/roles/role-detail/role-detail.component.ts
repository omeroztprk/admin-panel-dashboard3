import { Component, OnInit, HostListener } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RoleService } from '../../../core/services/role.service';
import { UserService } from '../../../core/services/user.service';
import { AuthService } from '../../../core/services/auth.service';
import { Role, Permission, RoleUser } from '../../../core/models';


@Component({
  selector: 'app-role-detail',
  templateUrl: './role-detail.component.html',
  styleUrls: ['./role-detail.component.scss']
})
export class RoleDetailComponent implements OnInit {
  role: Role | null = null;
  roleUsers: RoleUser[] = [];
  loading = false;
  usersLoading = false;
  error = '';
  roleId = '';
  showDropdown = false;

  // Math helper ekle
  Math = Math;

  // Users pagination
  usersCurrentPage = 1;
  usersTotalPages = 0;
  usersTotalItems = 0;
  usersItemsPerPage = 10;

  // Permissions
  canUpdate = false;
  canDelete = false;
  canManage = false;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private roleService: RoleService,
    private userService: UserService,
    private authService: AuthService
  ) {}

  ngOnInit() {
    this.roleId = this.route.snapshot.params['id'];
    this.checkPermissions();
    this.loadRole();
    this.loadRoleUsers();
  }

  private checkPermissions() {
    this.canUpdate = this.authService.hasPermission('role:update');
    this.canDelete = this.authService.hasPermission('role:delete');
    this.canManage = this.authService.hasPermission('role:manage');
  }

  loadRole() {
    this.loading = true;
    this.error = '';
    
    this.roleService.getRoleById(this.roleId, true).subscribe({
      next: (response) => {
        this.role = response.data?.role || null;
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'Rol bilgileri yüklenirken hata oluştu';
        this.loading = false;
      }
    });
  }

  loadRoleUsers(page: number = 1) {
    this.usersLoading = true;
    
    this.roleService.getRoleUsers(this.roleId, { page, limit: this.usersItemsPerPage }).subscribe({
      next: (response) => {
        this.roleUsers = response.data?.users || [];
        this.usersCurrentPage = response.pagination?.currentPage || 1;
        this.usersTotalPages = response.pagination?.totalPages || 0;
        this.usersTotalItems = response.pagination?.totalItems || 0;
        this.usersItemsPerPage = response.pagination?.itemsPerPage || 10;
        this.usersLoading = false;
      },
      error: (error) => {
        console.error('Failed to load role users:', error);
        this.roleUsers = [];
        this.usersLoading = false;
        
        // 401 hatası için redirect
        if (error.status === 401 && !this.authService.isDefaultSessionActive) {
          this.authService.hardLogout();
          this.router.navigate(['/login']);
        } else {
          console.warn('Rol kullanıcıları yüklenirken hata oluştu:', error?.error?.message || error?.message);
        }
      }
    });
  }

  editRole() {
    if (!this.canUpdate || !this.role || this.role.isSystem) return;
    this.router.navigate(['/roles', this.roleId, 'edit']);
  }

  toggleRoleStatus() {
    if (!this.canManage || !this.role || this.role.isSystem) return;
    
    this.roleService.toggleRoleStatus(this.roleId, !this.role.isActive).subscribe({
      next: () => {
        this.loadRole();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Durum değiştirilirken hata oluştu';
      }
    });
  }

  deleteRole() {
    if (!this.canDelete || !this.role || this.role.isSystem) return;
    
    const roleName = this.role.displayName || this.role.name;
    if (confirm(`${roleName} rolünü silmek istediğinizden emin misiniz?`)) {
      this.roleService.deleteRole(this.roleId).subscribe({
        next: () => {
          this.router.navigate(['/roles']);
        },
        error: (error) => {
          this.error = error?.error?.message || 'Rol silinirken hata oluştu';
        }
      });
    }
  }

  getPermissionsByCategory() {
    if (!this.role?.permissions || this.role.permissions.length === 0) return [];
    
    const categories: { [key: string]: Permission[] } = {};
    
    // Permission array tipini kontrol et
    (this.role.permissions as Permission[]).forEach((permission: Permission) => {
      const category = permission.category || 'Diğer';
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(permission);
    });
    
    // Kategorileri alfabetik sırala, Diğer'i en sona koy
    const sortedCategories = Object.keys(categories).sort((a, b) => {
      if (a === 'Diğer') return 1;
      if (b === 'Diğer') return -1;
      return a.localeCompare(b, 'tr');
    });
    
    return sortedCategories.map(category => ({
      category,
      permissions: categories[category].sort((a, b) => {
        const nameA = a?.displayName || a?.name || '';
        const nameB = b?.displayName || b?.name || '';
        return nameA.localeCompare(nameB, 'tr');
      })
    }));
  }

  assignPermissions() {
    if (!this.canManage || !this.role) return;
    // Role edit sayfasına yönlendir
    this.router.navigate(['/roles', this.roleId, 'edit']);
  }

  removePermissions() {
    if (!this.canManage || !this.role) return;
    // Role edit sayfasına yönlendir  
    this.router.navigate(['/roles', this.roleId, 'edit']);
  }

  formatCategory(category: string): string {
    if (!category) return '';
    if (category === 'Diğer') return category;
    return category
      .split('_')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  onUsersPageChange(page: number) {
    this.loadRoleUsers(page);
  }

  viewUser(user: RoleUser) {
    this.router.navigate(['/users', user._id]);
  }

  getUserInitials(user: RoleUser): string {
    const first = user.firstName || '';
    const last = user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }

  getUserStatus(user: RoleUser): string {
    if (user.lockoutUntil && new Date(user.lockoutUntil) > new Date()) {
      return 'Kilitli';
    }
    return user.isActive ? 'Aktif' : 'Pasif';
  }

  getUserStatusClass(user: RoleUser): string {
    if (user.lockoutUntil && new Date(user.lockoutUntil) > new Date()) {
      return 'locked';
    }
    return user.isActive ? 'active' : 'inactive';
  }

  trackByUserId(index: number, user: RoleUser): string {
    return user._id || user.id || index.toString();
  }

  toggleDropdown() {
    this.showDropdown = !this.showDropdown;
  }

  closeDropdown() {
    this.showDropdown = false;
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: Event) {
    const target = event.target as HTMLElement;
    const dropdown = document.querySelector('.dropdown');
    if (dropdown && !dropdown.contains(target)) {
      this.showDropdown = false;
    }
  }

  getRoleStatus(): string {
    return this.role?.isActive ? 'Aktif' : 'Pasif';
  }

  getStatusClass(): string {
    return this.role?.isActive ? 'active' : 'inactive';
  }

  getRoleType(): string {
    return this.role?.isSystem ? 'Sistem Rolü' : 'Özel Rol';
  }

  getRoleTypeClass(): string {
    return this.role?.isSystem ? 'system' : 'custom';
  }

  getMetadataInfo(): { label: string; value: string; class?: string }[] {
    if (!this.role) return [];

    const info: { label: string; value: string; class?: string }[] = [];

    if (this.role.createdAt) {
      info.push({
        label: 'Oluşturulma',
        value: new Date(this.role.createdAt).toLocaleDateString('tr-TR', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      });
    }

    if (this.role.updatedAt) {
      info.push({
        label: 'Son Güncelleme',
        value: new Date(this.role.updatedAt).toLocaleDateString('tr-TR', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      });
    }

    return info;
  }

  getUsersPageNumbers(): number[] {
    const pages: number[] = [];
    const maxVisible = 5;
    
    let start = Math.max(1, this.usersCurrentPage - Math.floor(maxVisible / 2));
    let end = Math.min(this.usersTotalPages, start + maxVisible - 1);
    
    if (end - start + 1 < maxVisible) {
      start = Math.max(1, end - maxVisible + 1);
    }
    
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    
    return pages;
  }

  goBack() {
    this.router.navigate(['/roles']);
  }

  trackByPermissionId(index: number, permission: Permission): string {
    return permission._id || index.toString();
  }
}