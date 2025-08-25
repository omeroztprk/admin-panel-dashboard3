import { Component, OnInit, HostListener } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { PermissionService } from '../../../core/services/permission.service';
import { AuthService } from '../../../core/services/auth.service';
import { Permission } from '../../../core/models';

@Component({
  selector: 'app-permission-detail',
  templateUrl: './permission-detail.component.html',
  styleUrls: ['./permission-detail.component.scss']
})
export class PermissionDetailComponent implements OnInit {
  permission: Permission | null = null;
  loading = false;
  error = '';
  permissionId = '';
  showDropdown = false;

  canUpdate = false;
  canDelete = false;
  canManage = false;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private permissionService: PermissionService,
    private authService: AuthService
  ) {}

  ngOnInit() {
    this.permissionId = this.route.snapshot.params['id'];
    this.checkPermissions();
    this.loadPermission();
  }

  private checkPermissions() {
    this.canUpdate = this.authService.hasPermission('permission:update');
    this.canDelete = this.authService.hasPermission('permission:delete');
    this.canManage = this.authService.hasPermission('permission:manage');
  }

  loadPermission() {
    this.loading = true;
    this.error = '';
    
    this.permissionService.getPermissionById(this.permissionId).subscribe({
      next: (response) => {
        this.permission = response.data?.permission || null;
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'İzin bilgileri yüklenirken hata oluştu';
        this.loading = false;
      }
    });
  }

  editPermission() {
    if (!this.canUpdate || !this.permission || this.permission.isSystem) return;
    this.router.navigate(['/permissions', this.permissionId, 'edit']);
  }

  togglePermissionStatus() {
    if (!this.canManage || !this.permission || this.permission.isSystem) return;
    
    this.permissionService.togglePermissionStatus(this.permissionId, !this.permission.isActive).subscribe({
      next: () => {
        this.loadPermission();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Durum değiştirilirken hata oluştu';
      }
    });
  }

  deletePermission() {
    if (!this.canDelete || !this.permission || this.permission.isSystem) return;
    
    const permissionName = this.permission.displayName || this.permission.name;
    if (confirm(`${permissionName} iznini silmek istediğinizden emin misiniz?`)) {
      this.permissionService.deletePermission(this.permissionId).subscribe({
        next: () => {
          this.router.navigate(['/permissions']);
        },
        error: (error) => {
          this.error = error?.error?.message || 'İzin silinirken hata oluştu';
        }
      });
    }
  }

  goBack() {
    this.router.navigate(['/permissions']);
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

  getPermissionStatus(): string {
    return this.permission?.isActive ? 'Aktif' : 'Pasif';
  }

  getStatusClass(): string {
    return this.permission?.isActive ? 'active' : 'inactive';
  }

  getPermissionType(): string {
    return this.permission?.isSystem ? 'Sistem İzni' : 'Özel İzin';
  }

  getPermissionTypeClass(): string {
    return this.permission?.isSystem ? 'system' : 'custom';
  }

  formatCategory(category: string): string {
    if (!category) return 'Diğer';
    return category
      .split('_')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  getMetadataInfo(): { label: string; value: string; class?: string }[] {
    if (!this.permission) return [];

    const info: { label: string; value: string; class?: string }[] = [];

    if (this.permission.createdAt) {
      info.push({
        label: 'Oluşturulma',
        value: new Date(this.permission.createdAt).toLocaleDateString('tr-TR', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      });
    }

    if (this.permission.updatedAt) {
      info.push({
        label: 'Son Güncelleme',
        value: new Date(this.permission.updatedAt).toLocaleDateString('tr-TR', {
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
}