import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { RoleService } from '../../../core/services/role.service';
import { AuthService } from '../../../core/services/auth.service';
import { Role, Permission, CreateRoleRequest, UpdateRoleRequest } from '../../../core/models';
import { finalize } from 'rxjs/operators';

@Component({
  selector: 'app-role-form',
  templateUrl: './role-form.component.html',
  styleUrls: ['./role-form.component.scss']
})
export class RoleFormComponent implements OnInit {
  roleForm: FormGroup;
  permissions: Permission[] = [];
  loading = false;
  saving = false;
  error = '';
  isEditMode = false;
  roleId = '';
  role: Role | null = null;

  canCreate = false;
  canUpdate = false;

  constructor(
    private fb: FormBuilder,
    private route: ActivatedRoute,
    private router: Router,
    private roleService: RoleService
  ) {
    this.roleForm = this.createForm();
  }

  ngOnInit() {
    this.roleId = this.route.snapshot.params['id'];
    this.isEditMode = !!this.roleId;

    this.checkPermissions();
    this.loadPermissions();

    if (this.isEditMode) {
      this.loadRole(this.roleId);
    } else {
      this.roleForm = this.createForm();
    }
  }

  private createForm(): FormGroup {
    return this.fb.group({
      name: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50), Validators.pattern(/^[a-zA-Z0-9_-]+$/)]],
      displayName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(100)]],
      description: ['', [Validators.maxLength(500)]],
      priority: [0, [Validators.min(0), Validators.max(100)]],
      permissions: [[]],
      isActive: [true]
    });
  }

  private checkPermissions() {
    this.canCreate = true;
    this.canUpdate = true;
  }

  loadPermissions() {
    this.roleService.getAllPermissions().subscribe({
      next: (response) => {
        this.permissions = response.data?.permissions || [];
      },
      error: (error) => {
        console.warn('Permissions yüklenirken hata:', error);
        this.permissions = [];
      }
    });
  }

  loadRole(id: string) {
    this.loading = true;
    this.error = '';

    this.roleService.getRoleById(id, true)
      .pipe(finalize(() => (this.loading = false)))
      .subscribe({
        next: (response) => {
          const role = response?.data?.role;
          if (!role) {
            this.error = 'Rol bulunamadı';
            return;
          }

          this.role = role;

          const permissionIds =
            Array.isArray(role.permissions)
              ? (role.permissions as (Permission | string)[])
                .map(p => (typeof p === 'string' ? p : p?._id))
                .filter((v): v is string => !!v)
              : [];

          this.roleForm.patchValue({
            name: role.name || '',
            displayName: role.displayName || '',
            description: role.description || '',
            priority: typeof role.priority === 'number' ? role.priority : 0,
            isActive: !!role.isActive,
            permissions: permissionIds
          });
        },
        error: (err) => {
          this.error = err?.error?.message || 'Rol yüklenirken hata oluştu';
        }
      });
  }

  getPermissionId(p: Permission | string): string {
    return typeof p === 'string' ? p : (p?._id || p?.name || '');
  }

  isPermissionSelected(p: Permission): boolean {
    const id = this.getPermissionId(p);
    const selected: string[] = this.roleForm.get('permissions')?.value || [];
    return !!id && selected.includes(id);
  }

  private togglePermission(permissionId: string, checked?: boolean) {
    const ctrl = this.roleForm.get('permissions');
    const current: string[] = ctrl?.value || [];
    const exists = current.includes(permissionId);

    let next: string[];
    if (checked === true || (!exists && checked === undefined)) {
      next = exists ? current : [...current, permissionId];
    } else if (checked === false || (exists && checked === undefined)) {
      next = current.filter(id => id !== permissionId);
    } else {
      next = current;
    }

    ctrl?.setValue(next);
    ctrl?.markAsDirty();
    ctrl?.updateValueAndValidity({ emitEvent: true });
  }

  onPermissionChange(event: any, permissionId: string) {
    this.togglePermission(permissionId, !!event.target.checked);
  }

  onPermissionLabelClick(event: MouseEvent, permissionId: string) {
    event.preventDefault();
    event.stopPropagation();
    this.togglePermission(permissionId);
  }

  onSubmit() {
    if (this.roleForm.invalid) {
      this.markFormGroupTouched();
      this.error = 'Lütfen tüm gerekli alanları doğru şekilde doldurun';
      return;
    }

    if (this.isEditMode && !this.canUpdate) {
      this.error = 'Bu rolü güncelleme yetkiniz bulunmuyor';
      return;
    }

    if (!this.isEditMode && !this.canCreate) {
      this.error = 'Rol oluşturma yetkiniz bulunmuyor';
      return;
    }

    if (this.isEditMode && this.role?.isSystem) {
      this.error = 'Sistem rolü düzenlenemez';
      return;
    }

    this.saving = true;
    this.error = '';

    const formData: CreateRoleRequest | UpdateRoleRequest = { ...this.roleForm.value };

    const operation = this.isEditMode
      ? this.roleService.updateRole(this.roleId, formData as UpdateRoleRequest)
      : this.roleService.createRole(formData as CreateRoleRequest);

    operation.pipe(
      finalize(() => this.saving = false)
    ).subscribe({
      next: () => {
        this.router.navigate(['/roles']);
      },
      error: (error) => {
        const errorMsg = error?.error?.message || error?.message || 'Bir hata oluştu';
        this.error = `Rol ${this.isEditMode ? 'güncellenirken' : 'oluşturulurken'} hata: ${errorMsg}`;
      }
    });
  }

  private markFormGroupTouched() {
    const markControlsRecursively = (formGroup: any) => {
      Object.keys(formGroup.controls).forEach(key => {
        const control = formGroup.get(key);
        control?.markAsTouched();

        if (control?.controls) {
          markControlsRecursively(control);
        }
      });
    };

    markControlsRecursively(this.roleForm);
  }

  isFieldInvalid(fieldName: string): boolean {
    const field = this.roleForm.get(fieldName);
    return !!(field && field.invalid && (field.dirty || field.touched));
  }

  getFieldError(fieldName: string): string {
    const field = this.roleForm.get(fieldName);
    if (!field || !field.errors) return '';

    const errors = field.errors;
    if (errors['required']) return `${this.getFieldDisplayName(fieldName)} zorunludur`;
    if (errors['minlength']) return `En az ${errors['minlength'].requiredLength} karakter olmalıdır`;
    if (errors['maxlength']) return `En fazla ${errors['maxlength'].requiredLength} karakter olmalıdır`;
    if (errors['min']) return `Minimum değer ${errors['min'].min} olmalıdır`;
    if (errors['max']) return `Maksimum değer ${errors['max'].max} olmalıdır`;
    if (errors['pattern']) {
      if (fieldName === 'name') {
        return 'Sadece harf, rakam, tire (-) ve alt çizgi (_) kullanabilirsiniz';
      }
      return 'Geçersiz format';
    }

    return 'Geçersiz değer';
  }

  private getFieldDisplayName(fieldName: string): string {
    const fieldMap: { [key: string]: string } = {
      'name': 'Rol Adı',
      'displayName': 'Görünen Ad',
      'description': 'Açıklama',
      'priority': 'Öncelik'
    };

    return fieldMap[fieldName] || fieldName;
  }

  cancel() {
    if (this.isEditMode) {
      this.router.navigate(['/roles', this.roleId]);
    } else {
      this.router.navigate(['/roles']);
    }
  }

  getPermissionsByCategory() {
    if (!this.permissions || this.permissions.length === 0) return [];

    const categories: { [key: string]: Permission[] } = {};

    this.permissions.forEach(permission => {
      const category = permission.category || 'Diğer';
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(permission);
    });

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

  formatCategory(category: string): string {
    if (!category) return '';
    if (category === 'Diğer') return category;
    return category
      .split('_')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  trackByPermissionId(index: number, permission: Permission): string {
    return permission._id;
  }
}