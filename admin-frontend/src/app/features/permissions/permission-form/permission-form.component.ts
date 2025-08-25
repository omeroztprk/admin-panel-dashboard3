import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { PermissionService } from '../../../core/services/permission.service';
import { AuthService } from '../../../core/services/auth.service';
import { Permission, CreatePermissionRequest, UpdatePermissionRequest } from '../../../core/models';

@Component({
  selector: 'app-permission-form',
  templateUrl: './permission-form.component.html',
  styleUrls: ['./permission-form.component.scss']
})
export class PermissionFormComponent implements OnInit {
  permissionForm: FormGroup;
  resources: string[] = [];
  actions: string[] = [];
  categories: string[] = [];
  loading = false;
  saving = false;
  error = '';
  isEditMode = false;
  permissionId = '';
  permission: Permission | null = null;

  canCreate = false;
  canUpdate = false;

  constructor(
    private fb: FormBuilder,
    private route: ActivatedRoute,
    private router: Router,
    private permissionService: PermissionService,
    private authService: AuthService
  ) {
    this.permissionForm = this.createForm();
  }

  ngOnInit() {
    this.permissionId = this.route.snapshot.params['id'];
    this.isEditMode = !!this.permissionId;
    
    this.checkPermissions();
    this.loadMetadata();
    
    if (this.isEditMode) {
      this.loadPermission();
    } else {
      this.permissionForm = this.createForm();
    }
  }

  private createForm(): FormGroup {
    return this.fb.group({
      name: ['', [Validators.maxLength(100)]],
      displayName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(100)]],
      description: ['', [Validators.maxLength(500)]],
      resource: ['', [Validators.required]],
      action: ['', [Validators.required]],
      category: [''],
      isActive: [true]
    });
  }

  private checkPermissions() {
    this.canCreate = this.authService.hasPermission('permission:create');
    this.canUpdate = this.authService.hasPermission('permission:update');
  }

  private loadMetadata() {
    // Resources
    this.permissionService.getAvailableResources().subscribe({
      next: (response) => {
        this.resources = response.data?.resources || [];
      },
      error: (error) => {
        console.warn('Resources yüklenirken hata:', error);
      }
    });

    // Actions
    this.permissionService.getAvailableActions().subscribe({
      next: (response) => {
        this.actions = response.data?.actions || [];
      },
      error: (error) => {
        console.warn('Actions yüklenirken hata:', error);
      }
    });

    // Categories
    this.permissionService.getPermissionCategories().subscribe({
      next: (response) => {
        this.categories = response.data?.categories || [];
      },
      error: (error) => {
        console.warn('Categories yüklenirken hata:', error);
      }
    });
  }

  private loadPermission() {
    this.loading = true;
    this.error = '';
    
    this.permissionService.getPermissionById(this.permissionId).subscribe({
      next: (response) => {
        this.permission = response.data?.permission || null;
        if (this.permission) {
          this.permissionForm = this.createForm();
          this.populateForm(this.permission);
        }
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'İzin bilgileri yüklenirken hata oluştu';
        this.loading = false;
      }
    });
  }

  private populateForm(permission: Permission) {
    this.permissionForm.patchValue({
      name: permission.name,
      displayName: permission.displayName || permission.name,
      description: permission.description || '',
      resource: permission.resource,
      action: permission.action,
      category: permission.category || '',
      isActive: permission.isActive !== false
    });
  }

  onResourceActionChange() {
    const resource = this.permissionForm.get('resource')?.value;
    const action = this.permissionForm.get('action')?.value;
    
    // Auto-generate name if both resource and action are selected
    if (resource && action && !this.permissionForm.get('name')?.value) {
      const generatedName = `${resource}:${action}`;
      this.permissionForm.get('name')?.setValue(generatedName);
    }
  }

  onSubmit() {
    if (this.permissionForm.invalid) {
      this.markFormGroupTouched();
      this.error = 'Lütfen tüm gerekli alanları doğru şekilde doldurun';
      return;
    }

    // Permission check
    if (this.isEditMode && !this.canUpdate) {
      this.error = 'Bu izni güncelleme yetkiniz bulunmuyor';
      return;
    }
    
    if (!this.isEditMode && !this.canCreate) {
      this.error = 'İzin oluşturma yetkiniz bulunmuyor';
      return;
    }

    // System permission kontrolü
    if (this.isEditMode && this.permission?.isSystem) {
      this.error = 'Sistem izni düzenlenemez';
      return;
    }

    this.saving = true;
    this.error = '';

    const formData = { ...this.permissionForm.value };
    
    // Name alanı boşsa resource:action formatında oluştur
    if (!formData.name?.trim()) {
      formData.name = `${formData.resource}:${formData.action}`;
    }

    // Tip güvenliği için explicit casting
    const operation = this.isEditMode 
      ? this.permissionService.updatePermission(this.permissionId, formData as UpdatePermissionRequest)
      : this.permissionService.createPermission(formData as CreatePermissionRequest);

    operation.subscribe({
      next: () => {
        this.saving = false;
        this.router.navigate(['/permissions']);
      },
      error: (error) => {
        this.saving = false;
        const errorMsg = error?.error?.message || error?.message || 'Bir hata oluştu';
        this.error = `İzin ${this.isEditMode ? 'güncellenirken' : 'oluşturulurken'} hata: ${errorMsg}`;
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
    
    markControlsRecursively(this.permissionForm);
  }

  isFieldInvalid(fieldName: string): boolean {
    const field = this.permissionForm.get(fieldName);
    return !!(field && field.invalid && (field.dirty || field.touched));
  }

  getFieldError(fieldName: string): string {
    const field = this.permissionForm.get(fieldName);
    if (!field || !field.errors) return '';

    const errors = field.errors;
    if (errors['required']) return `${this.getFieldDisplayName(fieldName)} zorunludur`;
    if (errors['minlength']) return `En az ${errors['minlength'].requiredLength} karakter olmalıdır`;
    if (errors['maxlength']) return `En fazla ${errors['maxlength'].requiredLength} karakter olmalıdır`;
    if (errors['pattern']) {
      return 'Geçersiz format';
    }
    
    return 'Geçersiz değer';
  }

  private getFieldDisplayName(fieldName: string): string {
    const fieldMap: { [key: string]: string } = {
      'name': 'İzin Adı',
      'displayName': 'Görünen Ad',
      'description': 'Açıklama',
      'resource': 'Kaynak',
      'action': 'İşlem',
      'category': 'Kategori'
    };
    
    return fieldMap[fieldName] || fieldName;
  }

  cancel() {
    if (this.isEditMode) {
      this.router.navigate(['/permissions', this.permissionId]);
    } else {
      this.router.navigate(['/permissions']);
    }
  }

  formatCategory(category: string): string {
    if (!category) return 'Diğer';
    return category
      .split('_')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  getPreviewPermissionName(): string {
    const resource = this.permissionForm.get('resource')?.value;
    const action = this.permissionForm.get('action')?.value;
    const name = this.permissionForm.get('name')?.value;
    
    if (name?.trim()) {
      return name.trim();
    }
    
    if (resource && action) {
      return `${resource}:${action}`;
    }
    
    return 'Önizleme mevcut değil';
  }
}