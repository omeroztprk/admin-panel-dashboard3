import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { Observable, of } from 'rxjs';
import { UserService } from '../../../core/services/user.service';
import { RoleService } from '../../../core/services/role.service';
import { AuthService } from '../../../core/services/auth.service';
import { User, Role, CreateUserRequest, UpdateUserRequest } from '../../../core/models';
import { finalize, switchMap, catchError, tap } from 'rxjs/operators';

@Component({
  selector: 'app-user-form',
  templateUrl: './user-form.component.html',
  styleUrls: ['./user-form.component.scss']
})
export class UserFormComponent implements OnInit {
  userForm: FormGroup;
  roles: Role[] = [];
  loading = false;
  saving = false;
  error = '';
  isEditMode = false;
  userId = '';
  user: User | null = null;

  canCreate = false;
  canUpdate = false;

  // Backend ile aynı regex
  private readonly strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;

  // Keycloak kullanıcıyı tespit et
  isSsoUser = false;

  constructor(
    private fb: FormBuilder,
    private route: ActivatedRoute,
    private router: Router,
    private userService: UserService,
    private roleService: RoleService,
    private authService: AuthService
  ) {
    this.userForm = this.createForm();
  }

  ngOnInit() {
    this.userId = this.route.snapshot.params['id'];
    this.isEditMode = !!this.userId;

    // Formu, mod belirlendikten sonra oluştur (password validator doğru olsun)
    this.userForm = this.createForm();

    this.checkPermissions();
    this.loadRoles();

    if (this.isEditMode) {
      this.loadUser(this.userId);
    }
  }

  private createForm(): FormGroup {
    return this.fb.group({
      firstName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
      lastName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
      email: ['', [Validators.required, Validators.email]],
      password: ['', this.getPasswordValidators()],
      roles: [[]],
      profile: this.fb.group({
        language: ['tr'],
        phone: ['', [Validators.pattern(/^[\+]?[0-9\s\-\(\)]{10,}$/)]],
        timezone: ['Europe/Istanbul']
      })
    });
  }

  private getPasswordValidators() {
    const baseValidators = [Validators.minLength(8), Validators.pattern(this.strongPasswordRegex)];
    return this.isEditMode ? baseValidators : [Validators.required, ...baseValidators];
  }

  private checkPermissions() {
    this.canCreate = this.authService.hasPermission('user:create');
    this.canUpdate = this.authService.hasPermission('user:update');
  }

  loadRoles() {
    this.roleService.getRoles({ includePermissions: false, isActive: true, limit: 100 }).subscribe({
      next: (response) => {
        this.roles = response.data?.roles || [];
      },
      error: (error) => {
        console.error('Failed to load roles:', error);
        this.error = 'Roller yüklenirken hata oluştu';
      }
    });
  }

  loadUser(id: string) {
    this.loading = true;
    this.error = '';

    this.userService.getUserById(id)
      .pipe(finalize(() => { this.loading = false; }))
      .subscribe({
        next: (response) => {
          // Hem { data: { user } } hem de { user } formatlarını destekle
          const user = response?.data?.user || (response as any)?.user;
          if (!user) {
            this.error = 'Kullanıcı bulunamadı';
            return;
          }

          this.user = user;

          // Keycloak kullanıcıyı tespit et
          this.isSsoUser = (user as any)?.sso?.provider === 'keycloak' || user.authMethod === 'sso';
          if (this.isSsoUser) {
            // SSO kullanıcıda şifre yerelden yönetilmez
            this.userForm.get('password')?.disable({ onlySelf: true });
          }

          this.userForm.patchValue({
            firstName: user.firstName || '',
            lastName: user.lastName || '',
            email: user.email || '',
            roles: Array.isArray(user.roles)
              ? user.roles
                  .map((r: any) => typeof r === 'string' ? r : r?._id)
                  .filter(Boolean)
              : [],
            profile: {
              phone: user.profile?.phone || '',
              language: user.profile?.language || 'tr',
              timezone: user.profile?.timezone || 'Europe/Istanbul'
            }
          });

          // Edit modunda şifre zorunlu olmadığından alanı boş bırak
          this.userForm.get('password')?.setValue('');
        },
        error: (error) => {
          this.error = error?.error?.message || 'Kullanıcı yüklenirken hata oluştu';
        }
      });
  }

  onRoleChange(event: any, roleId: string) {
    const currentRoles = this.userForm.get('roles')?.value || [];
    let updatedRoles: string[];
    
    if (event.target.checked) {
      if (!currentRoles.includes(roleId)) {
        updatedRoles = [...currentRoles, roleId];
      } else {
        updatedRoles = currentRoles;
      }
    } else {
      updatedRoles = currentRoles.filter((id: string) => id !== roleId);
    }
    
    this.userForm.get('roles')?.setValue(updatedRoles);
    this.userForm.get('roles')?.markAsDirty();
  }

  onSubmit() {
    if (this.userForm.invalid) {
      this.markFormGroupTouched();
      this.error = 'Lütfen tüm gerekli alanları doğru şekilde doldurun';
      return;
    }

    // Permission check
    if (this.isEditMode && !this.canUpdate) {
      this.error = 'Bu kullanıcıyı güncelleme yetkiniz bulunmuyor';
      return;
    }
    
    if (!this.isEditMode && !this.canCreate) {
      this.error = 'Kullanıcı oluşturma yetkiniz bulunmuyor';
      return;
    }

    this.saving = true;
    this.error = '';

    // getRawValue: disabled alanları da içersin (SSO'da password disable)
    const formValue: any = { ...this.userForm.getRawValue() };

    // Edit modunda boş şifre alanını kaldır
    if (this.isEditMode && (!formValue.password || !String(formValue.password).trim())) {
      delete formValue.password;
    }

    // Boş profile alanlarını temizle
    if (formValue.profile) {
      const profileKeys = Object.keys(formValue.profile);
      profileKeys.forEach(key => {
        const value = formValue.profile[key];
        if (!value || (typeof value === 'string' && !value.trim())) {
          delete formValue.profile[key];
        }
      });
      
      if (Object.keys(formValue.profile).length === 0) {
        delete formValue.profile;
      }
    }

    // SSO kullanıcı: önce profil, sonra rol
    if (this.isEditMode && this.isSsoUser) {
      const formValue: any = { ...this.userForm.getRawValue() };
      const roleIds: string[] = Array.isArray(formValue.roles) ? formValue.roles : [];
      const { roles, password, ...profilePayload } = formValue;

      // Rol değişimi var mı kontrol et
      const currentRoleIds = Array.isArray(this.user?.roles)
        ? (this.user!.roles as any[]).map(r => typeof r === 'string' ? r : r?._id).filter(Boolean)
        : [];
      const sameRoles =
        roleIds.length === currentRoleIds.length &&
        roleIds.every(id => currentRoleIds.includes(id));

      this.userService.updateUser(this.userId, profilePayload as UpdateUserRequest)
        .pipe(
          switchMap(() => (sameRoles || roleIds.length === 0)
            ? of(null)
            : this.userService.assignRoles(this.userId, roleIds).pipe(
                tap(() => {
                  const currentUser = this.authService.user;
                  if (currentUser && (currentUser._id === this.userId || (currentUser as any).id === this.userId)) {
                    // Rol değişimi sonrası self ise: kullanıcı + permissions tazele
                    this.userService.getUserById(this.userId).subscribe({
                      next: (res) => {
                        const updatedUser = (res as any)?.data?.user || (res as any)?.user;
                        if (updatedUser) {
                          // Permissions'ı ayrı uçtan çek ve birlikte yaz
                          this.userService.getUserPermissions(this.userId).subscribe({
                            next: (permRes) => {
                              const permissions = permRes?.data?.permissions || [];
                              this.authService.updateUserInObservable({ ...updatedUser, permissions } as any);
                            },
                            error: () => {
                              // permissions alınamazsa en azından profil/roller güncellensin
                              this.authService.updateUserInObservable(updatedUser as any);
                            }
                          });
                        }
                      }
                    });
                  }
                })
              )
          ),
          // Rol atama hata verirse kullanıcıya anlamlı mesaj göster ama profil güncellemesini iptal etme
          catchError((err) => {
            const msg = err?.error?.message || err?.message || 'Rol atama sırasında hata oluştu';
            this.error = `Rol güncellenemedi: ${msg}`;
            return of(null);
          }),
          finalize(() => { this.saving = false; })
        )
        .subscribe({
          next: () => this.router.navigate(['/users']),
          error: (error) => {
            const errorMsg = error?.error?.message || error?.message || 'Bir hata oluştu';
            this.error = `Kullanıcı güncellenirken hata: ${errorMsg}`;
          }
        });
      return;
    }

    // DEFAULT / HYBRID (JWT) kullanıcı akışı
    const operation = this.isEditMode 
      ? this.userService.updateUser(this.userId, formValue as UpdateUserRequest)
      : this.userService.createUser(formValue as CreateUserRequest);

    operation.subscribe({
      next: () => {
        this.saving = false;
        this.router.navigate(['/users']);
      },
      error: (error) => {
        this.saving = false;
        const errorMsg = error?.error?.message || error?.message || 'Bir hata oluştu';
        this.error = `Kullanıcı ${this.isEditMode ? 'güncellenirken' : 'oluşturulurken'} hata: ${errorMsg}`;
      }
    });
  }

  private markFormGroupTouched() {
    const markControlsRecursively = (formGroup: any) => {
      Object.keys(formGroup.controls).forEach(key => {
        const control = formGroup.get(key);
        control?.markAsTouched();
        
        // FormGroup veya FormArray kontrollerini kontrol et
        if (control?.controls) {
          markControlsRecursively(control);
        }
      });
    };
    
    markControlsRecursively(this.userForm);
  }

  isFieldInvalid(fieldName: string, nestedField?: string): boolean {
    const field = nestedField 
      ? this.userForm.get(`${fieldName}.${nestedField}`)
      : this.userForm.get(fieldName);
    return !!(field && field.invalid && (field.dirty || field.touched));
  }

  getFieldError(fieldName: string, nestedField?: string): string {
    const field = nestedField 
      ? this.userForm.get(`${fieldName}.${nestedField}`)
      : this.userForm.get(fieldName);
      
    if (!field || !field.errors) return '';

    const errors = field.errors;
    if (errors['required']) return `${this.getFieldDisplayName(fieldName, nestedField)} zorunludur`;
    if (errors['email']) return 'Geçerli bir email adresi giriniz';
    if (errors['minlength']) return `En az ${errors['minlength'].requiredLength} karakter olmalıdır`;
    if (errors['maxlength']) return `En fazla ${errors['maxlength'].requiredLength} karakter olmalıdır`;
    if (errors['pattern']) {
      if (fieldName === 'profile' && nestedField === 'phone') {
        return 'Geçerli bir telefon numarası giriniz';
      }
      if (fieldName === 'password') {
        return 'Şifre en az 8 karakter, büyük/küçük harf, rakam ve özel karakter içermelidir';
      }
      return 'Geçersiz format';
    }
    
    return 'Geçersiz değer';
  }

  private getFieldDisplayName(fieldName: string, nestedField?: string): string {
    const fieldMap: { [key: string]: string } = {
      'firstName': 'Ad',
      'lastName': 'Soyad',
      'email': 'Email',
      'password': 'Şifre',
      'profile.language': 'Dil',
      'profile.phone': 'Telefon',
      'profile.timezone': 'Saat Dilimi'
    };
    
    const fullFieldName = nestedField ? `${fieldName}.${nestedField}` : fieldName;
    return fieldMap[fullFieldName] || fieldName;
  }

  cancel() {
    if (this.isEditMode) {
      this.router.navigate(['/users', this.userId]);
    } else {
      this.router.navigate(['/users']);
    }
  }

  trackByRoleId(index: number, role: Role): string {
    return role._id;
  }

  trackByUserId(index: number, user: User): string {
    return user._id;
  }
}