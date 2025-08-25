import { Component, OnInit, HostListener } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { take } from 'rxjs/operators';
import { UserService } from '../../../core/services/user.service';
import { AuthService } from '../../../core/services/auth.service';
import { User } from '../../../core/models';

@Component({
  selector: 'app-user-detail',
  templateUrl: './user-detail.component.html',
  styleUrls: ['./user-detail.component.scss']
})
export class UserDetailComponent implements OnInit {
  user: User | null = null;
  userPermissions: any[] = [];
  loading = false;
  permissionsLoading = false;
  error = '';
  userId = '';
  showDropdown = false;

  // Permissions
  canUpdate = false;
  canDelete = false;
  canManage = false;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private userService: UserService,
    private authService: AuthService
  ) {}

  ngOnInit() {
    this.userId = this.route.snapshot.params['id'];
    this.checkPermissions();
    this.loadUser();
    this.loadUserPermissions();
  }

  private checkPermissions() {
    this.canUpdate = this.authService.hasPermission('user:update');
    this.canDelete = this.authService.hasPermission('user:delete');
    this.canManage = this.authService.hasPermission('user:manage');
    
    // Self-access kontrolü - her iki ID formatını da kontrol et
    this.authService.user$.pipe(take(1)).subscribe(currentUser => {
      const currentUserId = currentUser?._id || currentUser?.id;
      if (currentUserId === this.userId) {
        this.canUpdate = true; // Kendi profilini güncelleyebilir
        // Kendi hesabını silemez
        this.canDelete = false;
      }
    });
  }

  loadUser() {
    this.loading = true;
    this.error = '';
    
    this.userService.getUserById(this.userId).subscribe({
      next: (response) => {
        this.user = response.data?.user || null;
        this.loading = false;
      },
      error: (error) => {
        this.error = error?.error?.message || 'Kullanıcı bilgileri yüklenirken hata oluştu';
        this.loading = false;
      }
    });
  }

  loadUserPermissions() {
    this.permissionsLoading = true;
    
    this.userService.getUserPermissions(this.userId).subscribe({
      next: (response) => {
        this.userPermissions = response.data?.permissions || [];
        this.permissionsLoading = false;
      },
      error: (error) => {
        console.error('Failed to load user permissions:', error);
        this.userPermissions = [];
        this.permissionsLoading = false;
        
        // 401 hatası için redirect
        if (error.status === 401 && !this.authService.isDefaultSessionActive) {
          this.authService.hardLogout();
          this.router.navigate(['/login']);
        } else {
          // Diğer hatalar için kullanıcıya bilgi ver - sadece console'a yazdırma
          console.warn('İzinler yüklenirken hata oluştu:', error?.error?.message || error?.message);
        }
      }
    });
  }

  editUser() {
    if (!this.canUpdate) return;
    this.router.navigate(['/users', this.userId, 'edit']);
  }

  toggleUserStatus() {
    if (!this.canManage || !this.user) return;
    
    this.userService.toggleUserStatus(this.userId, !this.user.isActive).subscribe({
      next: () => {
        this.loadUser();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Durum değiştirilirken hata oluştu';
      }
    });
  }

  deleteUser() {
    if (!this.canDelete || !this.user) return;
    
    const fullName = `${this.user.firstName} ${this.user.lastName}`;
    if (confirm(`${fullName} kullanıcısını silmek istediğinizden emin misiniz?`)) {
      this.userService.deleteUser(this.userId).subscribe({
        next: () => {
          this.router.navigate(['/users']);
        },
        error: (error) => {
          this.error = error?.error?.message || 'Kullanıcı silinirken hata oluştu';
        }
      });
    }
  }

  unlockUser() {
    if (!this.canManage) return;
    
    this.userService.unlockUser(this.userId).subscribe({
      next: () => {
        this.loadUser();
      },
      error: (error) => {
        this.error = error?.error?.message || 'Kullanıcı kilidi açılırken hata oluştu';
      }
    });
  }

  resetPassword() {
    if (!this.canManage || !this.user) return;
    
    const newPassword = prompt('Yeni şifreyi girin (min. 8 karakter, büyük/küçük harf, rakam ve özel karakter):');
    if (!newPassword) return;
    
    // Kompleks validasyon
    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/;
    if (!strongPasswordRegex.test(newPassword)) {
      alert('Şifre en az 8 karakter olmalı; büyük/küçük harf, rakam ve özel karakter içermelidir');
      return;
    }
    
    this.userService.resetPassword(this.userId, newPassword).subscribe({
      next: () => {
        alert('Şifre başarıyla sıfırlandı');
      },
      error: (error) => {
        const errorMsg = error?.error?.message || error?.message || 'Bir hata oluştu';
        this.error = `Şifre sıfırlanırken hata: ${errorMsg}`;
      }
    });
  }

  getUserRoles(): string {
    if (!this.user?.roles || this.user.roles.length === 0) return 'Rol atanmamış';
    return (this.user.roles as any[]).map(r => {
      if (typeof r === 'string') return r;
      return r.displayName || r.name || '';
    }).filter(Boolean).join(', ');
  }

  getPermissionsByCategory() {
    const categories: { [key: string]: any[] } = {};
    
    this.userPermissions.forEach(permission => {
      // Backend'den gelen permissions normalizasyonu - tip güvenliği ile
      let permObj: any = permission;
      
      // Backend response'a göre farklı yapıları normalize et
      if (permission && typeof permission === 'object') {
        // _id, name alanları varsa direkt kullan
        if ('_id' in permission && 'name' in permission) {
          permObj = permission;
        } 
        // nested permission objesi varsa
        else if ('permission' in permission && permission.permission) {
          permObj = permission.permission;
        }
        else {
          console.warn('Unexpected permission format:', permission);
          return;
        }
      } else {
        console.warn('Invalid permission object:', permission);
        return;
      }
      
      const category = permObj?.category || 'Diğer';
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push(permObj);
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

  // Kategori adını "Audit Management" gibi Title Case'e çevir
  formatCategory(category: string): string {
    if (!category) return '';
    if (category === 'Diğer') return category; // Türkçe "Other" sabit kalsın
    return category
      .split('_')
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  goBack() {
    this.router.navigate(['/users']);
  }

  trackByPermissionId(index: number, permission: any): string {
    return permission._id || permission.id || index;
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

  getUserInitials(): string {
    if (!this.user) return '';
    const first = this.user.firstName || '';
    const last = this.user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }

  isUserLocked(): boolean {
    if (!this.user?.lockoutUntil) return false;
    return new Date(this.user.lockoutUntil) > new Date();
  }

  getUserStatus(): string {
    if (!this.user) return '';
    
    if (this.isUserLocked()) {
      return 'Kilitli';
    }
    
    return this.user.isActive ? 'Aktif' : 'Pasif';
  }

  getStatusClass(): string {
    if (!this.user) return '';
    
    if (this.isUserLocked()) {
      return 'locked';
    }
    
    return this.user.isActive ? 'active' : 'inactive';
  }

  // Metadata bilgilerinden email doğrulama kısmını kaldır
  getMetadataInfo(): { label: string; value: string; class?: string }[] {
    if (!this.user) return [];

    const info: { label: string; value: string; class?: string }[] = [];

    if (this.user.createdAt) {
      info.push({
        label: 'Oluşturulma',
        value: new Date(this.user.createdAt).toLocaleDateString('tr-TR', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      });
    }

    if (this.user.updatedAt) {
      info.push({
        label: 'Son Güncelleme',
        value: new Date(this.user.updatedAt).toLocaleDateString('tr-TR', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      });
    }

    if (this.user.loginAttempts !== undefined && this.user.loginAttempts > 0) {
      info.push({
        label: 'Başarısız Giriş Denemeleri',
        value: this.user.loginAttempts.toString(),
        class: 'warning'
      });
    }

    if (this.user.lockoutUntil && this.isUserLocked()) {
      info.push({
        label: 'Kilit Süresi',
        value: new Date(this.user.lockoutUntil).toLocaleDateString('tr-TR', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        }),
        class: 'error'
      });
    }

    if (this.user.authMethod) {
      info.push({
        label: 'Giriş Yöntemi',
        value: this.user.authMethod === 'jwt' ? 'Yerel Kimlik Doğrulama' : 'SSO'
      });
    }

    return info;
  }
}