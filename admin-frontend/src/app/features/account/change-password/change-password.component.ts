import { Component } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { AuthService } from '../../../core/services/auth.service';
import { Router } from '@angular/router';
import { UserService } from '../../../core/services/user.service';
import { take } from 'rxjs/operators';

@Component({
  selector: 'app-change-password',
  templateUrl: './change-password.component.html',
  styleUrls: ['./change-password.component.scss']
})
export class ChangePasswordComponent {
  saving = false;
  success = '';
  error = '';

  form = this.fb.group({
    currentPassword: ['', [Validators.required]],
    newPassword:     ['', [Validators.required, Validators.minLength(8),
      Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,128}$/)]],
    confirmPassword: ['', [Validators.required]]
  });

  constructor(private fb: FormBuilder, private auth: AuthService, private router: Router, private userService: UserService) {
    this.auth.user$.pipe(take(1)).subscribe(u => {
      const isSso = !!(u && ((u as any).authMethod === 'sso' || (u as any)?.sso?.provider === 'keycloak'));
      if (isSso) {
        const ctrl = this.form.get('currentPassword');
        ctrl?.clearValidators();
        ctrl?.updateValueAndValidity({ emitEvent: false });
      }
    });
  }

  get isSsoSessionActive(): boolean {
    return !this.auth.isDefaultSessionActive;
  }

  submit() {
    this.success = ''; this.error = '';
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }

    const { currentPassword, newPassword, confirmPassword } = this.form.value;
    if (newPassword !== confirmPassword) {
      this.error = 'Yeni şifreler eşleşmiyor.'; return;
    }

    this.saving = true;

    if (this.isSsoSessionActive) {
      this.auth.user$.pipe(take(1)).subscribe(u => {
        const userId = u?._id || u?.id;
        if (!userId) { this.saving = false; this.error = 'Kullanıcı bulunamadı'; return; }
        this.userService.resetPassword(userId, newPassword!).subscribe({
          next: () => {
            this.saving = false;
            this.success = 'Şifre değiştirildi. Güvenliğiniz için yeniden giriş yapın.';
            this.auth.logout().subscribe();
          },
          error: (e) => { this.saving = false; this.error = e?.error?.message || e?.message || 'Şifre değiştirilemedi'; }
        });
      });
      return;
    }

    this.auth.changePassword(currentPassword!, newPassword!).subscribe({
      next: () => {
        this.saving = false;
        this.success = 'Şifre değiştirildi. Güvenliğiniz için yeniden giriş yapın.';
        this.auth.logout().subscribe({
          next: () => this.router.navigateByUrl('/login'),
          error: () => this.router.navigateByUrl('/login')
        });
      },
      error: (e) => {
        this.saving = false; 
        this.error = e?.error?.message || e?.message || 'Şifre değiştirilemedi';
      }
    });
  }
}
