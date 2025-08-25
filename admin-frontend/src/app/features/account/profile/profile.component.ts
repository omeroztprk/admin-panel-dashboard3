import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from '../../../core/services/auth.service';
import { AuthUser } from '../../../core/models';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss']
})
export class ProfileComponent {
  saving = false;
  success = '';
  error = '';

  user: AuthUser | null = null;

  form = this.fb.group({
    firstName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
    lastName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
    profile: this.fb.group({
      phone: [''],
      timezone: [''],
      language: ['tr']
    })
  });

  constructor(private fb: FormBuilder, private auth: AuthService) {
    this.auth.user$.subscribe(u => {
      this.user = u;
      if (u) {
        this.form.patchValue({
          firstName: u.firstName || '',
          lastName: u.lastName || '',
          profile: {
            phone: u.profile?.phone || '',
            timezone: u.profile?.timezone || '',
            language: u.profile?.language || 'tr'
          }
        });
      }
    });
  }

  submit() {
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.saving = true; this.success = ''; this.error = '';
    // Backend, SSO oturumlarda Keycloak Admin API üzerinden güncelleyecek şekilde zaten düzenlendi
    this.auth.updateProfile(this.form.value as any).subscribe({
      next: () => { this.saving = false; this.success = 'Profil güncellendi.'; },
      error: (e) => { this.saving = false; this.error = e?.error?.message || e?.message || 'Güncelleme başarısız'; }
    });
  }

  getUserInitials(): string {
    if (!this.user) return '';
    const first = this.user.firstName || '';
    const last = this.user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }
}
