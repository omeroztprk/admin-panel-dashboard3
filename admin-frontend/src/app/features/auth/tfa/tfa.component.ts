import { Component } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { AuthService } from '../../../core/services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-tfa',
  templateUrl: './tfa.component.html',
  styleUrls: ['./tfa.component.scss']
})
export class TfaComponent {
  loading = false;
  error = '';
  emailHint = '';
  attempts = 0;
  maxAttempts = 3;

  form = this.fb.group({ 
    code: ['', [Validators.required, Validators.minLength(6), Validators.maxLength(6), Validators.pattern(/^\d{6}$/)]] 
  });

  constructor(private fb: FormBuilder, private auth: AuthService, private router: Router) {
    const last = auth.lastLoginEmail || sessionStorage.getItem('ap.lastEmail') || '';
    this.emailHint = last ? `E-posta: ${this.maskEmail(last)}` : '';
    
    // TFA sayfasına direk gelinmişse login'e yönlendir
    if (!last) {
      this.router.navigate(['/login']);
    }
  }

  submit() {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    
    this.loading = true; 
    this.error = '';
    
    this.auth.verifyTfa(this.form.value.code!).subscribe({
      next: () => { 
        this.loading = false; 
        this.router.navigateByUrl('/dashboard'); 
      },
      error: (e) => { 
        this.loading = false; 
        this.attempts++;
        this.error = e?.error?.message || 'Doğrulama başarısız';
        
        // Max deneme aşıldıysa login'e yönlendir
        if (this.attempts >= this.maxAttempts) {
          setTimeout(() => {
            this.auth.lastLoginEmail = null;
            this.router.navigate(['/login']);
          }, 2000);
          this.error = 'Çok fazla yanlış deneme. Giriş sayfasına yönlendiriliyorsunuz...';
        }
        
        // Form'u temizle
        this.form.patchValue({ code: '' });
      }
    });
  }

  private maskEmail(email: string): string {
    const [username, domain] = email.split('@');
    if (username.length <= 2) return email;
    const masked = username.substring(0, 2) + '*'.repeat(username.length - 2);
    return `${masked}@${domain}`;
  }

  // Kod input'una sadece rakam girişi için
  onCodeInput(event: any) {
    const value = event.target.value.replace(/\D/g, '');
    this.form.patchValue({ code: value });
  }
}