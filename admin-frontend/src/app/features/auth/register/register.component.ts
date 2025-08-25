import { Component } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent {
  loading = false; 
  error = '';
  successMessage = '';
  
  form = this.fb.group({
    firstName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
    lastName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(8), Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$/)]],
  });

  constructor(private fb: FormBuilder, private auth: AuthService, private router: Router) {}

  submit() {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    
    this.loading = true; 
    this.error = '';
    this.successMessage = '';
    
    this.auth.register(this.form.value as any).subscribe({
      next: (res) => { 
        this.loading = false; 
        this.successMessage = 'Kayıt başarılı! Giriş sayfasına yönlendiriliyorsunuz...';
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 2000);
      },
      error: (e) => { 
        this.loading = false; 
        this.error = e?.error?.message || 'Kayıt başarısız';
      }
    });
  }

  // Form validasyon yardımcı metodları
  getFieldError(fieldName: string): string {
    const field = this.form.get(fieldName);
    if (field?.errors && field.touched) {
      if (field.errors['required']) return `${fieldName} zorunludur`;
      if (field.errors['email']) return 'Geçerli bir email adresi girin';
      if (field.errors['minlength']) return `En az ${field.errors['minlength'].requiredLength} karakter olmalı`;
      if (field.errors['maxlength']) return `En fazla ${field.errors['maxlength'].requiredLength} karakter olmalı`;
      if (field.errors['pattern']) return 'Şifre en az 8 karakter, büyük/küçük harf, rakam ve özel karakter içermeli';
    }
    return '';
  }
}