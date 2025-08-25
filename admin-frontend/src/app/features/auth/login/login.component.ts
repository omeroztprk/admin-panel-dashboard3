import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { AuthService } from '../../../core/services/auth.service';
import { LoginDecision } from '../../../core/models';
import { environment } from '../../../../environments/environment.development';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  loading = false;
  error = '';

  authMode = environment.authMode;
  isSSO = this.authMode === 'SSO';
  isDefault = this.authMode === 'DEFAULT';
  isHybrid = this.authMode === 'HYBRID';

  form = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required]]
  });

  constructor(
    private fb: FormBuilder,
    private auth: AuthService,
    private router: Router,
    private route: ActivatedRoute
  ) { }

  ngOnInit() {

    if (this.auth.isAuthenticated) {
      const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') || '/dashboard';
      this.router.navigateByUrl(returnUrl);
    }
  }

  submitSSO() {
    this.loading = true;
    this.auth.ssoLogin();
  }

  submit() {
    if (this.isSSO) {
      this.submitSSO();
      return;
    }

    if (this.form.invalid) {
      this.form.markAllAsTouched();
      this.error = 'Lütfen tüm alanları doldurun';
      return;
    }

    this.loading = true;
    this.error = '';
    const { email, password } = this.form.value;

    this.auth.login(email!, password!).subscribe({
      next: (res: LoginDecision) => {
        this.loading = false;
        if (res.requiresTfa) {
          this.router.navigate(['/tfa']);
        } else {
          const ret = this.route.snapshot.queryParamMap.get('returnUrl') || '/dashboard';
          this.router.navigateByUrl(ret);
        }
      },
      error: (e: HttpErrorResponse | any) => {
        this.loading = false;
        this.error = e?.error?.message || 'Giriş başarısız';
        if (e?.status === 423) {
          const retryAfter = e?.headers?.get?.('Retry-After');
          if (retryAfter) {
            const seconds = parseInt(retryAfter);
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = seconds % 60;
            this.error = `Hesap kilitlendi. ${minutes} dakika ${remainingSeconds} saniye sonra tekrar deneyin.`;
          }
        }
      }
    });
  }
}
