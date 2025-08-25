import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { Subject } from 'rxjs';
import { debounceTime, takeUntil } from 'rxjs/operators';
import { AuthService } from '../../../core/services/auth.service';
import { AuthUser } from '../../../core/models';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss']
})
export class ProfileComponent implements OnInit, OnDestroy {
  saving = false;
  success = '';
  error = '';

  user: AuthUser | null = null;

  private destroyed$ = new Subject<void>();
  private suspendFormPatch = false;

  form = this.fb.group({
    firstName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
    lastName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(50)]],
    profile: this.fb.group({
      phone: [''],
      timezone: [''],
      language: ['tr']
    })
  });

  constructor(private fb: FormBuilder, private auth: AuthService) {}

  ngOnInit(): void {
    this.auth.user$
      .pipe(takeUntil(this.destroyed$))
      .subscribe(u => {
        this.user = u;
        if (!u) return;

        if (this.suspendFormPatch || this.saving) return;

        const current = this.getFormPayload();
        if (!this.areSame(current, u)) {
          this.patchFormWithUser(u);
        }
      });

    this.form.valueChanges
      .pipe(debounceTime(100), takeUntil(this.destroyed$))
      .subscribe(() => {
        this.suspendFormPatch = true;
      });
  }

  ngOnDestroy(): void {
    this.destroyed$.next();
    this.destroyed$.complete();
  }

  private patchFormWithUser(u: AuthUser) {
    this.form.patchValue({
      firstName: u.firstName || '',
      lastName: u.lastName || '',
      profile: {
        phone: u.profile?.phone || '',
        timezone: u.profile?.timezone || '',
        language: u.profile?.language || 'tr'
      }
    }, { emitEvent: false });
  }

  private getFormPayload() {
    const v = this.form.value as any;
    return {
      firstName: v.firstName || '',
      lastName: v.lastName || '',
      profile: {
        phone: v.profile?.phone || '',
        timezone: v.profile?.timezone || '',
        language: v.profile?.language || 'tr'
      }
    };
  }

  private areSame(formVal: any, user: AuthUser): boolean {
    return (
      (formVal.firstName || '') === (user.firstName || '') &&
      (formVal.lastName || '') === (user.lastName || '') &&
      (formVal.profile?.phone || '') === (user.profile?.phone || '') &&
      (formVal.profile?.timezone || '') === (user.profile?.timezone || '') &&
      (formVal.profile?.language || 'tr') === (user.profile?.language || 'tr')
    );
  }

  submit() {
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.saving = true; this.success = ''; this.error = '';

    this.suspendFormPatch = true;

    this.auth.updateProfile(this.getFormPayload()).subscribe({
      next: () => {
        this.saving = false;
        this.success = 'Profil güncellendi.';
        this.suspendFormPatch = false;
      },
      error: (e) => {
        this.saving = false;
        this.error = e?.error?.message || e?.message || 'Güncelleme başarısız';
      }
    });
  }

  getUserInitials(): string {
    if (!this.user) return '';
    const first = this.user.firstName || '';
    const last = this.user.lastName || '';
    return (first[0] || '') + (last[0] || '');
  }
}
