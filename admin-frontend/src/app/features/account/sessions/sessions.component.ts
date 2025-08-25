// src/app/features/account/sessions/sessions.component.ts  (YENİ)
import { Component, OnInit, OnDestroy } from '@angular/core';
import { AuthService } from '../../../core/services/auth.service';
import { Router } from '@angular/router';
import { environment } from '../../../../environments/environment.development';
import { Subject, takeUntil } from 'rxjs';

@Component({
  selector: 'app-sessions',
  templateUrl: './sessions.component.html',
  styleUrls: ['./sessions.component.scss']
})
export class SessionsComponent implements OnInit, OnDestroy {
  loading = true;
  error = '';
  sessions: any[] = [];
  revoking: Record<string, boolean> = {};
  private destroy$ = new Subject<void>();
  
  // Mod kontrolü (artık SSO için de açık)
  get isSessionManagementAvailable(): boolean {
    return true;
  }

  get authMode(): string {
    return environment.authMode;
  }

  constructor(
    private auth: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.fetch();
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  fetch() {
    this.loading = true; 
    this.error = '';
    
    this.auth.getSessions()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (res) => { 
          this.loading = false; 
          const payload = (res && (res as any).data) ? (res as any).data : res;
          this.sessions = payload?.sessions || [];
        },
        error: (e) => { 
          this.loading = false; 
          const errorMsg = e?.error?.message || e?.message || 'Oturumlar getirilemedi';
          this.error = errorMsg;
          
          if (e?.status === 401 || errorMsg.includes('Authentication') || errorMsg.includes('Token')) {
            this.router.navigate(['/login']);
          }
        }
      });
  }

  revoke(id: string) {
    if (!id || this.revoking[id] || !this.isSessionManagementAvailable) return;
    
    this.revoking[id] = true;
    this.error = '';

    this.auth.revokeSession(id)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: () => { 
          delete this.revoking[id]; 
          this.fetch();
        },
        error: (e) => { 
          delete this.revoking[id]; 
          const errorMsg = e?.error?.message || e?.message || 'Oturum sonlandırılamadı';
          this.error = errorMsg;

          if (e?.status === 401 || errorMsg.includes('Current session invalidated')) {
            setTimeout(() => {
              this.auth.hardLogout();
              this.router.navigate(['/login']);
            }, 300);
          }
        }
      });
  }

  revokeAll() {
    if (!this.isSessionManagementAvailable) {
      this.error = 'Bu işlem yalnızca varsayılan giriş modunda kullanılabilir.';
      return;
    }

    this.loading = true;
    this.error = '';
    
    this.auth.logoutAll()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: () => { 
          // logoutAll başarılı - AuthService zaten logout yapacak ve yönlendirecek
          this.loading = false; 
          this.sessions = []; 
        },
        error: (e) => { 
          this.loading = false; 
          this.error = e?.error?.message || e?.message || 'Tüm oturumlardan çıkış yapılamadı';
          // Hata durumunda da logout yapmayı dene
          setTimeout(() => {
            this.auth.hardLogout();
            this.router.navigate(['/login']);
          }, 2000);
        }
      });
  }

  goToDashboard() {
    this.router.navigate(['/dashboard']);
  }
}
