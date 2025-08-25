// src/app/app-routing.module.ts
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AuthGuard } from './core/guards/auth.guard';
import { PermissionGuard } from './core/guards/permission.guard';

// Layout
import { MainLayoutComponent } from './layout/main-layout/main-layout.component';

// Auth Components
import { LoginComponent } from './features/auth/login/login.component';
import { RegisterComponent } from './features/auth/register/register.component';
import { TfaComponent } from './features/auth/tfa/tfa.component';

// Dashboard
import { DashboardComponent } from './features/dashboard/dashboard.component';

// Account Components
import { ProfileComponent } from './features/account/profile/profile.component';
import { ChangePasswordComponent } from './features/account/change-password/change-password.component';
import { SessionsComponent } from './features/account/sessions/sessions.component';

// User Components
import { UserListComponent } from './features/users/user-list/user-list.component';
import { UserDetailComponent } from './features/users/user-detail/user-detail.component';
import { UserFormComponent } from './features/users/user-form/user-form.component';

// Role Components
import { RoleListComponent } from './features/roles/role-list/role-list.component';
import { RoleDetailComponent } from './features/roles/role-detail/role-detail.component';
import { RoleFormComponent } from './features/roles/role-form/role-form.component';

// Permission Components
import { PermissionListComponent } from './features/permissions/permission-list/permission-list.component';
import { PermissionDetailComponent } from './features/permissions/permission-detail/permission-detail.component';
import { PermissionFormComponent } from './features/permissions/permission-form/permission-form.component';

const routes: Routes = [
  // Auth pages (layout dışında)
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'tfa', component: TfaComponent },

  // Layout altında çalışacak tüm sayfalar
  {
    path: '',
    component: MainLayoutComponent,
    canActivate: [AuthGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      { path: 'dashboard', component: DashboardComponent },

      // Hesap sayfaları (artık SSO için de açık)
      { path: 'account/profile', component: ProfileComponent },
      { path: 'account/security', component: ChangePasswordComponent },
      { path: 'account/sessions', component: SessionsComponent },

      // User Management Routes with permission checks
      { path: 'users', component: UserListComponent, canActivate: [PermissionGuard], data: { permission: 'user:read' } },
      { path: 'users/new', component: UserFormComponent, canActivate: [PermissionGuard], data: { permission: 'user:create' } },
      { path: 'users/:id', component: UserDetailComponent, canActivate: [PermissionGuard], data: { permission: 'user:read' } },
      { path: 'users/:id/edit', component: UserFormComponent, canActivate: [PermissionGuard], data: { permission: 'user:update' } },

      // Role Management Routes with permission checks
      { path: 'roles', component: RoleListComponent, canActivate: [PermissionGuard], data: { permission: 'role:read' } },
      { path: 'roles/new', component: RoleFormComponent, canActivate: [PermissionGuard], data: { permission: 'role:create' } },
      { path: 'roles/:id', component: RoleDetailComponent, canActivate: [PermissionGuard], data: { permission: 'role:read' } },
      { path: 'roles/:id/edit', component: RoleFormComponent, canActivate: [PermissionGuard], data: { permission: 'role:update' } },

      { path: 'permissions', component: PermissionListComponent, canActivate: [PermissionGuard], data: { permission: 'permission:read' } },
      { path: 'permissions/new', component: PermissionFormComponent, canActivate: [PermissionGuard], data: { permission: 'permission:create' } },
      { path: 'permissions/:id', component: PermissionDetailComponent, canActivate: [PermissionGuard], data: { permission: 'permission:read' } },
      { path: 'permissions/:id/edit', component: PermissionFormComponent, canActivate: [PermissionGuard], data: { permission: 'permission:update' } }
    ]
  },

  // Unknown routes
  { path: '**', redirectTo: 'login' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes, { bindToComponentInputs: true })],
  exports: [RouterModule]
})
export class AppRoutingModule { }
