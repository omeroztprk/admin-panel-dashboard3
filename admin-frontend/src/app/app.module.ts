// src/app/app.module.ts  (DEĞİŞTİ)
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { CommonModule } from '@angular/common';

import { AppComponent } from './app.component';
import { AppRoutingModule } from './app-routing.module';

// Layout Components
import { MainLayoutComponent } from './layout/main-layout/main-layout.component';
import { HeaderComponent } from './layout/header/header.component';
import { SidebarComponent } from './layout/sidebar/sidebar.component';
import { FooterComponent } from './layout/footer/footer.component';

// Auth Components
import { LoginComponent } from './features/auth/login/login.component';
import { RegisterComponent } from './features/auth/register/register.component';
import { TfaComponent } from './features/auth/tfa/tfa.component';

// Dashboard Component
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

import { AuthInterceptor } from './core/interceptors/auth.interceptor';
import { PermissionService } from './core/services/permission.service';

@NgModule({
  declarations: [
    AppComponent,

    // Layout Components
    MainLayoutComponent,
    HeaderComponent,
    SidebarComponent,
    FooterComponent,

    // Auth Components
    LoginComponent,
    RegisterComponent,
    TfaComponent,

    // Dashboard
    DashboardComponent,

    // Account Components
    ProfileComponent,
    ChangePasswordComponent,
    SessionsComponent,

    // User Components
    UserListComponent,
    UserDetailComponent,
    UserFormComponent,

    // Role Components
    RoleListComponent,
    RoleDetailComponent,
    RoleFormComponent,

    // Permission Components
    PermissionListComponent,
    PermissionDetailComponent,
    PermissionFormComponent
  ],
  imports: [
    BrowserModule,
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    AppRoutingModule
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
    PermissionService
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
