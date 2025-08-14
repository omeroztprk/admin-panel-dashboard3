# Admin Panel Dashboard Backend

## Description

A scalable and secure backend for an admin panel dashboard, built with **Node.js**, **Express.js**, and **MongoDB**. It provides user, role, permission, category, and audit log management with JWT-based authentication, RBAC (Role-Based Access Control), and i18n multi-language support. Designed with a modular architecture for enterprise-grade maintainability and security.

## Features

- **JWT Authentication** – Secure login and token-based session management.
- **Role & Permission Management (RBAC)** – Fine-grained access control for resources and actions.
- **Audit Logging** – Tracks all critical actions with severity levels and filtering capabilities.
- **Rate Limiting with Redis** – Prevents abuse by limiting request rates.
- **Multi-language Support (i18n)** – Supports multiple languages for responses and error messages.
- **Security Middleware** – Includes Helmet, XSS Clean, and Mongo Sanitize.
- **Centralized Error Handling** – All errors managed through a unified handler.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/OmerOztprk/admin-panel-dashboard.git
    ```

2. Navigate to the project directory:

    ```bash
    cd admin-panel-dashboard
    ```

3. Install dependencies:

    ```bash
    npm install
    ```

4. Copy the example environment file:

    ```bash
    cp .env.example .env
    ```

5. Configure .env with your database, JWT, Redis, and other required settings.

## Running the Application

### Development

```bash
npm run dev
```

### Production

```bash
npm start
```

## Seeding (Default Data)

```bash
npm run seed
```

This command creates default users, roles and permissions

## API Endpoint Examples

- `POST /api/v1/auth/login` – User login  
- `GET /api/v1/users` – List users  
- `PATCH /api/v1/users/{id}` – Update user details  
- `DELETE /api/v1/users/{id}` – Delete user  
- `GET /api/v1/audit` – List audit logs  

## License

This project is licensed under the [MIT License](LICENSE).
