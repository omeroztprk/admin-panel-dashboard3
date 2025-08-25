export const environment = {
  production: false,
  apiBase: 'http://localhost:5001/api/v1',
  authMode: 'HYBRID' as 'DEFAULT' | 'SSO' | 'HYBRID',
  sso: {
    loginUrl: 'http://localhost:5001/api/v1/auth/keycloak',
    meUrl: 'http://localhost:5001/api/v1/auth/keycloak/me',
    logoutUrl: 'http://localhost:5001/api/v1/auth/keycloak/logout'
  }
};
