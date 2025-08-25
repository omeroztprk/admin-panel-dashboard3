const express = require('express');
const passport = require('passport');
const KeycloakStrategy = require('passport-keycloak-oauth2-oidc').Strategy;
const { filterKeycloakRoles, extractRolesFromToken } = require('../utils/sso');
const KeycloakRoleService = require('../services/keycloakRoleService');
const config = require('../config');
const { standardizeUser, processKeycloakUser } = require('../middleware/auth-unified');
const fetch = global.fetch || require('node-fetch');

const router = express.Router();

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use('keycloak', new KeycloakStrategy(
  {
    clientID: config.auth.keycloak.clientId,
    clientSecret: config.auth.keycloak.clientSecret,
    realm: config.auth.keycloak.realm,
    publicClient: false,
    sslRequired: 'external',
    authServerURL: config.auth.keycloak.url,
    callbackURL: config.auth.keycloak.redirectUri,
    skipUserProfile: (process.env.KEYCLOAK_SKIP_USERINFO || '').toLowerCase() === 'true'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const kcAll = extractRolesFromToken(accessToken, config.auth.keycloak.clientId);
      const kcRoles = filterKeycloakRoles(kcAll, config.auth.keycloak.realm);

      const keycloakUserId = profile?.id || profile?._json?.sub;
      const user = await KeycloakRoleService.updateUserKeycloakInfo(
        keycloakUserId,
        kcRoles,
        profile?._json || profile
      );

      return done(null, {
        profile,
        accessToken,
        refreshToken,
        kcRoles,
        user
      });
    } catch (err) {
      return done(err);
    }
  }
));

router.get('/keycloak', (req, res, next) => {
  passport.authenticate('keycloak', { scope: ['openid', 'profile', 'email'] })(req, res, next);
});

router.get('/keycloak/callback', (req, res, next) => {
  passport.authenticate('keycloak', { failureRedirect: '/api/v1/auth/keycloak' }, (err, user, info) => {
    if (err) { 
      console.error('Keycloak callback error:', err); 
      return next(err); 
    }
    if (!user) { 
      console.error('Keycloak authentication failed:', info); 
      return res.redirect('/api/v1/auth/keycloak'); 
    }
    req.logIn(user, (loginErr) => {
      if (loginErr) return next(loginErr);
      return res.redirect(config.auth.keycloak.postLoginRedirectUri);
    });
  })(req, res, next);
});

router.get('/keycloak/logout', async (req, res) => {
  const redirectAfter = config.auth.keycloak.postLogoutRedirectUri || '/api/v1/auth/keycloak';

  try {
    const refreshToken = req.user?.refreshToken;
    if (refreshToken) {
      const url = `${config.auth.keycloak.url}/realms/${config.auth.keycloak.realm}/protocol/openid-connect/logout`;
      const params = new URLSearchParams({
        client_id: config.auth.keycloak.clientId,
        client_secret: config.auth.keycloak.clientSecret,
        refresh_token: refreshToken
      });
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params
      }).catch(() => {});
    }
  } catch (e) {
    console.error('Keycloak backchannel logout error:', e?.message || e);
  } finally {
    req.logout(() => {
      req.session?.destroy(() => res.redirect(redirectAfter));
    });
  }
});

router.get('/keycloak/me', async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  try {
    const unified = await processKeycloakUser(req.user, req); // pass req to allow session throttle
    return res.json(standardizeUser(unified, 'sso'));
  } catch (error) {
    console.error('Error in keycloak/me:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/ping', (_req, res) => res.send('ok'));

module.exports = router;
