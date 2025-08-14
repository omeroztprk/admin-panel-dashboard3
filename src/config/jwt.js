const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('./index');

const buildSignOpts = (expiresIn) => {
  const opts = { algorithm: 'HS256', expiresIn };
  if (config.jwt.issuer) opts.issuer = config.jwt.issuer;
  if (config.jwt.audience) opts.audience = config.jwt.audience;
  return opts;
};

const buildVerifyOpts = () => {
  const opts = { algorithms: ['HS256'], clockTolerance: 5 };
  if (config.jwt.issuer) opts.issuer = config.jwt.issuer;
  if (config.jwt.audience) opts.audience = config.jwt.audience;
  return opts;
};

const generateAccessToken = (payload) =>
  jwt.sign(payload, config.jwt.access.secret, buildSignOpts(config.jwt.access.expiresIn));

const generateRefreshToken = (payload = {}) => {
  const withJti = {
    ...payload,
    jti: payload.jti || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'))
  };
  return jwt.sign(withJti, config.jwt.refresh.secret, buildSignOpts(config.jwt.refresh.expiresIn));
};

const verifyAccessToken = (token) =>
  jwt.verify(token, config.jwt.access.secret, buildVerifyOpts());

const verifyRefreshToken = (token) =>
  jwt.verify(token, config.jwt.refresh.secret, buildVerifyOpts());

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
};
