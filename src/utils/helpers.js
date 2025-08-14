const bcrypt = require('bcryptjs');
const config = require('../config');
const { prefixKey } = require('../config/redis');

const hashPassword = async (password) => {
  if (!password || typeof password !== 'string') throw new Error('Password must be a non-empty string');
  const saltRounds = config.security?.bcrypt?.saltRounds || 12;
  return bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password, hash) => {
  if (!password || !hash) throw new Error('Password and hash are required');
  return bcrypt.compare(password, hash);
};

const sanitizeObject = (obj, fieldsToRemove = ['password', '__v']) => {
  if (!obj || typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) return obj.map((item) => sanitizeObject(item, fieldsToRemove));

  let sanitized;
  if (obj.toObject && typeof obj.toObject === 'function') sanitized = obj.toObject();
  else if (obj.toJSON && typeof obj.toJSON === 'function') sanitized = obj.toJSON();
  else sanitized = { ...obj };

  fieldsToRemove.forEach((field) => {
    if (field.includes('.')) {
      const parts = field.split('.');
      let current = sanitized;
      for (let i = 0; i < parts.length - 1; i++) {
        if (current[parts[i]]) current = current[parts[i]];
        else return;
      }
      if (current && current[parts[parts.length - 1]]) delete current[parts[parts.length - 1]];
    } else {
      delete sanitized[field];
    }
  });

  return sanitized;
};

const normalizeEmail = (email) =>
  (typeof email === 'string' ? email.trim().toLowerCase() : '');

const escapeRegex = (str) =>
  String(str || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const isValidObjectId = (v) =>
  /^[0-9a-fA-F]{24}$/.test(String(v || ''));

const toBool = (v, d) =>
  (typeof v === 'boolean' ? v : typeof v === 'string' ? v === 'true' : d);

const normalizeIp = (ip) => {
  if (!ip || typeof ip !== 'string') return null;
  let v = ip.trim();

  // [::1] -> ::1
  if (v.startsWith('[') && v.includes(']')) v = v.slice(1, v.indexOf(']'));
  // fe80::1%lo0 -> fe80::1
  v = v.replace(/%.+$/, '');
  // 1.2.3.4:5678 -> 1.2.3.4
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(v)) v = v.split(':')[0];
  // ::1 -> 127.0.0.1
  if (v === '::1') return '127.0.0.1';
  // ::ffff:1.2.3.4 -> 1.2.3.4
  const mapped = v.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped) return mapped[1];

  return v;
};

const buildLoginAttemptsKey = (email, ip) => {
  const normEmail = normalizeEmail(email || 'unknown');
  const normIp = normalizeIp(ip || 'unknown') || 'unknown';
  return prefixKey(`login_attempts:${normEmail}:${normIp}`);
};

const getClientIP = (req, { fallbackToHeaders = true } = {}) => {
  if (!req) return '127.0.0.1';

  if (Array.isArray(req.ips) && req.ips.length > 0) {
    const n = normalizeIp(req.ips[0]);
    if (n) return n;
  }

  if (req.ip) {
    const n = normalizeIp(req.ip);
    if (n) return n;
  }

  if (fallbackToHeaders) {
    const headers = req.headers || {};
    const directHeaders = ['cf-connecting-ip', 'x-real-ip', 'x-client-ip'];
    for (const h of directHeaders) {
      const val = headers[h];
      if (val && typeof val === 'string') {
        const n = normalizeIp(val);
        if (n) return n;
      }
    }

    const xff = headers['x-forwarded-for'];
    if (xff && typeof xff === 'string') {
      const first = xff.split(',')[0]?.trim();
      const n = normalizeIp(first);
      if (n) return n;
    }
  }

  const candidates = [
    req.connection?.remoteAddress,
    req.socket?.remoteAddress,
    req.connection?.socket?.remoteAddress,
  ];
  for (const raw of candidates) {
    const n = normalizeIp(raw);
    if (n) return n;
  }

  return '127.0.0.1';
};

const parseUserAgent = (userAgent) => {
  if (!userAgent || typeof userAgent !== 'string') {
    return { browser: 'Unknown', platform: 'Unknown', version: 'Unknown' };
  }

  let browser = 'Unknown';
  let platform = 'Unknown';
  let version = 'Unknown';

  const browserPatterns = [
    { name: 'Chrome', pattern: /Chrome\/([0-9.]+)/, exclude: /Edg|OPR/ },
    { name: 'Firefox', pattern: /Firefox\/([0-9.]+)/ },
    { name: 'Safari', pattern: /Version\/([0-9.]+).*Safari/, exclude: /Chrome|Chromium/ },
    { name: 'Edge', pattern: /Edg\/([0-9.]+)/ },
    { name: 'Opera', pattern: /OPR\/([0-9.]+)/ },
    { name: 'Internet Explorer', pattern: /MSIE ([0-9.]+)|rv:([0-9.]+)/ }
  ];

  for (const { name, pattern, exclude } of browserPatterns) {
    if ((!exclude || !exclude.test(userAgent)) && pattern.test(userAgent)) {
      browser = name;
      const match = userAgent.match(pattern);
      if (match) version = match[1] || match[2] || 'Unknown';
      break;
    }
  }

  const platformPatterns = [
    { name: 'Windows', pattern: /Windows/ },
    { name: 'macOS', pattern: /Mac OS X|Macintosh/ },
    { name: 'Linux', pattern: /Linux/ },
    { name: 'Android', pattern: /Android/ },
    { name: 'iOS', pattern: /iPhone|iPad|iPod/ },
    { name: 'ChromeOS', pattern: /CrOS/ }
  ];
  for (const { name, pattern } of platformPatterns) {
    if (pattern.test(userAgent)) { platform = name; break; }
  }

  return { browser, platform, version };
};

const sleep = (ms) => {
  if (typeof ms !== 'number' || ms < 0) throw new Error('Sleep duration must be a non-negative number');
  return new Promise((resolve) => setTimeout(resolve, ms));
};

const toInt = (v, d) => {
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? d : n;
};

module.exports = {
  hashPassword,
  comparePassword,
  sanitizeObject,
  buildLoginAttemptsKey,
  getClientIP,
  parseUserAgent,
  sleep,
  toInt,
  isValidObjectId,
  normalizeEmail,
  escapeRegex,
  toBool,
};
