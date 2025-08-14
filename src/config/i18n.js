const path = require('path');
const fs = require('fs');
const i18next = require('i18next');
const Backend = require('i18next-fs-backend');
const HttpMiddleware = require('i18next-http-middleware');
const config = require('./index');

const localesDir = path.join(__dirname, '../locales');

const preloadLanguages = fs.existsSync(localesDir)
  ? fs.readdirSync(localesDir).filter((f) => f.endsWith('.json')).map((f) => path.basename(f, '.json'))
  : [config.i18n.defaultLanguage];

const supportedLanguages = preloadLanguages;

const toBaseLng = (lng) => (lng || '').split(',')[0].split(';')[0].split('-')[0];

const parseAcceptLanguage = (header) => {
  if (!header || typeof header !== 'string') return null;
  try {
    const parts = header.split(',').map((s) => {
      const [raw, ...params] = s.trim().split(';');
      const tag = toBaseLng(raw);
      let q = 1.0;
      for (const p of params) {
        const m = p.match(/q=([0-9.]+)/i);
        if (m) q = parseFloat(m[1]);
      }
      return { tag, q: Number.isFinite(q) ? q : 1.0 };
    });

    const bestByTag = new Map();
    for (const { tag, q } of parts) {
      if (!tag) continue;
      if (!bestByTag.has(tag) || bestByTag.get(tag) < q) bestByTag.set(tag, q);
    }

    return [...bestByTag.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([tag]) => tag)
      .find((tag) => supportedLanguages.includes(tag)) || null;
  } catch {
    return null;
  }
};

const resolveLanguage = (lngOrHeader) => {
  if (!lngOrHeader) return config.i18n.defaultLanguage;

  if (lngOrHeader.includes(',') || lngOrHeader.includes(';')) {
    const best = parseAcceptLanguage(lngOrHeader);
    if (best) return best;
  }

  const base = toBaseLng(lngOrHeader);
  if (supportedLanguages.includes(base)) return base;
  return config.i18n.defaultLanguage;
};

const detectLanguage = (req, user = null) => {
  if (user?.profile?.language) return resolveLanguage(user.profile.language);
  if (req?.user?.profile?.language) return resolveLanguage(req.user.profile.language);
  if (req?.query?.lng) return resolveLanguage(req.query.lng);
  if (req?.cookies?.i18next) return resolveLanguage(req.cookies.i18next);
  if (req?.headers?.['accept-language']) return resolveLanguage(req.headers['accept-language']);
  return resolveLanguage(config.i18n.defaultLanguage);
};

const t = (key, options = {}) => {
  try {
    const lng = resolveLanguage(options.lng || config.i18n.defaultLanguage);
    if (!i18next.isInitialized) return key;
    const result = i18next.t(key, { ...options, lng });
    if (config.i18n.debug && (!result || result === key)) {
      console.warn(`Missing translation for "${key}" (lng="${lng}")`);
    }
    return result || key;
  } catch (error) {
    if (config.i18n.debug) console.error('Translation error:', error);
    return key;
  }
};

const createRequestTranslator = (req) => {
  return (key, options = {}) => {
    try {
      const preferred = options.lng || detectLanguage(req);
      if (req.i18n?.t) {
        const res = req.i18n.t(key, { ...options, lng: resolveLanguage(preferred) });
        if (res) return res;
      }
      return t(key, { ...options, lng: resolveLanguage(preferred) });
    } catch (error) {
      if (config.i18n.debug) console.error('Request translation error:', error);
      return key;
    }
  };
};

const addTranslationHelper = (req, res, next) => {
  req.t = createRequestTranslator(req);
  req.getLanguage = () => detectLanguage(req);
  req.translate = (key, options = {}) => {
    const lng = resolveLanguage(options.lng || req.getLanguage());
    return t(key, { ...options, lng });
  };
  next();
};

const initializeI18n = async () => {
  await i18next
    .use(Backend)
    .use(HttpMiddleware.LanguageDetector)
    .init({
      lng: config.i18n.defaultLanguage,
      fallbackLng: [config.i18n.defaultLanguage, 'en'],
      debug: config.i18n.debug,

      backend: {
        loadPath: path.join(localesDir, '{{lng}}.json'),
      },

      detection: {
        order: ['querystring', 'cookie', 'header'],
        caches: false,
        lookupHeader: 'accept-language',
        lookupQuerystring: 'lng',
        lookupCookie: 'i18next',
      },

      interpolation: { escapeValue: false },

      preload: preloadLanguages,
      supportedLngs: preloadLanguages,
      nonExplicitSupportedLngs: true,
      returnEmptyString: false,
      initImmediate: false,
    });

  if (config.i18n.debug) {
    console.log(`i18n initialized (default="${config.i18n.defaultLanguage}"; supported=${supportedLanguages.join(', ')})`);
  }

  return i18next;
};

module.exports = {
  t,
  i18next,
  addTranslationHelper,
  detectLanguage,
  initializeI18n,
  supportedLanguages,
  resolveLanguage,
};
