require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios');

const app = express();
const PORT = Number(process.env.PORT || 3000);

const ROOT = __dirname;
const CFG_PATH = path.join(ROOT, 'api', 'staff_config.json');
const STATUS_PATH = path.join(ROOT, 'api', 'status.json');

// Handlers pour éviter crashes silencieux
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

function loadConfig() {
  // ⚠️ SÉCURITÉ: Utilise UNIQUEMENT les variables d'environnement
  // Le fichier staff_config.json ne doit JAMAIS contenir de credentials
  return {
    staffPassword: String(process.env.STAFF_PASSWORD || ''),
    fivemSecret: String(process.env.FIVEM_SECRET || '')
  };
}

let config = loadConfig();

function loadStatusConfig() {
  try {
    const raw = fs.readFileSync(STATUS_PATH, 'utf8');
    const j = JSON.parse(raw);
    return {
      serverIp: String(process.env.FIVEM_SERVER_IP || j.serverIp || ''),
      discordInvite: String(process.env.DISCORD_INVITE || j.discordInvite || '')
    };
  } catch {
    // Fichier absent = on utilise uniquement les variables d'environnement
    return {
      serverIp: String(process.env.FIVEM_SERVER_IP || ''),
      discordInvite: String(process.env.DISCORD_INVITE || '')
    };
  }
}

function normalizeBaseUrl(serverIp) {
  const ip = String(serverIp || '').trim();
  if (!ip) return null;
  if (ip.startsWith('http://') || ip.startsWith('https://')) return ip.replace(/\/+$/, '');
  return `http://${ip}`;
}

async function fetchJsonWithTimeout(url, timeoutMs) {
  return new Promise((resolve) => {
    try {
      const lib = url.startsWith('https') ? https : http;
      const req = lib.get(url, { timeout: timeoutMs }, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return resolve(null);
        }

        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(null);
          }
        });
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    } catch {
      resolve(null);
    }
  });
}

// In-memory auth tokens
const tokens = new Map(); // token -> { expiresAt }
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

// In-memory player cache (can be fed by FiveM)
let latest = {
  updatedAt: Date.now(),
  server: { name: 'Nightfall RP', id: 'local' },
  players: []
};

// Server uptime tracking
const serverStartTime = Date.now();

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

function isTokenValid(token) {
  const info = tokens.get(token);
  if (!info) return false;
  if (Date.now() > info.expiresAt) {
    tokens.delete(token);
    return false;
  }
  return true;
}

function authMiddleware(req, res, next) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  const token = m ? m[1] : null;
  if (!token || !isTokenValid(token)) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ========== SÉCURITÉ: Headers, CORS, Rate Limiting ==========

// 🔥 CRITIQUE: Trust proxy pour Render (nécessaire pour secure cookies)
app.set('trust proxy', 1);

// Sessions (requis pour Passport Discord)
// 🔥 CRITIQUE: Configuration session pour OAuth2 sur Render
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'fallback-secret-please-set-SESSION_SECRET',
  resave: true, // Force resave pour garantir persistence
  saveUninitialized: false,
  rolling: true, // Renouveler le cookie à chaque requête
  cookie: {
    secure: false, // 🔴 Désactivé temporairement pour debug
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 heures
    sameSite: 'lax' // Important pour OAuth2
  }
};

console.log('[Session] ⚙️ Session config:', {
  secure: sessionConfig.cookie.secure,
  sameSite: sessionConfig.cookie.sameSite,
  maxAge: sessionConfig.cookie.maxAge,
  trustProxy: app.get('trust proxy')
});

app.use(session(sessionConfig));

// Initialiser Passport (DOIT ÊTRE AVANT LE MIDDLEWARE DE DEBUG !)
app.use(passport.initialize());
app.use(passport.session());

// Middleware de debug pour logger chaque requête (APRÈS Passport !)
app.use((req, res, next) => {
  // Log UNIQUEMENT les routes d'authentification importantes (pas les assets/API en boucle)
  if (req.path.startsWith('/auth/') && !req.path.includes('status')) {
    console.log(`[Auth Route] ${req.method} ${req.path} | User: ${req.user?.id || 'none'}`);
  }
  next();
});

// Configuration Passport Discord (optionnel)
const discordConfigured = process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET;

if (discordConfigured) {
  passport.use(new DiscordStrategy({
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      scope: ['identify', 'guilds', 'guilds.members.read']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Stocker l'access token dans le profil pour les appels API futurs
        profile.accessToken = accessToken;
        profile.refreshToken = refreshToken;
        return done(null, profile);
      } catch (error) {
        return done(error, null);
      }
    }
  ));

  // 🔥 CRITIQUE: Stocker uniquement les données essentielles en session
  passport.serializeUser((user, done) => {
    console.log('[Passport] 💾 Serializing user:', user.id);
    // Stocker l'objet complet (mais c'est OK car Discord Strategy le fait bien)
    done(null, {
      id: user.id,
      username: user.username,
      discriminator: user.discriminator,
      avatar: user.avatar,
      accessToken: user.accessToken,
      refreshToken: user.refreshToken
    });
  });

  passport.deserializeUser((obj, done) => {
    // Désérialisation silencieuse (trop verbeux)
    done(null, obj);
  });
} else {
  console.warn('[Discord] OAuth2 not configured - Discord authentication disabled');
}

// Fonction pour vérifier les rôles Discord
async function checkDiscordRoles(discordId, accessToken) {
  try {
    const guildId = process.env.DISCORD_GUILD_ID; // ID de votre serveur Discord
    if (!guildId) {
      console.error('[Discord] DISCORD_GUILD_ID not configured');
      return { hasStaffRole: false, hasPlayerRole: false };
    }

    console.log('[Discord] 🔍 Checking roles for user:', discordId);
    console.log('[Discord] 🏰 Guild ID:', guildId);

    // Récupérer les rôles du membre via l'API Discord
    const response = await axios.get(
      `https://discord.com/api/v10/users/@me/guilds/${guildId}/member`,
      {
        headers: { Authorization: `Bearer ${accessToken}` }
      }
    );

    console.log('[Discord] ✅ API Response:', JSON.stringify(response.data, null, 2));

    const memberRoles = response.data.roles || [];
    const staffRoleId = process.env.DISCORD_STAFF_ROLE_ID;
    const adminRoleId = process.env.DISCORD_ADMIN_ROLE_ID;
    const playerRoleId = process.env.DISCORD_PLAYER_ROLE_ID;

    console.log('[Discord] 📋 User roles:', memberRoles);
    console.log('[Discord] 🎯 Looking for Staff Role:', staffRoleId);
    console.log('[Discord] 🎯 Looking for Admin Role:', adminRoleId);
    console.log('[Discord] 🎯 Looking for Player Role:', playerRoleId);

    const result = {
      hasStaffRole: memberRoles.includes(staffRoleId) || memberRoles.includes(adminRoleId),
      hasPlayerRole: memberRoles.includes(playerRoleId),
      roles: memberRoles
    };

    console.log('[Discord] 🎭 Final result:', result);

    return result;
  } catch (error) {
    console.error('[Discord] ❌ Error checking roles:', error.message);
    console.error('[Discord] 📄 Error details:', error.response?.data || error.response?.status);
    console.error('[Discord] 🔑 Error status:', error.response?.status);
    
    // Si erreur 403, c'est probablement un problème de scope OAuth2
    if (error.response?.status === 403) {
      console.error('[Discord] ⚠️ ERREUR 403: Vérifiez que le scope "guilds.members.read" est activé dans Discord Developer Portal!');
    }
    
    return { hasStaffRole: false, hasPlayerRole: false };
  }
}

// Middleware pour vérifier que l'utilisateur est authentifié via Discord
function requireDiscordAuth(req, res, next) {
  if (!req.isAuthenticated()) {
    // Sauvegarder l'URL demandée pour rediriger après auth
    const returnTo = encodeURIComponent(req.originalUrl);
    
    // Pour les requêtes HTML (navigateur), rediriger vers Discord
    // Pour les requêtes API (AJAX), renvoyer JSON
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ error: 'Not authenticated', redirectTo: `/auth/discord?returnTo=${returnTo}` });
    }
    return res.redirect(`/auth/discord?returnTo=${returnTo}`);
  }
  next();
}

// Middleware pour vérifier le rôle staff
async function requireStaffRole(req, res, next) {
  if (!req.user) {
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return res.redirect('/auth/discord');
  }

  // Utiliser les rôles en cache de la session (mis à jour lors du callback Discord)
  // Revalider les rôles toutes les 5 minutes pour éviter les appels API excessifs
  const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  const now = Date.now();
  const rolesFetchedAt = req.session.rolesFetchedAt || 0;
  const shouldRefreshRoles = !req.session.userRoles || (now - rolesFetchedAt > CACHE_TTL);

  let roles = req.session.userRoles;

  if (shouldRefreshRoles) {
    try {
      roles = await checkDiscordRoles(req.user.id, req.user.accessToken);
      req.session.userRoles = roles;
      req.session.rolesFetchedAt = now;
    } catch (error) {
      console.error('[Staff Auth] Error refreshing roles:', error.message);
      // Si l'API échoue mais qu'on a des rôles en cache, les utiliser
      if (!req.session.userRoles) {
        return res.redirect('/auth/no-role');
      }
      roles = req.session.userRoles;
    }
  }

  if (!roles.hasStaffRole) {
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(403).json({ error: 'Insufficient permissions - Staff role required' });
    }
    return res.redirect('/auth/no-role');
  }

  req.userRoles = roles;
  next();
}

// Middleware pour vérifier le rôle joueur
async function requirePlayerRole(req, res, next) {
  if (!req.user) {
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return res.redirect('/auth/discord');
  }

  // Utiliser les rôles en cache de la session (mis à jour lors du callback Discord)
  // Revalider les rôles toutes les 5 minutes pour éviter les appels API excessifs
  const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  const now = Date.now();
  const rolesFetchedAt = req.session.rolesFetchedAt || 0;
  const shouldRefreshRoles = !req.session.userRoles || (now - rolesFetchedAt > CACHE_TTL);

  let roles = req.session.userRoles;

  if (shouldRefreshRoles) {
    try {
      roles = await checkDiscordRoles(req.user.id, req.user.accessToken);
      req.session.userRoles = roles;
      req.session.rolesFetchedAt = now;
    } catch (error) {
      console.error('[Player Auth] Error refreshing roles:', error.message);
      // Si l'API échoue mais qu'on a des rôles en cache, les utiliser
      if (!req.session.userRoles) {
        return res.redirect('/auth/no-role');
      }
      roles = req.session.userRoles;
    }
  }

  if (!roles.hasPlayerRole) {
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(403).json({ error: 'Insufficient permissions - Player role required' });
    }
    return res.redirect('/auth/no-role');
  }

  req.userRoles = roles;
  next();
}

// Helmet pour headers de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com", "https://www.youtube.com", "https://s.ytimg.com"],
      imgSrc: ["'self'", "data:", "https:", "https://i.ytimg.com"],
      connectSrc: ["'self'", "https://unpkg.com", "https://cdnjs.cloudflare.com", "https://www.youtube.com"],
      fontSrc: ["'self'", "https:", "data:"],
      frameSrc: ["'self'", "https://www.youtube.com", "https://www.youtube-nocookie.com"],
      mediaSrc: ["'self'", "https://www.youtube.com", "https://*.googlevideo.com"],
      childSrc: ["'self'", "https://www.youtube.com"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuré de manière stricte
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  // Ajoutez votre domaine de production ici
];

app.use(cors({
  origin: (origin, callback) => {
    // Autoriser les requêtes sans origin (comme Postman) en développement
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-nightfall-secret']
}));

// Rate limiting global - augmenté pour éviter les erreurs 429
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 1000, // Max 1000 requêtes par minute
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting strict pour le login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 tentatives
  message: { error: 'Too many login attempts, please try again later.' },
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting pour l'API FiveM
const fivemLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // Max 60 updates par minute
  message: { error: 'Too many updates' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', generalLimiter);

app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

// Fonction de validation des erreurs
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Invalid input', details: errors.array() });
  }
  next();
};

// Fonction pour échapper le HTML (protection XSS)
const escapeHtml = (unsafe) => {
  if (typeof unsafe !== 'string') return unsafe;
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// ========== ROUTES API (AVANT express.static) ==========

// ========== ROUTES D'AUTHENTIFICATION DISCORD ==========

// Démarrer l'authentification Discord
app.get('/auth/discord', (req, res, next) => {
  // Utiliser le paramètre state de Discord OAuth2 pour passer le returnTo
  const returnTo = req.query.returnTo || '/';
  console.log('[Auth] 💾 returnTo will be passed in state:', returnTo);
  
  passport.authenticate('discord', {
    state: Buffer.from(JSON.stringify({ returnTo })).toString('base64')
  })(req, res, next);
});

// Callback après authentification Discord
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/auth/failed' }),
  async (req, res) => {
    try {
      const roles = await checkDiscordRoles(req.user.id, req.user.accessToken);
      
      // ⚠️ IMPORTANT: Stocker les rôles dans la session pour éviter les appels API répétés
      req.session.userRoles = roles;
      req.session.rolesFetchedAt = Date.now();
      
      console.log('[Auth] 💾 Saving session before redirect...');
      
      // 🔥 CRITIQUE : Sauvegarder la session AVANT de rediriger !
      req.session.save((err) => {
        if (err) {
          console.error('[Auth] ❌ Session save error:', err);
          return res.redirect('/auth/failed');
        }
        
        console.log('[Auth] ✅ Session saved successfully!');
        
        // Récupérer le returnTo depuis le state OAuth2
        let returnTo = '/';
        try {
          if (req.query.state) {
            const stateData = JSON.parse(Buffer.from(req.query.state, 'base64').toString());
            returnTo = stateData.returnTo || '/';
          }
        } catch (e) {
          console.error('[Auth] Error parsing state:', e);
        }
        
        console.log('[Auth] 🔍 returnTo from state:', returnTo);
        
        // Rediriger vers returnTo
        if (returnTo && returnTo !== '/') {
          console.log('[Auth] 🎯 Redirecting to returnTo:', returnTo);
          return res.redirect(returnTo);
        }
        
        // Sinon, redirection par défaut selon les rôles
        if (roles.hasStaffRole && !roles.hasPlayerRole) {
          console.log('[Auth] 🎯 Staff only -> /staff');
          res.redirect('/staff');
        } else if (roles.hasPlayerRole && !roles.hasStaffRole) {
          console.log('[Auth] 🎯 Player only -> /player');
          res.redirect('/player');
        } else if (roles.hasStaffRole && roles.hasPlayerRole) {
          // Si les deux rôles, aller sur la page d'accueil pour choisir
          console.log('[Auth] 🎯 Both roles -> home');
          res.redirect('/');
        } else {
          console.log('[Auth] ⚠️ No role -> /auth/no-role');
          res.redirect('/auth/no-role');
        }
      });
    } catch (error) {
      console.error('[Auth] Error checking roles:', error);
      res.redirect('/auth/failed');
    }
  }
);

// Route pour vérifier l'état d'authentification
app.get('/api/auth/status', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.json({ authenticated: false });
  }

  res.json({
    authenticated: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      discriminator: req.user.discriminator,
      avatar: req.user.avatar
    }
  });
});

// Déconnexion
app.get('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.redirect('/');
  });
});

// Page d'échec d'authentification
app.get('/auth/failed', (req, res) => {
  res.status(401).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authentification échouée</title>
      <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: #fff; }
        .error { background: #ff4444; padding: 20px; border-radius: 10px; display: inline-block; }
        a { color: #4dabf7; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="error">
        <h1>❌ Authentification échouée</h1>
        <p>Une erreur s'est produite lors de la connexion avec Discord.</p>
        <p><a href="/">← Retour à l'accueil</a></p>
      </div>
    </body>
    </html>
  `);
});

// Page pas de rôle
app.get('/auth/no-role', (req, res) => {
  res.status(403).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Accès refusé</title>
      <style>
        body { font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: #fff; }
        .warning { background: #ff9800; padding: 20px; border-radius: 10px; display: inline-block; }
        a { color: #4dabf7; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="warning">
        <h1>⚠️ Accès refusé</h1>
        <p>Vous n'avez pas les rôles Discord requis pour accéder à cette page.</p>
        <p>Contactez un administrateur pour obtenir l'accès.</p>
        <p><a href="/">← Retour à l'accueil</a> | <a href="/auth/logout">Se déconnecter</a></p>
      </div>
    </body>
    </html>
  `);
});

// ========== ROUTES PUBLIQUES ==========

// Simple health
app.get('/api/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Public status (proxy côté serveur pour éviter CORS + statut réel FiveM)
app.get('/api/status', async (_req, res) => {
  try {
    const cfg = loadStatusConfig();
    const base = normalizeBaseUrl(cfg.serverIp);

    let isOnline = false;
    let playersOnline = 0;
    let avgPing = 0;
    let uptime = 0;

    if (base) {
      try {
        const dynamic = await fetchJsonWithTimeout(`${base}/dynamic.json`, 8000);
        const players = await fetchJsonWithTimeout(`${base}/players.json`, 8000);
        const info = await fetchJsonWithTimeout(`${base}/info.json`, 8000);

        // Si dynamic OU players répond (même vide), le serveur est online
        if (dynamic || players !== null) isOnline = true;
        if (Array.isArray(players)) {
          playersOnline = players.length;
          // Calculer le ping moyen
          if (players.length > 0) {
            const totalPing = players.reduce((sum, p) => sum + (p.ping || 0), 0);
            avgPing = Math.round(totalPing / players.length);
          }
        }
        else if (dynamic && typeof dynamic.clients === 'number') playersOnline = dynamic.clients;

        // Récupérer l'uptime depuis info.json si disponible
        if (info && info.vars && info.vars.uptime) {
          uptime = Math.floor(info.vars.uptime / 60); // Convertir en minutes
        }
      } catch (err) {
        console.error('[FiveM check] Error:', err.message);
      }
    }

    const displayIp = cfg.serverIp || '';

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      isOnline,
      playersOnline,
      serverIp: displayIp,
      discordInvite: cfg.discordInvite || '',
      avgPing: avgPing,
      uptime: uptime
    });
  } catch (err) {
    console.error('[API Status] Error:', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

// Staff login - SÉCURISÉ avec rate limiting et validation
app.post('/api/staff/login',
  loginLimiter,
  [
    body('password').isString().trim().notEmpty().withMessage('Password is required')
  ],
  handleValidationErrors,
  (req, res) => {
    config = loadConfig();
    const pw = String(req.body?.password || '');
    
    // Vérifier que le mot de passe est configuré
    if (!config.staffPassword) {
      console.error('[Security] STAFF_PASSWORD not configured in .env');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    
    // Vérifier le mot de passe
    if (pw !== config.staffPassword) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const token = makeToken();
    tokens.set(token, { expiresAt: Date.now() + TOKEN_TTL_MS });
    
    res.json({ token });
  }
);

// API publique pour les véhicules
app.get('/api/vehicles', (_req, res) => {
  try {
    const vehiclesPath = path.join(ROOT, 'api', 'vehicles', 'config_vehicles.json');
    const raw = fs.readFileSync(vehiclesPath, 'utf8');
    const vehicles = JSON.parse(raw);
    res.json({ vehicles });
  } catch (err) {
    console.error('[API Vehicles] Error:', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

// ========== ROUTES STAFF (Protection Discord Staff) ==========

// Staff: get players (nécessite rôle staff)
app.get('/api/staff/players', requireDiscordAuth, requireStaffRole, (_req, res) => {
  res.json({
    updatedAt: latest.updatedAt,
    server: latest.server,
    players: latest.players
  });
});

// Staff: search all players (nécessite rôle staff) - Utilise le cache FiveM
app.get('/api/staff/search',
  requireDiscordAuth,
  requireStaffRole,
  [
    query('q').optional().isString().trim().isLength({ max: 100 }),
    query('limit').optional().isInt({ min: 1, max: 200 })
  ],
  handleValidationErrors,
  (req, res) => {
    try {
      const query = String(req.query.q || '').trim().toLowerCase();
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);

      let players = latest.players.filter(p => p.citizenid); // Uniquement les joueurs avec personnage

      // Filtrer par query si présente
      if (query) {
        players = players.filter(p => {
          const charinfo = p.charinfo || {};
          const firstname = (charinfo.firstname || '').toLowerCase();
          const lastname = (charinfo.lastname || '').toLowerCase();
          const citizenid = (p.citizenid || '').toLowerCase();
          const phone = (charinfo.phone || '').toLowerCase();
          
          return firstname.includes(query) || 
                 lastname.includes(query) || 
                 citizenid.includes(query) || 
                 phone.includes(query);
        });
      }

      // Limiter le nombre de résultats
      players = players.slice(0, limit);

      const formattedPlayers = players.map(p => ({
        citizenid: escapeHtml(p.citizenid),
        firstname: escapeHtml(p.charinfo.firstname || 'Unknown'),
        lastname: escapeHtml(p.charinfo.lastname || 'Player'),
        phone: escapeHtml(p.charinfo.phone || 'N/A'),
        job: {
          name: escapeHtml(p.jobData?.name || p.job || 'unemployed'),
          label: escapeHtml(p.jobData?.label || 'Unemployed'),
          grade: escapeHtml(p.jobData?.grade?.name || p.jobGrade || '0')
        },
        money: {
          cash: parseInt(p.money?.cash) || 0,
          bank: parseInt(p.money?.bank) || 0
        },
        lastUpdated: latest.updatedAt
      }));

      res.json({ players: formattedPlayers, count: formattedPlayers.length });
    } catch (err) {
      console.error('[API Search] Error:', err.message);
      res.status(500).json({ error: 'Search error' });
    }
  }
);

// Staff: search ALL players from database (nécessite rôle staff) - Requête vers FiveM bridge
app.get('/api/staff/search-db',
  requireDiscordAuth,
  requireStaffRole,
  [
    query('q').optional().isString().trim().isLength({ max: 100 }),
    query('limit').optional().isInt({ min: 1, max: 200 })
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const fivemServerIp = config.fivemServerIp;
      
      if (!fivemServerIp || !config.fivemSecret) {
        return res.status(503).json({
          error: 'FiveM server not configured',
          message: 'Le serveur FiveM n\'est pas configuré. Contacte un administrateur.'
        });
      }

      const fivemUrl = `http://${fivemServerIp}/all-players`;
      
      console.log('[API Search DB] Fetching all players from FiveM...');
      
      const response = await axios.get(fivemUrl, {
        headers: {
          'x-nightfall-secret': config.fivemSecret
        },
        timeout: 10000
      });

      console.log('[API Search DB] Response:', JSON.stringify(response.data).substring(0, 200));
      let players = response.data.players || [];
      
      console.log(`[API Search DB] Received ${players.length} players from FiveM`);
      if (players.length > 0) {
        console.log('[API Search DB] First player sample:', JSON.stringify(players[0]));
      }
      
      // Filtrer par query si présente
      const queryStr = String(req.query.q || '').trim().toLowerCase();
      if (queryStr) {
        players = players.filter(p => {
          const firstname = (p.firstname || '').toLowerCase();
          const lastname = (p.lastname || '').toLowerCase();
          const citizenid = (p.citizenid || '').toLowerCase();
          const phone = (p.phone || '').toLowerCase();
          
          return firstname.includes(queryStr) || 
                 lastname.includes(queryStr) || 
                 citizenid.includes(queryStr) || 
                 phone.includes(queryStr);
        });
      }
      
      // Limiter le nombre de résultats
      const limit = Math.min(parseInt(req.query.limit) || 100, 200);
      players = players.slice(0, limit);

      const formattedPlayers = players.map(p => ({
        citizenid: escapeHtml(p.citizenid),
        firstname: escapeHtml(p.firstname || 'Unknown'),
        lastname: escapeHtml(p.lastname || 'Player'),
        phone: escapeHtml(p.phone || 'N/A'),
        birthdate: escapeHtml(p.birthdate || 'N/A'),
        gender: parseInt(p.gender) || 0,
        job: {
          name: escapeHtml(p.job?.name || 'unemployed'),
          label: escapeHtml(p.job?.label || 'Sans emploi'),
          grade: escapeHtml(p.job?.grade?.name || '0')
        },
        money: {
          cash: parseInt(p.money?.cash) || 0,
          bank: parseInt(p.money?.bank) || 0
        },
        last_updated: p.last_updated
      }));

      res.json({ players: formattedPlayers, count: formattedPlayers.length, source: 'database' });
    } catch (err) {
      console.error('[API Search DB] Error:', err.message);
      res.status(500).json({ error: 'Database search error', message: err.message });
    }
  }
);

// Staff: get specific player details (nécessite rôle staff) - Utilise le cache FiveM
app.get('/api/staff/player/:citizenid',
  requireDiscordAuth,
  requireStaffRole,
  [
    param('citizenid').isString().trim().isLength({ min: 1, max: 50 })
  ],
  handleValidationErrors,
  (req, res) => {
    try {
      const citizenid = req.params.citizenid;

      // Chercher le joueur dans le cache
      const player = latest.players.find(p => p.citizenid === citizenid);

      if (!player) {
        return res.status(404).json({ 
          error: 'Player not found',
          message: 'Le joueur doit être connecté au serveur FiveM pour afficher ses données.'
        });
      }

      res.json({
        citizenid: escapeHtml(player.citizenid),
        name: escapeHtml(player.name),
        charinfo: player.charinfo || {},
        job: player.jobData || { name: 'unemployed', label: 'Unemployed', grade: { name: '0', level: 0 } },
        money: player.money || { cash: 0, bank: 0 },
        position: player.position || { x: 0, y: 0, z: 0 },
        vehicles: player.vehicles || [],
        lastUpdated: latest.updatedAt,
        source: 'cache'
      });
    } catch (err) {
      console.error('[API Player] Error:', err.message);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// FiveM ingest endpoint (outgoing HTTP from server -> here) - SÉCURISÉ
app.post('/api/fivem/players',
  fivemLimiter,
  [
    body('serverName').optional().isString().trim().isLength({ max: 100 }),
    body('serverId').optional().isString().trim().isLength({ max: 100 }),
    body('players').optional().isArray({ max: 256 })
  ],
  handleValidationErrors,
  (req, res) => {
    config = loadConfig();
    const secret = req.get('x-nightfall-secret') || '';
    
    // Vérifier que le secret est configuré
    if (!config.fivemSecret) {
      console.error('[Security] FIVEM_SECRET not configured in .env');
      return res.status(500).json({ error: 'Server configuration error' });
    }
    
    // Vérifier le secret
    if (secret !== config.fivemSecret) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const body = req.body || {};
    const players = Array.isArray(body.players) ? body.players : [];

    latest = {
      updatedAt: Date.now(),
      server: {
        name: escapeHtml(String(body.serverName || 'Nightfall RP')),
        id: escapeHtml(String(body.serverId || 'fivem'))
      },
      players: players
        .map(p => ({
          // Données de base pour la map
          id: p.id,
          name: escapeHtml(String(p.name || 'Joueur')),
          job: p.job ? escapeHtml(String(p.job)) : undefined,
          jobGrade: p.jobGrade !== undefined && p.jobGrade !== null ? escapeHtml(String(p.jobGrade)) : undefined,
          ping: typeof p.ping === 'number' ? Math.max(0, Math.min(9999, p.ping)) : undefined,
          x: typeof p.x === 'number' ? p.x : 0,
          y: typeof p.y === 'number' ? p.y : 0,
          z: typeof p.z === 'number' ? p.z : 0,
          
          // Données complètes pour le profil joueur
          discordId: p.discordId || null,
          citizenid: p.citizenid || null,
          charinfo: p.charinfo || { firstname: "Unknown", lastname: "Player", phone: "N/A", birthdate: "N/A" },
          jobData: p.job ? {
            name: p.job,
            label: p.job.charAt(0).toUpperCase() + p.job.slice(1),
            grade: {
              name: p.jobGrade || "0",
              level: 0
            }
          } : undefined,
          money: p.money || { cash: 0, bank: 0 },
          position: p.position || { x: p.x || 0, y: p.y || 0, z: p.z || 0 },
          vehicles: p.vehicles || []
        }))
        .slice(0, 256)
    };

    res.json({ ok: true, count: latest.players.length });
  }
);

// ========== PROTECTION DES PAGES STAFF & PLAYER ==========

// Protéger la page staff avec authentification Discord + rôle staff
app.get('/staff', requireDiscordAuth, requireStaffRole, (req, res) => {
  res.sendFile(path.join(ROOT, 'staff', 'index.html'));
});

// Servir les fichiers statiques du dossier staff (CSS, JS, etc.) - AVANT la route générique
app.use('/staff', requireDiscordAuth, requireStaffRole, express.static(path.join(ROOT, 'staff')));

// Protéger la page player avec authentification Discord + rôle player
app.get('/player', requireDiscordAuth, requirePlayerRole, (req, res) => {
  res.sendFile(path.join(ROOT, 'player', 'index.html'));
});

app.get('/player/*', requireDiscordAuth, requirePlayerRole, (req, res, next) => {
  // Servir les fichiers statiques du dossier player (CSS, JS, etc.)
  express.static(path.join(ROOT, 'player'))(req, res, next);
});

// ========== EXPRESS STATIC (APRÈS les routes API) ==========

// Serve static site with no-cache for CSS/JS to force refresh
app.use(express.static(ROOT, {
  extensions: ['html'],
  setHeaders: (res, path) => {
    if (path.endsWith('.css') || path.endsWith('.js')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// Mock generator (local demo): if no FiveM data incoming, we move fake players.
function tickMock() {
  const now = Date.now();
  const tooOld = now - latest.updatedAt > 10_000;
  if (!tooOld) return;

  const base = now / 1000;
  const players = [];
  const count = 12;

  for (let i = 1; i <= count; i++) {
    const t = base * 0.25 + i;
    const x = -1200 + Math.cos(t) * (900 + i * 22);
    const y = 800 + Math.sin(t * 1.1) * (700 + i * 18);
    const z = 30;
    players.push({
      id: i,
      name: `Player_${String(i).padStart(2, '0')}`,
      job: i % 3 === 0 ? 'LSPD' : i % 3 === 1 ? 'EMS' : 'Civil',
      jobGrade: i % 3 === 0 ? 'Officer' : i % 3 === 1 ? 'Paramedic' : '—',
      ping: 25 + (i * 3) % 60,
      x,
      y,
      z
    });
  }

  latest = {
    updatedAt: now,
    server: { name: 'Nightfall RP (mock)', id: 'local' },
    players
  };
}
// setInterval(tickMock, 750); // DÉSACTIVÉ: on attend les données FiveM réelles

// ========== ROUTES JOUEUR (Protection Discord Joueur) ==========

// Récupérer les données du joueur connecté
app.get('/api/player/me', requireDiscordAuth, requirePlayerRole, async (req, res) => {
  try {
    const discordId = req.user.id;
    console.log('[API Player] Fetching profile for Discord ID:', discordId);

    // STRATÉGIE 1 : Chercher dans le cache (joueur connecté)
    const player = latest.players.find(p => p.discordId === discordId);

    if (player && player.citizenid) {
      console.log('[API Player] ✅ Found in cache (online):', player.citizenid);
      
      const charinfo = player.charinfo || { firstname: "Unknown", lastname: "Player", phone: "N/A", birthdate: "N/A" };
      const jobData = player.jobData || { name: "unemployed", label: "Unemployed", grade: { name: "0", level: 0 } };
      const money = player.money || { cash: 0, bank: 0 };
      const position = player.position || { x: 0, y: 0, z: 0 };
      const vehicles = player.vehicles || [];

      return res.json({
        citizenid: escapeHtml(player.citizenid),
        charinfo: {
          firstname: escapeHtml(charinfo.firstname || "Unknown"),
          lastname: escapeHtml(charinfo.lastname || "Player"),
          phone: escapeHtml(charinfo.phone || "N/A"),
          birthdate: escapeHtml(charinfo.birthdate || "N/A"),
          gender: parseInt(charinfo.gender) || 0
        },
        job: {
          name: escapeHtml(jobData.name || "unemployed"),
          label: escapeHtml(jobData.label || "Unemployed"),
          grade: {
            name: escapeHtml(jobData.grade?.name || "0"),
            level: parseInt(jobData.grade?.level) || 0
          }
        },
        money: {
          cash: parseInt(money.cash) || 0,
          bank: parseInt(money.bank) || 0
        },
        metadata: {
          hunger: player.metadata?.hunger !== undefined ? player.metadata.hunger : 100,
          thirst: player.metadata?.thirst !== undefined ? player.metadata.thirst : 100,
          stress: player.metadata?.stress !== undefined ? player.metadata.stress : 0,
          health: player.metadata?.health !== undefined ? player.metadata.health : 200,
          maxHealth: player.metadata?.maxHealth !== undefined ? player.metadata.maxHealth : 200,
          armor: player.metadata?.armor !== undefined ? player.metadata.armor : 0,
          isdead: player.metadata?.isdead || false,
          inlaststand: player.metadata?.inlaststand || false
        },
        position: position,
        vehicles: vehicles.map(v => ({
          vehicle: escapeHtml(v.vehicle || "unknown"),
          plate: escapeHtml(v.plate || "N/A"),
          state: parseInt(v.state) || 0,
          engine: parseFloat(v.engine) || 1000.0,
          body: parseFloat(v.body) || 1000.0
        })),
        lastUpdated: latest.updatedAt,
        source: 'cache',
        online: true
      });
    }

    // STRATÉGIE 2 : Interroger le serveur FiveM via HTTP (joueur hors ligne)
    console.log('[API Player] Not in cache, querying FiveM server...');
    
    const fivemServerIp = process.env.FIVEM_SERVER_IP || '';
    if (!fivemServerIp) {
      console.error('[API Player] FIVEM_SERVER_IP not configured');
      return res.status(503).json({ 
        error: 'FiveM server not configured',
        message: 'Le serveur FiveM n\'est pas configuré. Contacte un administrateur.'
      });
    }

    const fivemUrl = `http://${fivemServerIp}/player?discordId=${encodeURIComponent(discordId)}`;
    console.log('[API Player] 🔍 Full URL:', fivemUrl);
    console.log('[API Player] 🔑 Secret header:', config.fivemSecret.substring(0, 10) + '...');
    
    try {
      const response = await axios.get(fivemUrl, {
        headers: {
          'x-nightfall-secret': config.fivemSecret
        },
        timeout: 5000
      });

      const data = response.data;
      
      if (data.error) {
        console.log('[API Player] FiveM returned error:', data.error);
        return res.status(404).json({ 
          error: 'No character found',
          message: 'Aucun personnage trouvé. Crée un personnage sur le serveur FiveM pour voir ton profil.'
        });
      }

      console.log('[API Player] ✅ Found in database (offline):', data.citizenid);

      // Parser les données
      const charinfo = data.charinfo || {};
      const job = data.job || {};
      const money = data.money || {};
      const position = data.position || {};
      const metadata = data.metadata || {};
      const vehicles = data.vehicles || [];

      res.json({
        citizenid: escapeHtml(data.citizenid),
        charinfo: {
          firstname: escapeHtml(charinfo.firstname || "Unknown"),
          lastname: escapeHtml(charinfo.lastname || "Player"),
          phone: escapeHtml(charinfo.phone || "N/A"),
          birthdate: escapeHtml(charinfo.birthdate || "N/A"),
          gender: parseInt(charinfo.gender) || 0
        },
        job: {
          name: escapeHtml(job.name || "unemployed"),
          label: escapeHtml(job.label || "Unemployed"),
          grade: {
            name: escapeHtml(job.grade?.name || "0"),
            level: parseInt(job.grade?.level) || 0
          }
        },
        money: {
          cash: parseInt(money.cash) || 0,
          bank: parseInt(money.bank) || 0
        },
        metadata: {
          hunger: metadata.hunger !== undefined ? parseFloat(metadata.hunger) : 100,
          thirst: metadata.thirst !== undefined ? parseFloat(metadata.thirst) : 100,
          stress: metadata.stress !== undefined ? parseFloat(metadata.stress) : 0,
          health: metadata.health !== undefined ? parseInt(metadata.health) : 200,
          maxHealth: metadata.maxHealth !== undefined ? parseInt(metadata.maxHealth) : 200,
          armor: metadata.armor !== undefined ? parseInt(metadata.armor) : 0,
          isdead: Boolean(metadata.isdead),
          inlaststand: Boolean(metadata.inlaststand)
        },
        position: position,
        vehicles: vehicles.map(v => ({
          vehicle: escapeHtml(v.vehicle || "unknown"),
          plate: escapeHtml(v.plate || "N/A"),
          state: parseInt(v.state) || 0,
          engine: parseFloat(v.engine) || 1000.0,
          body: parseFloat(v.body) || 1000.0
        })),
        lastUpdated: data.lastUpdated,
        source: 'database',
        online: false
      });
    } catch (fivemError) {
      console.error('[API Player] FiveM query failed:', fivemError.message);
      console.error('[API Player] 🚨 Error details:', {
        code: fivemError.code,
        status: fivemError.response?.status,
        statusText: fivemError.response?.statusText,
        data: fivemError.response?.data,
        url: fivemUrl
      });
      
      if (fivemError.code === 'ECONNREFUSED' || fivemError.code === 'ETIMEDOUT') {
        return res.status(503).json({ 
          error: 'FiveM server unavailable',
          message: 'Le serveur FiveM est hors ligne. Réessaye plus tard.'
        });
      }

      return res.status(404).json({ 
        error: 'No character found',
        message: 'Aucun personnage trouvé. Crée un personnage sur le serveur FiveM.'
      });
    }
  } catch (err) {
    console.error('[API Player] ❌ ERROR:', err.message);
    console.error('[API Player] Stack:', err.stack);
    res.status(500).json({ 
      error: 'Server error', 
      message: 'Une erreur est survenue lors de la récupération de ton profil.'
    });
  }
});

app.listen(PORT, () => {
  console.log(`[Server] 🚀 Started on port ${PORT}`);
  console.log(`[Server] 🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`[Server] 💾 Data Source: FiveM Bridge (Cache)`);
});
