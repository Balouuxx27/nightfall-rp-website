require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const mysql = require('mysql2/promise');
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

// MySQL connection pool (optional, only if DB credentials are provided)
let dbPool = null;
try {
  const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'qbcore',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  };
  
  // Only create pool if password is provided (means DB is configured)
  if (dbConfig.password) {
    dbPool = mysql.createPool(dbConfig);
  }
} catch (err) {
  console.error('[MySQL] Error creating pool:', err.message);
}

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

// Sessions (requis pour Passport Discord)
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-please-set-SESSION_SECRET',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Initialiser Passport
app.use(passport.initialize());
app.use(passport.session());

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
        profile.accessToken = accessToken;
        return done(null, profile);
      } catch (error) {
        return done(error, null);
      }
    }
  ));

  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((obj, done) => {
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

    // Récupérer les rôles du membre via l'API Discord
    const response = await axios.get(
      `https://discord.com/api/v10/users/@me/guilds/${guildId}/member`,
      {
        headers: { Authorization: `Bearer ${accessToken}` }
      }
    );

    const memberRoles = response.data.roles || [];
    const staffRoleId = process.env.DISCORD_STAFF_ROLE_ID;
    const playerRoleId = process.env.DISCORD_PLAYER_ROLE_ID;

    return {
      hasStaffRole: staffRoleId ? memberRoles.includes(staffRoleId) : false,
      hasPlayerRole: playerRoleId ? memberRoles.includes(playerRoleId) : false,
      roles: memberRoles
    };
  } catch (error) {
    console.error('[Discord] Error checking roles:', error.message);
    return { hasStaffRole: false, hasPlayerRole: false };
  }
}

// Middleware pour vérifier que l'utilisateur est authentifié via Discord
function requireDiscordAuth(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated', redirectTo: '/auth/discord' });
  }
  next();
}

// Middleware pour vérifier le rôle staff
async function requireStaffRole(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const roles = await checkDiscordRoles(req.user.id, req.user.accessToken);
  if (!roles.hasStaffRole) {
    return res.status(403).json({ error: 'Insufficient permissions - Staff role required' });
  }

  req.userRoles = roles;
  next();
}

// Middleware pour vérifier le rôle joueur
async function requirePlayerRole(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const roles = await checkDiscordRoles(req.user.id, req.user.accessToken);
  if (!roles.hasPlayerRole && !roles.hasStaffRole) {
    return res.status(403).json({ error: 'Insufficient permissions - Player role required' });
  }

  req.userRoles = roles;
  next();
}

// Helmet pour headers de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https:", "data:"],
      frameSrc: ["'self'", "https://www.youtube.com"],
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

// Rate limiting global
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requêtes par IP
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
app.get('/auth/discord', passport.authenticate('discord'));

// Callback après authentification Discord
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/auth/failed' }),
  async (req, res) => {
    try {
      const roles = await checkDiscordRoles(req.user.id, req.user.accessToken);
      
      // Redirection selon le rôle
      if (roles.hasStaffRole) {
        res.redirect('/staff');
      } else if (roles.hasPlayerRole) {
        res.redirect('/player');
      } else {
        res.redirect('/auth/no-role');
      }
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

// Staff: search all players in database (nécessite rôle staff) - SÉCURISÉ contre SQL injection
app.get('/api/staff/search',
  requireDiscordAuth,
  requireStaffRole,
  [
    query('q').optional().isString().trim().isLength({ max: 100 }),
    query('limit').optional().isInt({ min: 1, max: 200 })
  ],
  handleValidationErrors,
  async (req, res) => {
    if (!dbPool) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    try {
      const query = String(req.query.q || '').trim();
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);

      let sql = `
        SELECT 
          citizenid,
          JSON_UNQUOTE(JSON_EXTRACT(charinfo, '$.firstname')) as firstname,
          JSON_UNQUOTE(JSON_EXTRACT(charinfo, '$.lastname')) as lastname,
          JSON_UNQUOTE(JSON_EXTRACT(charinfo, '$.phone')) as phone,
          JSON_UNQUOTE(JSON_EXTRACT(job, '$.name')) as job_name,
          JSON_UNQUOTE(JSON_EXTRACT(job, '$.label')) as job_label,
          JSON_UNQUOTE(JSON_EXTRACT(job, '$.grade.name')) as job_grade,
          JSON_UNQUOTE(JSON_EXTRACT(money, '$.cash')) as cash,
          JSON_UNQUOTE(JSON_EXTRACT(money, '$.bank')) as bank,
          last_updated
        FROM players
      `;

      const params = [];

      if (query) {
        // ⚠️ SÉCURITÉ: Utilisation de paramètres préparés pour éviter l'injection SQL
        sql += ` WHERE 
          citizenid LIKE ? OR
          JSON_EXTRACT(charinfo, '$.firstname') LIKE ? OR
          JSON_EXTRACT(charinfo, '$.lastname') LIKE ? OR
          JSON_EXTRACT(charinfo, '$.phone') LIKE ?
        `;
        const searchPattern = `%${query}%`;
        params.push(searchPattern, searchPattern, searchPattern, searchPattern);
      }

      sql += ` ORDER BY last_updated DESC LIMIT ?`;
      params.push(limit);

      const [rows] = await dbPool.query(sql, params);

      const players = rows.map(row => ({
        citizenid: escapeHtml(row.citizenid),
        firstname: escapeHtml(row.firstname),
        lastname: escapeHtml(row.lastname),
        phone: escapeHtml(row.phone),
        job: {
          name: escapeHtml(row.job_name),
          label: escapeHtml(row.job_label),
          grade: escapeHtml(row.job_grade)
        },
        money: {
          cash: parseInt(row.cash) || 0,
          bank: parseInt(row.bank) || 0
        },
        lastUpdated: row.last_updated
      }));

      res.json({ players, count: players.length });
    } catch (err) {
      console.error('[API Search] Error:', err.message);
      res.status(500).json({ error: 'Database error' });
    }
  }
);

// Staff: get specific player details (nécessite rôle staff) - SÉCURISÉ
app.get('/api/staff/player/:citizenid',
  requireDiscordAuth,
  requireStaffRole,
  [
    param('citizenid').isString().trim().isLength({ min: 1, max: 50 })
  ],
  handleValidationErrors,
  async (req, res) => {
    if (!dbPool) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    try {
      const citizenid = req.params.citizenid;

      // ⚠️ SÉCURITÉ: Requête préparée pour éviter l'injection SQL
      const [rows] = await dbPool.query(
        'SELECT * FROM players WHERE citizenid = ? LIMIT 1',
        [citizenid]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: 'Player not found' });
      }

      const player = rows[0];
      
      // Parse JSON fields avec protection
      let charinfo = {};
      let job = {};
      let money = {};
      let metadata = {};
      
      try {
        charinfo = JSON.parse(player.charinfo || '{}');
        job = JSON.parse(player.job || '{}');
        money = JSON.parse(player.money || '{}');
        metadata = JSON.parse(player.metadata || '{}');
      } catch (e) {
        console.error('[API Player] JSON parse error:', e.message);
      }

      res.json({
        citizenid: escapeHtml(player.citizenid),
        license: escapeHtml(player.license),
        name: escapeHtml(player.name),
        charinfo: charinfo,
        job: job,
        money: money,
        metadata: metadata,
        position: JSON.parse(player.position || '{}'),
        last_updated: player.last_updated
      });
    } catch (err) {
      console.error('[API Player] Error:', err.message);
      res.status(500).json({ error: 'Database error' });
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
          id: p.id,
          name: escapeHtml(String(p.name || 'Joueur')),
          job: p.job ? escapeHtml(String(p.job)) : undefined,
          jobGrade: p.jobGrade !== undefined && p.jobGrade !== null ? escapeHtml(String(p.jobGrade)) : undefined,
          ping: typeof p.ping === 'number' ? Math.max(0, Math.min(9999, p.ping)) : undefined,
          x: typeof p.x === 'number' ? p.x : 0,
          y: typeof p.y === 'number' ? p.y : 0,
          z: typeof p.z === 'number' ? p.z : 0
        }))
        .slice(0, 256)
    };

    res.json({ ok: true, count: latest.players.length });
  }
);

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
  if (!dbPool) {
    return res.status(503).json({ error: 'Database not configured' });
  }

  try {
    const discordId = req.user.id;

    // Chercher le joueur par Discord ID (nécessite une colonne discord_id dans la table players)
    // Pour l'instant, on cherche par le premier joueur trouvé (à adapter selon votre structure)
    const [rows] = await dbPool.query(`
      SELECT 
        citizenid,
        charinfo,
        job,
        money,
        position,
        last_updated,
        discord_id
      FROM players
      WHERE discord_id = ?
      LIMIT 1
    `, [discordId]);

    if (rows.length === 0) {
      return res.status(404).json({ 
        error: 'No character found',
        message: 'Connectez-vous au serveur FiveM pour créer un personnage'
      });
    }

    const row = rows[0];
    
    // Parser JSON
    const charinfo = typeof row.charinfo === 'string' ? JSON.parse(row.charinfo) : row.charinfo;
    const job = typeof row.job === 'string' ? JSON.parse(row.job) : row.job;
    const money = typeof row.money === 'string' ? JSON.parse(row.money) : row.money;
    const position = typeof row.position === 'string' ? JSON.parse(row.position) : row.position;

    // Récupérer les véhicules du joueur
    const [vehicles] = await dbPool.query(`
      SELECT vehicle, plate, state, engine, body
      FROM player_vehicles
      WHERE citizenid = ?
      ORDER BY vehicle ASC
    `, [row.citizenid]);

    res.json({
      citizenid: escapeHtml(row.citizenid),
      charinfo: {
        firstname: escapeHtml(charinfo.firstname),
        lastname: escapeHtml(charinfo.lastname),
        phone: escapeHtml(charinfo.phone),
        birthdate: escapeHtml(charinfo.birthdate)
      },
      job: {
        name: escapeHtml(job.name),
        label: escapeHtml(job.label),
        grade: {
          name: escapeHtml(job.grade?.name),
          level: parseInt(job.grade?.level) || 0
        }
      },
      money: {
        cash: parseInt(money.cash) || 0,
        bank: parseInt(money.bank) || 0
      },
      position: position,
      vehicles: vehicles.map(v => ({
        vehicle: escapeHtml(v.vehicle),
        plate: escapeHtml(v.plate),
        state: parseInt(v.state) || 0,
        engine: parseFloat(v.engine) || 1000.0,
        body: parseFloat(v.body) || 1000.0
      })),
      lastUpdated: row.last_updated
    });
  } catch (err) {
    console.error('[API Player] Error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

app.listen(PORT, () => {
  console.log(`[Server] Started on port ${PORT}`);
});
