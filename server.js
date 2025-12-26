require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const mysql = require('mysql2/promise');

const express = require('express');

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
  try {
    const raw = fs.readFileSync(CFG_PATH, 'utf8');
    const j = JSON.parse(raw);
    return {
      staffPassword: String(process.env.STAFF_PASSWORD || j.staffPassword || ''),
      fivemSecret: String(process.env.FIVEM_SECRET || j.fivemSecret || '')
    };
  } catch {
    return {
      staffPassword: String(process.env.STAFF_PASSWORD || ''),
      fivemSecret: String(process.env.FIVEM_SECRET || '')
    };
  }
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
    console.log('[MySQL] Connection pool created');
  } else {
    console.log('[MySQL] No database configured (DB_PASSWORD not set)');
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

app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

// ========== ROUTES API (AVANT express.static) ==========

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
        const dynamic = await fetchJsonWithTimeout(`${base}/dynamic.json`, 3000);
        const players = await fetchJsonWithTimeout(`${base}/players.json`, 3000);
        const info = await fetchJsonWithTimeout(`${base}/info.json`, 3000);

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

// Staff login
app.post('/api/staff/login', (req, res) => {
  config = loadConfig();
  const pw = String(req.body?.password || '');
  if (!config.staffPassword || pw !== config.staffPassword) return res.status(403).json({ error: 'forbidden' });

  const token = makeToken();
  tokens.set(token, { expiresAt: Date.now() + TOKEN_TTL_MS });
  res.json({ token });
});

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

// Staff: get players
app.get('/api/staff/players', authMiddleware, (_req, res) => {
  res.json({
    updatedAt: latest.updatedAt,
    server: latest.server,
    players: latest.players
  });
});

// Staff: search all players in database
app.get('/api/staff/search', authMiddleware, async (req, res) => {
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
      citizenid: row.citizenid,
      firstname: row.firstname,
      lastname: row.lastname,
      phone: row.phone,
      job: {
        name: row.job_name,
        label: row.job_label,
        grade: row.job_grade
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
});

// Staff: get specific player details
app.get('/api/staff/player/:citizenid', authMiddleware, async (req, res) => {
  if (!dbPool) {
    return res.status(503).json({ error: 'Database not configured' });
  }

  try {
    const citizenid = req.params.citizenid;

    const [rows] = await dbPool.query(
      'SELECT * FROM players WHERE citizenid = ? LIMIT 1',
      [citizenid]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Player not found' });
    }

    const player = rows[0];
    
    // Parse JSON fields
    const charinfo = JSON.parse(player.charinfo || '{}');
    const job = JSON.parse(player.job || '{}');
    const money = JSON.parse(player.money || '{}');
    const metadata = JSON.parse(player.metadata || '{}');

    res.json({
      citizenid: player.citizenid,
      license: player.license,
      name: player.name,
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
});

// FiveM ingest endpoint (outgoing HTTP from server -> here)
app.post('/api/fivem/players', (req, res) => {
  config = loadConfig();
  const secret = req.get('x-nightfall-secret') || '';
  if (!config.fivemSecret || secret !== config.fivemSecret) return res.status(403).json({ error: 'forbidden' });

  const body = req.body || {};
  const players = Array.isArray(body.players) ? body.players : [];

  latest = {
    updatedAt: Date.now(),
    server: {
      name: String(body.serverName || 'Nightfall RP'),
      id: String(body.serverId || 'fivem')
    },
    players: players
      .map(p => ({
        id: p.id,
        name: String(p.name || 'Joueur'),
        job: p.job ? String(p.job) : undefined,
        jobGrade: p.jobGrade !== undefined && p.jobGrade !== null ? String(p.jobGrade) : undefined,
        ping: typeof p.ping === 'number' ? p.ping : undefined,
        x: typeof p.x === 'number' ? p.x : 0,
        y: typeof p.y === 'number' ? p.y : 0,
        z: typeof p.z === 'number' ? p.z : 0
      }))
      .slice(0, 256)
  };

  res.json({ ok: true, count: latest.players.length });
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

app.listen(PORT, () => {
  console.log(`Nightfall web running on http://localhost:${PORT}`);
  console.log(`Staff panel: http://localhost:${PORT}/staff/`);
});
