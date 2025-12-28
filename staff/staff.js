(() => {
  // ========== FONCTION DE SÉCURITÉ CONTRE XSS ==========
  // ⚠️ CRITIQUE: Échappe TOUT le HTML pour éviter les injections XSS
  function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Éléments du DOM
  const loginContainer = document.getElementById('login-form');
  const staffPanel = document.getElementById('staff-panel');
  const logoutBtn = document.getElementById('logout-btn');
  const toggleRefreshBtn = document.getElementById('toggle-refresh');
  const playerList = document.getElementById('player-list');
  const playerCount = document.getElementById('player-count');

  const state = {
    authenticated: false,
    user: null,
    map: null,
    markers: new Map(),
    autoRefresh: true,
    refreshInterval: null
  };

  // Cacher tout le contenu protégé au départ
  if (loginContainer) loginContainer.style.display = 'block';
  if (staffPanel) staffPanel.style.display = 'none';

  // Vérifier l'authentification Discord
  async function checkAuth() {
    console.log('[CLIENT] 🔍 checkAuth() appelé');
    console.log('[CLIENT] loginContainer:', loginContainer);
    console.log('[CLIENT] staffPanel:', staffPanel);
    
    try {
      console.log('[CLIENT] 📡 Appel /api/auth/status...');
      const res = await fetch('/api/auth/status', { credentials: 'include' });
      console.log('[CLIENT] 📡 Response status:', res.status);
      const data = await res.json();
      console.log('[CLIENT] 📡 Data reçue:', data);
      
      if (!data.authenticated) {
        console.log('[CLIENT] ❌ Non authentifié');
        // Non authentifié - afficher le bouton de connexion Discord
        if (loginContainer) loginContainer.style.display = 'block';
        if (staffPanel) staffPanel.style.display = 'none';
        return false;
      }
      
      console.log('[CLIENT] ✅ Authentifié !');
      state.authenticated = true;
      state.user = data.user;
      
      // Afficher le panel staff
      console.log('[CLIENT] 🎨 Cache login, affiche panel...');
      if (loginContainer) {
        console.log('[CLIENT] loginContainer.style avant:', loginContainer.style.display);
        loginContainer.style.display = 'none';
        console.log('[CLIENT] loginContainer.style après:', loginContainer.style.display);
      }
      if (staffPanel) {
        console.log('[CLIENT] staffPanel.style avant:', staffPanel.style.display);
        staffPanel.style.display = 'block';
        console.log('[CLIENT] staffPanel.style après:', staffPanel.style.display);
      }
      
      // Afficher le nom d'utilisateur Discord
      const discordUserEl = document.getElementById('discord-user');
      if (discordUserEl) {
        discordUserEl.textContent = `👤 ${state.user.username}#${state.user.discriminator}`;
      }
      
      return true;
    } catch (error) {
      console.error('[CLIENT] ❌ Auth check failed:', error);
      if (loginContainer) loginContainer.style.display = 'block';
      if (staffPanel) staffPanel.style.display = 'none';
      return false;
    }
  }

  async function api(path, opts = {}) {
    try {
      const headers = new Headers(opts.headers || {});
      headers.set('Content-Type', 'application/json');

      const res = await fetch(path, {
        ...opts,
        headers,
        credentials: 'include' // Important pour les sessions
      });
      if (!res.ok) {
        let detail = '';
        try {
          const j = await res.json();
          detail = j?.error ? ` (${j.error})` : '';
          
          // Si non autorisé, afficher le bouton de connexion
          if (res.status === 401 || res.status === 403) {
            if (loginContainer) loginContainer.style.display = 'block';
            if (staffPanel) staffPanel.style.display = 'none';
            throw new Error('Unauthorized');
          }
        } catch (parseError) {
          // Erreur de parsing JSON
        }
        throw new Error(`${res.status}${detail}`);
      }
      return res.json();
    } catch (error) {
      throw error;
    }
  }

  function gtaToMap({ x, y }) {
    // Nouvelle image: map gta.jpg (5944x8075 pixels)
    // Coordonnées GTA V officielles:
    // X: -4000 à +4000 (8000 unités)
    // Y: -4000 à +8000 (12000 unités)
    
    const minX = -4000;
    const maxX = 4000;
    const minY = -4000;
    const maxY = 8000;
    
    const mapWidth = 5944;
    const mapHeight = 8075;
    
    // Conversion proportionnelle SANS inversion Y
    const mapX = ((x - minX) / (maxX - minX)) * mapWidth;
    const mapY = ((y - minY) / (maxY - minY)) * mapHeight;
    
    return [mapY, mapX]; // Leaflet Simple CRS uses [lat, lng]
  }

  function initMap() {
    const mapEl = document.getElementById('map');
    if (!mapEl) return;

    // Nouvelle image map gta.jpg: 5944x8075 pixels
    const width = 5944;
    const height = 8075;
    const bounds = [[0, 0], [height, width]];

    const map = L.map('map', {
      crs: L.CRS.Simple,
      minZoom: -3,
      maxZoom: 3,
      zoomSnap: 0.25,
      zoomDelta: 0.25,
      wheelPxPerZoomLevel: 120,
      attributionControl: false,
      zoomControl: true
    });

    // Charger l'image et l'ajouter à la carte
    const img = new Image();
    img.onload = () => {
      L.imageOverlay('../assets/img/map gta.jpg', bounds, {
        interactive: false
      }).addTo(map);
      
      // Centrer la carte
      const center = [height / 2, width / 2];
      map.setView(center, -1);
      map.setMaxBounds(bounds);
    };
    img.onerror = () => {
      // Fallback: show a grid background if no image
      const gridSize = 512;
      for (let i = 0; i <= height; i += gridSize) {
        // Horizontal lines
        L.polyline([[i, 0], [i, width]], { 
          color: 'rgba(183,148,255,.12)', 
          weight: 1,
          interactive: false
        }).addTo(map);
      }
      for (let i = 0; i <= width; i += gridSize) {
        // Vertical lines
        L.polyline([[0, i], [height, i]], { 
          color: 'rgba(183,148,255,.12)', 
          weight: 1,
          interactive: false
        }).addTo(map);
      }
      // Add center cross
      L.polyline([[height/2 - 400, width/2], [height/2 + 400, width/2]], {
        color: 'rgba(53,209,255,.35)',
        weight: 2,
        interactive: false
      }).addTo(map);
      L.polyline([[height/2, width/2 - 300], [height/2, width/2 + 300]], {
        color: 'rgba(53,209,255,.35)',
        weight: 2,
        interactive: false
      }).addTo(map);
      // Background
      L.rectangle(bounds, { 
        color: 'rgba(183,148,255,.08)', 
        weight: 1, 
        fillColor: '#0a0d18',
        fillOpacity: 0.5,
        interactive: false
      }).addTo(map);
    };
    img.src = '../assets/img/map gta.jpg';

    state.map = map;
  }

  function markerIcon() {
    return L.divIcon({
      className: '',
      html: `
        <div style="
          width:20px;height:20px;border-radius:999px;
          background:#ff0066;
          border:3px solid #ffffff;
          box-shadow:0 0 0 4px rgba(255,0,102,.4), 0 0 20px rgba(255,0,102,.8);
          animation: pulse 2s infinite;
          position: relative;
          z-index: 1000;
        "></div>
        <style>
          @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.8; }
          }
        </style>
      `,
      iconSize: [20, 20],
      iconAnchor: [10, 10]
    });
  }

  function upsertPlayerMarker(p) {
    if (!state.map) return;

    const pos = gtaToMap(p);
    const key = String(p.id);

    const existing = state.markers.get(key);
    if (existing) {
      existing.setLatLng(pos);
      existing.setTooltipContent(`${p.name} (#${p.id})`);
      return;
    }

    const m = L.marker(pos, { icon: markerIcon() }).addTo(state.map);
    m.bindTooltip(`${p.name} (#${p.id})`, { direction: 'top', offset: [0, -8], opacity: 0.9 });
    state.markers.set(key, m);
  }

  function pruneMarkers(players) {
    const keep = new Set(players.map(p => String(p.id)));
    for (const [id, marker] of state.markers.entries()) {
      if (keep.has(id)) continue;
      marker.remove();
      state.markers.delete(id);
    }
  }

  function renderList(players) {
    if (!playerList) return;
    
    if (players.length === 0) {
      playerList.innerHTML = '<p style="color: rgba(255,255,255,0.5); text-align: center; padding: 40px 0;">Aucun joueur connecté</p>';
      return;
    }

    playerList.innerHTML = '';
    for (const p of players) {
      const item = document.createElement('div');
      item.className = 'player-item';
      item.innerHTML = `
        <div>
          <div class="player-name">${escapeHtml(p.name)} <span style="color: rgba(255,255,255,0.5);">#${p.id}</span></div>
          <div class="player-job">${escapeHtml(p.job || 'Aucun')} ${p.jobGrade ? `Grade ${p.jobGrade}` : ''}</div>
        </div>
        <div class="player-ping">${p.ping ?? '—'}ms</div>
      `;
      playerList.appendChild(item);
    }
  }

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  async function refreshPlayers() {
    try {
      const data = await api('../api/staff/players');
      const players = data?.players || [];
      
      if (playerCount) playerCount.textContent = players.length;
      
      renderList(players);
      
      players.forEach(p => upsertPlayerMarker(p));
      pruneMarkers(players);
    } catch (err) {
      console.error('Erreur refresh:', err);
    }
  }

  // Toggle auto-refresh
  if (toggleRefreshBtn) {
    toggleRefreshBtn.addEventListener('click', () => {
      state.autoRefresh = !state.autoRefresh;
      document.getElementById('refresh-text').textContent = `Auto-refresh: ${state.autoRefresh ? 'ON' : 'OFF'}`;
      
      if (state.autoRefresh) {
        state.refreshInterval = setInterval(refreshPlayers, 1200);
      } else if (state.refreshInterval) {
        clearInterval(state.refreshInterval);
        state.refreshInterval = null;
      }
    });
  }

  // ============================================================
  // TABS SYSTEM
  // ============================================================
  
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      
      // Update buttons
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      // Update content
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById(`tab-${tabName}`).classList.add('active');
    });
  });

  // ============================================================
  // PLAYER SEARCH
  // ============================================================

  const searchInput = document.getElementById('search-input');
  const searchResults = document.getElementById('search-results');
  let searchTimeout;

  // Charger automatiquement tous les joueurs au démarrage
  if (searchResults) {
    searchPlayers('');
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const query = e.target.value.trim();
      
      clearTimeout(searchTimeout);
      
      // Permettre la recherche même sans query (affiche tout)
      searchTimeout = setTimeout(() => {
        searchPlayers(query);
      }, 300);
    });
  }

  async function searchPlayers(query) {
    try {
      searchResults.innerHTML = '<div class="no-results">🔍 Chargement des joueurs...</div>';
      
      // Utiliser la route /search-db pour récupérer TOUS les joueurs de la base de données
      const url = query ? `../api/staff/search-db?q=${encodeURIComponent(query)}&limit=50` : '../api/staff/search-db?limit=100';
      const data = await api(url);
      const players = data?.players || [];
      
      if (players.length === 0) {
        searchResults.innerHTML = '<div class="no-results">❌ Aucun joueur trouvé dans la base de données</div>';
        return;
      }
      
      // Afficher la source des données
      if (data.source === 'database') {
        console.log(`[Staff] Loaded ${players.length} players from database`);
      }
      
      displaySearchResults(players);
    } catch (error) {
      console.error('Search error:', error);
      searchResults.innerHTML = '<div class="no-results">❌ Erreur lors de la recherche. Vérifiez que le serveur FiveM est accessible.</div>';
    }
  }

  function displaySearchResults(players) {
    searchResults.innerHTML = players.map(player => {
      const job = player.job || {};
      const jobLabel = job.label || 'Sans emploi';
      const gradeLabel = job.grade || '';
      const money = player.money || {};
      const onlineBadge = player.isOnline ? '<span class="badge-online">🟢 EN LIGNE</span>' : '';
      
      return `
        <div class="player-card${player.isOnline ? ' player-card--online' : ''}" data-citizenid="${escapeHtml(player.citizenid)}">
          <div class="player-card__header">
            <div>
              <h3>${escapeHtml(player.firstname)} ${escapeHtml(player.lastname)}</h3>
              ${onlineBadge}
            </div>
            <span class="job-badge">${escapeHtml(jobLabel)}${gradeLabel ? ` (${escapeHtml(gradeLabel)})` : ''}</span>
          </div>
          <div class="player-card__info">
            <div class="info-item">
              <span class="info-label">CitizenID</span>
              <span class="info-value">${escapeHtml(player.citizenid)}</span>
            </div>
            <div class="info-item">
              <span class="info-label">📱 Téléphone</span>
              <span class="info-value">${escapeHtml(player.phone || 'N/A')}</span>
            </div>
            <div class="info-item">
              <span class="info-label">💵 Liquide</span>
              <span class="money-badge cash">${formatMoney(money.cash || 0)}</span>
            </div>
            <div class="info-item">
              <span class="info-label">🏦 Banque</span>
              <span class="money-badge bank">${formatMoney(money.bank || 0)}</span>
            </div>
            <div class="info-item">
              <span class="info-label">📅 Dernière connexion</span>
              <span class="info-value">${formatDate(player.last_updated || player.lastUpdated)}</span>
            </div>
          </div>
          <button class="btn btn-primary btn-sm" data-citizenid="${escapeHtml(player.citizenid)}" data-action="view-details">
            📋 Voir détails complets
          </button>
        </div>
      `;
    }).join('');
  }

  window.viewPlayerDetails = async function(citizenid) {
    try {
      const player = await api(`../api/staff/player/${citizenid}`);
      
      // Create modal with full details
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.innerHTML = `
        <div class="modal-content">
          <div class="modal-header">
            <h2>👤 Profil Complet - ${escapeHtml(player.charinfo?.firstname)} ${escapeHtml(player.charinfo?.lastname)}</h2>
            <button class="btn-close" data-action="close-modal">✕</button>
          </div>
          <div class="modal-body">
            <div class="info-grid">
              <div class="info-section">
                <h3>🆔 Identité</h3>
                <div class="info-item">
                  <span class="info-label">CitizenID</span>
                  <span class="info-value">${escapeHtml(player.citizenid)}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Nom complet</span>
                  <span class="info-value">${escapeHtml(player.charinfo?.firstname)} ${escapeHtml(player.charinfo?.lastname)}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Date de naissance</span>
                  <span class="info-value">${escapeHtml(player.charinfo?.birthdate || 'N/A')}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Nationalité</span>
                  <span class="info-value">${escapeHtml(player.charinfo?.nationality || 'N/A')}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Téléphone</span>
                  <span class="info-value">${escapeHtml(player.charinfo?.phone || 'N/A')}</span>
                </div>
              </div>
              
              <div class="info-section">
                <h3>💼 Emploi</h3>
                <div class="info-item">
                  <span class="info-label">Job</span>
                  <span class="job-badge">${escapeHtml(player.job?.label || 'Sans emploi')}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Grade</span>
                  <span class="info-value">${escapeHtml(player.job?.grade?.name || 'N/A')} (Niveau ${player.job?.grade?.level || 0})</span>
                </div>
                <div class="info-item">
                  <span class="info-label">En service</span>
                  <span class="info-value">${player.job?.onduty ? '✅ Oui' : '❌ Non'}</span>
                </div>
              </div>
              
              <div class="info-section">
                <h3>💰 Finances</h3>
                <div class="info-item">
                  <span class="info-label">Liquide</span>
                  <span class="money-badge cash">${formatMoney(player.money?.cash || 0)}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Banque</span>
                  <span class="money-badge bank">${formatMoney(player.money?.bank || 0)}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Total</span>
                  <span class="money-badge">${formatMoney((player.money?.cash || 0) + (player.money?.bank || 0))}</span>
                </div>
              </div>
              
              <div class="info-section">
                <h3>📊 Statistiques</h3>
                <div class="info-item">
                  <span class="info-label">Dernière position</span>
                  <span class="info-value">${player.position ? `X: ${Math.round(player.position.x)}, Y: ${Math.round(player.position.y)}` : 'N/A'}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Dernière connexion</span>
                  <span class="info-value">${formatDate(player.last_updated)}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Inventory</span>
                  <span class="info-value">${player.inventory ? Object.keys(JSON.parse(player.inventory)).length : 0} items</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
      
      document.body.appendChild(modal);
      
      // Event listener pour fermer la modale (CSP-compliant)
      const closeBtn = modal.querySelector('[data-action="close-modal"]');
      if (closeBtn) {
        closeBtn.addEventListener('click', function() {
          modal.remove();
        });
      }
      
      // Close on overlay click
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.remove();
        }
      });
      
    } catch (error) {
      console.error('Error loading player details:', error);
      alert('Erreur lors du chargement des détails du joueur');
    }
  };

  function formatMoney(amount) {
    return new Intl.NumberFormat('fr-FR', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount || 0);
  }

  function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 60) return `Il y a ${diffMins} min`;
    if (diffMins < 1440) return `Il y a ${Math.floor(diffMins / 60)} h`;
    return `Il y a ${Math.floor(diffMins / 1440)} j`;
  }

  // Initialisation au chargement - Vérifier l'authentification Discord
  (async function init() {
    console.log('[CLIENT] 🚀 init() démarré');
    const authenticated = await checkAuth();
    console.log('[CLIENT] checkAuth() retourné:', authenticated);
    
    if (!authenticated) {
      console.log('[CLIENT] ⚠️ Pas authentifié, arrêt init()');
      return;
    }
    
    console.log('[CLIENT] ✅ Authentifié, initialisation du panel...');
    // Utilisateur authentifié, afficher le panel
    if (loginContainer) loginContainer.style.display = 'none';
    if (staffPanel) staffPanel.style.display = 'block';
    
    initMap();
    await refreshPlayers();
    
    // Event delegation pour les boutons "Voir détails" (CSP-compliant)
    document.addEventListener('click', function(e) {
      const btn = e.target.closest('[data-action="view-details"]');
      if (btn) {
        const citizenid = btn.getAttribute('data-citizenid');
        if (citizenid) viewPlayerDetails(citizenid);
      }
    });
    
    if (state.autoRefresh) {
      state.refreshInterval = setInterval(refreshPlayers, 1200);
    }
    
    console.log('[CLIENT] ✅ init() terminé');
  })();

  // Bouton déconnexion
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      window.location.href = '/auth/logout';
    });
  }

})();

