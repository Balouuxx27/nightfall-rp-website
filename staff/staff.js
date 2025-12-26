(() => {
  // Éléments du DOM
  const loginForm = document.getElementById('loginForm');
  const loginContainer = document.getElementById('login-form');
  const staffPanel = document.getElementById('staff-panel');
  const loginError = document.getElementById('login-error');
  const logoutBtn = document.getElementById('logout-btn');
  const toggleRefreshBtn = document.getElementById('toggle-refresh');
  const playerList = document.getElementById('player-list');
  const playerCount = document.getElementById('player-count');

  const storageKey = 'nightfall_staff_token';
  const state = {
    token: localStorage.getItem(storageKey) || null,
    map: null,
    markers: new Map(),
    autoRefresh: true,
    refreshInterval: null
  };

  // Cacher tout le contenu protégé au départ
  if (loginContainer) loginContainer.style.display = 'block';
  if (staffPanel) staffPanel.style.display = 'none';

  async function api(path, opts = {}) {
    const headers = new Headers(opts.headers || {});
    headers.set('Content-Type', 'application/json');
    if (state.token) headers.set('Authorization', `Bearer ${state.token}`);

    const res = await fetch(path, {
      ...opts,
      headers
    });
    if (!res.ok) {
      let detail = '';
      try {
        const j = await res.json();
        detail = j?.error ? ` (${j.error})` : '';
      } catch {}
      throw new Error(`${res.status}${detail}`);
    }
    return res.json();
  }

  function gtaToMap({ x, y }) {
    // Coordonnées GTA V standard
    const minX = -4000;
    const maxX = 4000;
    const minY = -4000;
    const maxY = 8000;
    
    const size = 4096;
    const mx = ((x - minX) / (maxX - minX)) * size;
    const my = ((y - minY) / (maxY - minY)) * size;
    return [my, mx]; // Leaflet Simple CRS uses [lat, lng]
  }

  function initMap() {
    const mapEl = document.getElementById('map');
    if (!mapEl) return;

    // Image satellite agrandie de 25%
    const size = 5120; // Plus grand pour agrandir l'image
    const bounds = [[0, 0], [size, size]];

    const map = L.map('map', {
      crs: L.CRS.Simple,
      minZoom: -2,
      maxZoom: 2,
      zoomSnap: 0.25,
      zoomDelta: 0.25,
      wheelPxPerZoomLevel: 120,
      attributionControl: false,
      zoomControl: true
    });

    // Charger l'image et l'ajouter à la carte
    const img = new Image();
    img.onload = () => {
      L.imageOverlay('../assets/img/gta-map.jpg', bounds, {
        interactive: false
      }).addTo(map);
      
      // Agrandir l'image en réduisant les bounds visuels
      const center = [size / 2, size / 2];
      map.setView(center, 0.3); // Zoom positif pour agrandir
      map.setMaxBounds(bounds);
    };
    img.onerror = () => {
      // Fallback: show a grid background if no image
      const gridSize = 512;
      for (let i = 0; i <= size; i += gridSize) {
        // Horizontal lines
        L.polyline([[i, 0], [i, size]], { 
          color: 'rgba(183,148,255,.12)', 
          weight: 1,
          interactive: false
        }).addTo(map);
        // Vertical lines
        L.polyline([[0, i], [size, i]], { 
          color: 'rgba(183,148,255,.12)', 
          weight: 1,
          interactive: false
        }).addTo(map);
      }
      // Add center cross
      L.polyline([[size/2 - 200, size/2], [size/2 + 200, size/2]], {
        color: 'rgba(53,209,255,.35)',
        weight: 2,
        interactive: false
      }).addTo(map);
      L.polyline([[size/2, size/2 - 200], [size/2, size/2 + 200]], {
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
    img.src = '../assets/img/gta-map.jpg';

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
    if (!state.token) return;
    
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

  // Login
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;
      
      try {
        const data = await api('../api/staff/login', {
          method: 'POST',
          body: JSON.stringify({ password })
        });
        
        state.token = data.token;
        localStorage.setItem(storageKey, data.token);
        
        // Afficher le panel, cacher le login
        if (loginContainer) loginContainer.style.display = 'none';
        if (staffPanel) staffPanel.style.display = 'block';
        
        // Init la carte et charger les joueurs
        initMap();
        refreshPlayers();
        
        // Démarrer l'auto-refresh
        if (state.autoRefresh) {
          state.refreshInterval = setInterval(refreshPlayers, 1200);
        }
      } catch (err) {
        if (loginError) {
          loginError.textContent = 'Mot de passe incorrect';
        }
      }
    });
  }

  // Logout
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      state.token = null;
      localStorage.removeItem(storageKey);
      
      if (state.refreshInterval) {
        clearInterval(state.refreshInterval);
        state.refreshInterval = null;
      }
      
      // Cacher le panel, afficher le login
      if (loginContainer) loginContainer.style.display = 'block';
      if (staffPanel) staffPanel.style.display = 'none';
      
      // Clear markers
      for (const marker of state.markers.values()) marker.remove();
      state.markers.clear();
    });
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

  // Si token existe déjà, charger directement

  if (state.token) {
    if (loginContainer) loginContainer.style.display = 'none';
    if (staffPanel) staffPanel.style.display = 'block';
    initMap();
    refreshPlayers();
    if (state.autoRefresh) {
      state.refreshInterval = setInterval(refreshPlayers, 1200);
    }
  }

})();

