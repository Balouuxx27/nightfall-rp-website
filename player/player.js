// ========== SÉCURITÉ: Protection XSS ==========
function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return unsafe;
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Vérification de l'authentification
async function checkAuth() {
  try {
    const res = await fetch('/api/auth/status', { credentials: 'include' });
    const data = await res.json();
    
    if (!data.authenticated) {
      window.location.href = '/auth/discord';
      return null;
    }
    
    return data.user;
  } catch (error) {
    console.error('Auth check failed:', error);
    showError('Erreur de vérification de l\'authentification');
    return null;
  }
}

// Récupérer les données du joueur
async function fetchPlayerData() {
  try {
    const res = await fetch(`/api/player/me`, { credentials: 'include' });
    
    if (!res.ok) {
      if (res.status === 404) {
        showError('Aucun personnage trouvé. Connectez-vous au serveur FiveM pour créer un personnage.');
        return null;
      }
      throw new Error('Failed to fetch player data');
    }
    
    return await res.json();
  } catch (error) {
    console.error('Error fetching player data:', error);
    showError('Erreur lors du chargement des données');
    return null;
  }
}

// Créer une barre de progression
function createProgressBar(id, value, max = 100) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));
  const fill = document.getElementById(`${id}-fill`);
  const text = document.getElementById(`${id}-text`);
  
  if (fill) fill.style.width = percentage + '%';
  if (text) text.textContent = Math.round(value) + (id === 'health' ? '' : '%');
}

// Afficher les données du joueur
function displayPlayerData(user, playerData) {
  console.log('Displaying player data:', playerData);
  
  // Avatar Discord
  const avatarUrl = user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
    : 'https://cdn.discordapp.com/embed/avatars/0.png';
  
  document.getElementById('discord-avatar').src = avatarUrl;
  document.getElementById('discord-username').textContent = 
    `${escapeHtml(user.username)}${user.discriminator !== '0' ? '#' + user.discriminator : ''}`;
  
  // Statut en ligne/hors ligne
  const onlineStatus = document.getElementById('online-status');
  if (playerData.online) {
    onlineStatus.innerHTML = '<div class="badge badge--ok">🟢 EN LIGNE</div>';
  } else {
    onlineStatus.innerHTML = '<div class="badge badge--off">⚫ HORS LIGNE</div>';
  }
  
  // Informations personnage
  const charinfo = playerData.charinfo || {};
  const fullName = `${escapeHtml(charinfo.firstname || 'Unknown')} ${escapeHtml(charinfo.lastname || 'Player')}`;
  document.getElementById('character-name').textContent = fullName;
  
  // Icône de genre
  const gender = parseInt(charinfo.gender) || 0;
  const genderIcon = document.getElementById('gender-icon');
  if (gender === 0) {
    genderIcon.textContent = '👨'; // Homme
  } else {
    genderIcon.textContent = '👩'; // Femme
  }
  
  document.getElementById('citizenid').textContent = escapeHtml(playerData.citizenid);
  document.getElementById('firstname').textContent = escapeHtml(charinfo.firstname || 'Unknown');
  document.getElementById('lastname').textContent = escapeHtml(charinfo.lastname || 'Player');
  document.getElementById('phone').textContent = escapeHtml(charinfo.phone || 'Non défini');
  document.getElementById('birthdate').textContent = escapeHtml(charinfo.birthdate || 'N/A');
  
  // Métier
  const job = playerData.job || {};
  const jobGrade = job.grade || {};
  const jobDisplay = job.label 
    ? `${escapeHtml(job.label)} - ${escapeHtml(jobGrade.name || 'Grade 0')}`
    : 'Sans emploi';
  document.getElementById('job').innerHTML = `<span class="badge">${jobDisplay}</span>`;
  
  // Argent
  const money = playerData.money || {};
  const cash = parseInt(money.cash) || 0;
  const bank = parseInt(money.bank) || 0;
  const total = cash + bank;
  
  document.getElementById('cash').textContent = `${cash.toLocaleString('fr-FR')} $`;
  document.getElementById('bank').textContent = `${bank.toLocaleString('fr-FR')} $`;
  document.getElementById('total-money').textContent = `${total.toLocaleString('fr-FR')} $`;
  
  // Métadonnées (stats de santé)
  const metadata = playerData.metadata || {};
  
  // Vie
  const health = parseInt(metadata.health) || 0;
  const maxHealth = parseInt(metadata.maxHealth) || 200;
  createProgressBar('health', health, maxHealth);
  
  // Armure
  const armor = parseInt(metadata.armor) || 0;
  createProgressBar('armor', armor, 100);
  
  // Faim
  const hunger = parseFloat(metadata.hunger) || 0;
  createProgressBar('hunger', hunger, 100);
  
  // Soif
  const thirst = parseFloat(metadata.thirst) || 0;
  createProgressBar('thirst', thirst, 100);
  
  // Stress
  const stress = parseFloat(metadata.stress) || 0;
  createProgressBar('stress', stress, 100);
  
  // Véhicules
  displayVehicles(playerData.vehicles || []);
  
  // Afficher le profil
  document.getElementById('loading').style.display = 'none';
  document.getElementById('player-profile').style.display = 'block';
}

// Afficher les véhicules
function displayVehicles(vehicles) {
  const list = document.getElementById('vehicle-list');
  const count = document.getElementById('vehicle-count');
  
  count.textContent = vehicles.length > 0 
    ? `${vehicles.length} véhicule${vehicles.length > 1 ? 's' : ''} possédé${vehicles.length > 1 ? 's' : ''}`
    : 'Aucun véhicule';
  
  if (vehicles.length === 0) {
    list.innerHTML = '<div style="text-align: center; color: var(--muted); padding: 30px;">🚗 Aucun véhicule possédé</div>';
    return;
  }
  
  // Fonction pour obtenir l'état du véhicule
  function getStateLabel(state) {
    switch(parseInt(state)) {
      case 0: return '<span style="color: #27ae60;">🟢 Sorti</span>';
      case 1: return '<span style="color: #3498db;">🔵 Garage</span>';
      case 2: return '<span style="color: #e74c3c;">🔴 Fourrière</span>';
      default: return '<span style="color: var(--muted);">❓ Inconnu</span>';
    }
  }
  
  // Fonction pour obtenir la couleur de la condition
  function getConditionColor(value) {
    value = parseFloat(value) || 1000;
    const percentage = (value / 1000) * 100;
    if (percentage >= 80) return '#27ae60';
    if (percentage >= 50) return '#f39c12';
    return '#e74c3c';
  }
  
  list.innerHTML = vehicles.map(v => {
    const vehicle = escapeHtml(v.vehicle || 'Inconnu');
    const plate = escapeHtml(v.plate || 'N/A');
    const state = getStateLabel(v.state);
    const engine = parseFloat(v.engine) || 1000;
    const body = parseFloat(v.body) || 1000;
    const enginePercent = Math.round((engine / 1000) * 100);
    const bodyPercent = Math.round((body / 1000) * 100);
    
    return `
      <div style="
        background: rgba(255,255,255,.04); 
        border: 1px solid rgba(255,255,255,.10); 
        border-radius: 16px; 
        padding: 20px;
        transition: all .2s ease;
        cursor: pointer;
      " onmouseover="this.style.background='rgba(255,255,255,.08)'; this.style.borderColor='rgba(183,148,255,.25)';" onmouseout="this.style.background='rgba(255,255,255,.04)'; this.style.borderColor='rgba(255,255,255,.10)';">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <div>
            <div style="font-size: 18px; font-weight: 800; color: var(--accent);">${vehicle}</div>
            <div style="font-size: 13px; color: var(--muted2); margin-top: 4px;">Plaque: <span style="font-family: monospace; background: rgba(0,0,0,.3); padding: 2px 8px; border-radius: 5px;">${plate}</span></div>
          </div>
          <div style="text-align: right;">
            ${state}
          </div>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px;">
          <div>
            <div style="font-size: 11px; color: var(--muted2); margin-bottom: 4px;">🔧 Moteur</div>
            <div style="width: 100%; height: 8px; background: rgba(255,255,255,.1); border-radius: 4px; overflow: hidden;">
              <div style="width: ${enginePercent}%; height: 100%; background: ${getConditionColor(engine)}; transition: width 0.3s;"></div>
            </div>
            <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">${enginePercent}%</div>
          </div>
          <div>
            <div style="font-size: 11px; color: var(--muted2); margin-bottom: 4px;">🚗 Carrosserie</div>
            <div style="width: 100%; height: 8px; background: rgba(255,255,255,.1); border-radius: 4px; overflow: hidden;">
              <div style="width: ${bodyPercent}%; height: 100%; background: ${getConditionColor(body)}; transition: width 0.3s;"></div>
            </div>
            <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">${bodyPercent}%</div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// Afficher une erreur
function showError(message) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('error').style.display = 'block';
  document.getElementById('error-message').textContent = message;
}

// Déconnexion
function logout() {
  window.location.href = '/auth/logout';
}

// Initialisation au chargement de la page
(async function init() {
  const user = await checkAuth();
  if (!user) return;
  
  const playerData = await fetchPlayerData();
  if (!playerData) return;
  
  displayPlayerData(user, playerData);
})();
