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
async function fetchPlayerData(discordId) {
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

// Afficher les données du joueur
function displayPlayerData(user, playerData) {
  // Avatar Discord
  const avatarUrl = user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
    : 'https://cdn.discordapp.com/embed/avatars/0.png';
  
  document.getElementById('discord-avatar').src = avatarUrl;
  document.getElementById('discord-username').textContent = `${escapeHtml(user.username)}#${user.discriminator}`;
  
  // Informations personnage
  const charinfo = playerData.charinfo || {};
  document.getElementById('character-name').textContent = 
    `${escapeHtml(charinfo.firstname)} ${escapeHtml(charinfo.lastname)}`;
  
  document.getElementById('citizenid').textContent = escapeHtml(playerData.citizenid);
  document.getElementById('firstname').textContent = escapeHtml(charinfo.firstname);
  document.getElementById('lastname').textContent = escapeHtml(charinfo.lastname);
  document.getElementById('phone').textContent = escapeHtml(charinfo.phone || 'Non défini');
  
  // Métier
  const job = playerData.job || {};
  const jobDisplay = job.label 
    ? `${escapeHtml(job.label)} - ${escapeHtml(job.grade?.name || '')}`
    : 'Sans emploi';
  document.getElementById('job').innerHTML = `<span class="job-badge">${jobDisplay}</span>`;
  
  // Argent
  const money = playerData.money || {};
  const cash = parseInt(money.cash) || 0;
  const bank = parseInt(money.bank) || 0;
  const total = cash + bank;
  
  document.getElementById('cash').textContent = `${cash.toLocaleString('fr-FR')} $`;
  document.getElementById('bank').textContent = `${bank.toLocaleString('fr-FR')} $`;
  document.getElementById('total-money').textContent = `Total: ${total.toLocaleString('fr-FR')} $`;
  
  // Véhicules
  displayVehicles(playerData.vehicles || []);
  
  // Afficher le profil
  document.getElementById('loading').style.display = 'none';
  document.getElementById('player-profile').style.display = 'block';
}

// Afficher les véhicules
function displayVehicles(vehicles) {
  const list = document.getElementById('vehicle-list');
  list.innerHTML = '';
  
  if (vehicles.length === 0) {
    list.innerHTML = '<li style="text-align: center; color: #999;">Aucun véhicule possédé</li>';
    return;
  }
  
  vehicles.forEach(vehicle => {
    const li = document.createElement('li');
    li.className = 'vehicle-item';
    
    const nameSpan = document.createElement('span');
    nameSpan.className = 'vehicle-name';
    nameSpan.textContent = escapeHtml(vehicle.vehicle || 'Véhicule inconnu');
    
    const plateSpan = document.createElement('span');
    plateSpan.className = 'vehicle-plate';
    plateSpan.textContent = escapeHtml(vehicle.plate || 'NO PLATE');
    
    const stateSpan = document.createElement('span');
    const state = parseInt(vehicle.state) || 0;
    stateSpan.textContent = state === 0 ? '🔧 Au garage' : state === 1 ? '🚗 Sorti' : '🔒 Fourrière';
    stateSpan.style.marginLeft = '10px';
    
    li.appendChild(nameSpan);
    li.appendChild(document.createTextNode(' '));
    li.appendChild(stateSpan);
    li.appendChild(plateSpan);
    
    list.appendChild(li);
  });
}

// Afficher une erreur
function showError(message) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('error').textContent = message;
  document.getElementById('error').style.display = 'block';
}

// Déconnexion
function logout() {
  window.location.href = '/auth/logout';
}

// Initialisation au chargement de la page
(async function init() {
  const user = await checkAuth();
  if (!user) return;
  
  const playerData = await fetchPlayerData(user.id);
  if (!playerData) return;
  
  displayPlayerData(user, playerData);
  
  // Actualisation automatique toutes les 30 secondes
  setInterval(async () => {
    const freshData = await fetchPlayerData(user.id);
    if (freshData) {
      displayPlayerData(user, freshData);
    }
  }, 30000);
})();
