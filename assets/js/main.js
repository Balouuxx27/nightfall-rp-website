(() => {
  const yearEl = document.querySelector('[data-year]');
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  // Fermer le menu mobile quand on clique sur un lien
  document.addEventListener('DOMContentLoaded', () => {
    const navLinks = document.querySelectorAll('.nav a');
    const nav = document.querySelector('.nav');
    const menuToggle = document.querySelector('.mobile-menu-toggle');
    
    // Fonction pour toggle le menu
    if (menuToggle) {
      menuToggle.addEventListener('click', () => {
        const isOpen = nav.classList.contains('mobile-open');
        if (isOpen) {
          nav.classList.remove('mobile-open');
          menuToggle.classList.remove('active');
          document.body.classList.remove('menu-open');
        } else {
          nav.classList.add('mobile-open');
          menuToggle.classList.add('active');
          document.body.classList.add('menu-open');
        }
      });
    }
    
    navLinks.forEach(link => {
      link.addEventListener('click', () => {
        if (nav) nav.classList.remove('mobile-open');
        if (menuToggle) menuToggle.classList.remove('active');
        document.body.classList.remove('menu-open');
      });
    });

    // Fermer le menu si on clique en dehors
    if (nav) {
      nav.addEventListener('click', (e) => {
        if (e.target === nav) {
          nav.classList.remove('mobile-open');
          if (menuToggle) menuToggle.classList.remove('active');
          document.body.classList.remove('menu-open');
        }
      });
    }
  });

  // Reveal au scroll - DÉSACTIVÉ COMPLÈTEMENT pour éviter les problèmes de disparition
  // Les éléments restent visibles tout le temps
  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const revealTargets = document.querySelectorAll('.hero, .section, .footer');
  
  // Force ALL elements to be visible immediately
  for (const el of revealTargets) {
    el.classList.add('is-in');
    el.style.opacity = '1';
    el.style.transform = 'none';
  }

  const mobileMenu = document.querySelector('[data-mobile-menu]');
  const menuBtn = document.querySelector('[data-menu]');
  if (menuBtn && mobileMenu) {
    menuBtn.addEventListener('click', () => {
      const isHidden = mobileMenu.hasAttribute('hidden');
      if (isHidden) mobileMenu.removeAttribute('hidden');
      else mobileMenu.setAttribute('hidden', '');
    });

    mobileMenu.addEventListener('click', (e) => {
      const a = e.target.closest('a');
      if (!a) return;
      mobileMenu.setAttribute('hidden', '');
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') mobileMenu.setAttribute('hidden', '');
    });
  }

  const accRoot = document.querySelector('[data-accordion]');
  if (accRoot) {
    accRoot.addEventListener('click', (e) => {
      const btn = e.target.closest('.acc');
      if (!btn) return;

      const expanded = btn.getAttribute('aria-expanded') === 'true';
      btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      const panel = btn.nextElementSibling;
      if (!panel) return;
      if (expanded) panel.setAttribute('hidden', '');
      else panel.removeAttribute('hidden');
    });
  }

  const copyBtn = document.querySelector('[data-copy-ip]');
  const ipEl = document.querySelector('[data-ip]');
  if (copyBtn && ipEl) {
    copyBtn.addEventListener('click', async () => {
      const ip = (ipEl.textContent || '').trim();
      if (!ip || ip === 'à configurer') {
        copyBtn.textContent = 'IP non configurée';
        setTimeout(() => (copyBtn.textContent = "Copier l'IP"), 1200);
        return;
      }
      try {
        await navigator.clipboard.writeText(ip);
        copyBtn.textContent = 'Copié !';
      } catch {
        copyBtn.textContent = 'Copie impossible';
      }
      setTimeout(() => (copyBtn.textContent = "Copier l'IP"), 1200);
    });
  }

  // Démo de statut/compteur (à brancher sur ta vraie API ensuite)
  const onlineEl = document.querySelector('[data-online]');
  const statusBadge = document.querySelector('[data-status]');
  let lastOnline = null;

  function setOnline(next) {
    if (!onlineEl) return;
    const target = Number.isFinite(next) ? next : 0;
    const from = typeof lastOnline === 'number' ? lastOnline : target;
    const start = performance.now();
    const dur = 420;

    function frame(now) {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      const val = Math.round(from + (target - from) * eased);
      onlineEl.textContent = String(val);
      if (t < 1) requestAnimationFrame(frame);
    }

    lastOnline = target;
    requestAnimationFrame(frame);
  }

  async function refreshStatus() {
    try {
      const res = await fetch('/api/status', { cache: 'no-store' });
      if (!res.ok) throw new Error('status');
      const data = await res.json();

      setOnline(Number(data.playersOnline ?? 0));
      if (statusBadge) {
        const up = Boolean(data.isOnline);
        statusBadge.textContent = up ? 'ONLINE' : 'OFFLINE';
        statusBadge.classList.toggle('badge--ok', up);
        statusBadge.classList.toggle('badge--off', !up);
      }

      const ip = document.querySelector('[data-ip]');
      if (ip && data.serverIp) ip.textContent = data.serverIp;

      const discord = document.querySelector('[data-discord-link]');
      if (discord && data.discordInvite) {
        discord.setAttribute('href', data.discordInvite);
        discord.textContent = 'Rejoindre le Discord';
      }

      // Charger le widget Discord dynamiquement
      const widgetContainer = document.getElementById('discord-widget-container');
      if (widgetContainer && data.discordServerId && data.discordServerId !== 'VOTRE_ID_ICI') {
        const iframe = document.createElement('iframe');
        iframe.src = `https://discord.com/widget?id=${data.discordServerId}&theme=dark`;
        iframe.width = '350';
        iframe.height = '500';
        iframe.allowTransparency = 'true';
        iframe.frameBorder = '0';
        iframe.sandbox = 'allow-popups allow-popups-to-escape-sandbox allow-same-origin allow-scripts';
        iframe.style.cssText = 'width: 350px !important; height: 500px !important; display: block !important;';
        widgetContainer.appendChild(iframe);
      }

      // Afficher l'uptime
      const uptimeEl = document.querySelector('[data-stat-uptime]');
      if (uptimeEl && data.uptime) {
        const minutes = data.uptime;
        if (minutes < 60) {
          uptimeEl.textContent = `${minutes}min`;
        } else if (minutes < 1440) {
          const hours = Math.floor(minutes / 60);
          uptimeEl.textContent = `${hours}h`;
        } else {
          const days = Math.floor(minutes / 1440);
          const hours = Math.floor((minutes % 1440) / 60);
          uptimeEl.textContent = `${days}j ${hours}h`;
        }
      } else if (uptimeEl) {
        uptimeEl.textContent = '—';
      }

      // Afficher le ping moyen
      const pingEl = document.querySelector('[data-stat-ping]');
      if (pingEl && data.avgPing) {
        pingEl.textContent = `${data.avgPing}ms`;
      } else if (pingEl) {
        pingEl.textContent = '—';
      }

      // Mettre à jour la stat des joueurs dans la section stats aussi
      const statPlayersEl = document.querySelector('[data-stat-players]');
      if (statPlayersEl) {
        statPlayersEl.textContent = Number(data.playersOnline ?? 0);
      }
    } catch {
      if (onlineEl) onlineEl.textContent = '—';
      lastOnline = null;
      if (statusBadge) {
        statusBadge.textContent = 'OFFLINE';
        statusBadge.classList.add('badge--off');
        statusBadge.classList.remove('badge--ok');
      }
      
      // Reset des valeurs en cas d'erreur
      const uptimeEl = document.querySelector('[data-stat-uptime]');
      if (uptimeEl) uptimeEl.textContent = '—';
      
      const pingEl = document.querySelector('[data-stat-ping]');
      if (pingEl) pingEl.textContent = '—';

      const statPlayersEl = document.querySelector('[data-stat-players]');
      if (statPlayersEl) statPlayersEl.textContent = '—';
    }
  }

  refreshStatus();
  setInterval(refreshStatus, 7000);
})();
