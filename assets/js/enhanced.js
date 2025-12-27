/* ==========================================================================
   🚀 NIGHTFALL RP - ENHANCED JAVASCRIPT
   ========================================================================== */

(function() {
  'use strict';

  // ========== COMPTEUR JOUEURS EN DIRECT ==========
  async function updateLiveCounter() {
    try {
      const response = await fetch('/api/status');
      if (response.ok) {
        const data = await response.json();
        const liveCount = document.querySelector('[data-live-count]');
        const statPlayers = document.querySelector('[data-stat-players]');
        
        if (liveCount && data.players !== undefined) {
          liveCount.textContent = data.players;
        }
        
        if (statPlayers && data.players !== undefined) {
          statPlayers.textContent = data.players;
        }
      }
    } catch (error) {
      console.log('Info: API non disponible en mode local');
    }
  }

  // Mise à jour toutes les 3 secondes
  updateLiveCounter();
  setInterval(updateLiveCounter, 3000);

  // ========== GALERIE VIDÉO INTERACTIVE ==========
  const galleryVideos = document.querySelectorAll('.gallery-item--video');
  
  galleryVideos.forEach(item => {
    const video = item.querySelector('.gallery-video');
    
    if (video && video.tagName === 'VIDEO') {
      // Only for HTML5 <video> elements, not iframes
      // Play on hover
      item.addEventListener('mouseenter', () => {
        video.play().catch(() => {});
      });
      
      // Pause on leave
      item.addEventListener('mouseleave', () => {
        video.pause();
        video.currentTime = 0;
      });
      
      // Fullscreen on click
      item.addEventListener('click', () => {
        if (video.requestFullscreen) {
          video.requestFullscreen();
        } else if (video.webkitRequestFullscreen) {
          video.webkitRequestFullscreen();
        }
        video.play().catch(() => {});
      });
    }
    // For iframes (YouTube), just let them be clickable for fullscreen
    else if (video && video.tagName === 'IFRAME') {
      item.addEventListener('click', () => {
        if (video.requestFullscreen) {
          video.requestFullscreen();
        } else if (video.webkitRequestFullscreen) {
          video.webkitRequestFullscreen();
        }
      });
    }
  });

  // ========== PARALLAX SCROLL AMÉLIORÉ ==========
  const parallaxElements = document.querySelectorAll('.tile, .stat-card, .staff-card, .gallery-item');
  
  function handleParallax() {
    const scrolled = window.pageYOffset;
    
    parallaxElements.forEach((el, index) => {
      const rect = el.getBoundingClientRect();
      const elementTop = rect.top + scrolled;
      const elementHeight = rect.height;
      const viewportHeight = window.innerHeight;
      
      // Check if element is in viewport
      if (rect.top < viewportHeight && rect.bottom > 0) {
        const scrollProgress = (scrolled + viewportHeight - elementTop) / (viewportHeight + elementHeight);
        const translateY = (scrollProgress - 0.5) * 20;
        
        el.style.transform = `translateY(${translateY * -1}px)`;
      }
    });
  }
  
  let ticking = false;
  window.addEventListener('scroll', () => {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        handleParallax();
        ticking = false;
      });
      ticking = true;
    }
  });

  // ========== STATS COUNTER ANIMATION ==========
  function animateCounter(element, target, duration = 2000) {
    const start = 0;
    const startTime = performance.now();
    
    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      const current = Math.floor(start + (target - start) * easeOutQuart);
      
      element.textContent = current + '+';
      
      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        element.textContent = target + '+';
      }
    }
    
    requestAnimationFrame(update);
  }

  // Observer pour animer les compteurs quand ils entrent dans le viewport
  const statObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const value = entry.target.dataset.statVehicles;
        if (value && !entry.target.dataset.animated) {
          const num = parseInt(value);
          if (!isNaN(num)) {
            animateCounter(entry.target, num);
            entry.target.dataset.animated = 'true';
          }
        }
      }
    });
  }, { threshold: 0.5 });

  const statVehicles = document.querySelector('[data-stat-vehicles]');
  if (statVehicles) {
    statObserver.observe(statVehicles);
  }

  // ========== ANIMATION AU SCROLL ==========
  const fadeElements = document.querySelectorAll('.section, .tile, .stat-card, .staff-card');
  
  const fadeObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, { threshold: 0.1 });

  fadeElements.forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(30px)';
    el.style.transition = 'opacity 0.8s ease-out, transform 0.8s ease-out';
    fadeObserver.observe(el);
  });

  // ========== EFFET CURSOR TRAIL (Traînée de particules) ==========
  const canvas = document.createElement('canvas');
  canvas.style.position = 'fixed';
  canvas.style.top = '0';
  canvas.style.left = '0';
  canvas.style.width = '100%';
  canvas.style.height = '100%';
  canvas.style.pointerEvents = 'none';
  canvas.style.zIndex = '9999';
  document.body.appendChild(canvas);

  const ctx = canvas.getContext('2d');
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;

  const particles = [];
  const maxParticles = 50;

  class Particle {
    constructor(x, y) {
      this.x = x;
      this.y = y;
      this.size = Math.random() * 3 + 1;
      this.speedX = (Math.random() - 0.5) * 2;
      this.speedY = (Math.random() - 0.5) * 2;
      this.life = 1;
      this.decay = Math.random() * 0.02 + 0.01;
      this.color = `rgba(183, 148, 255, ${this.life})`;
    }

    update() {
      this.x += this.speedX;
      this.y += this.speedY;
      this.life -= this.decay;
      this.color = `rgba(183, 148, 255, ${this.life})`;
    }

    draw() {
      ctx.fillStyle = this.color;
      ctx.shadowBlur = 10;
      ctx.shadowColor = this.color;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  document.addEventListener('mousemove', (e) => {
    if (particles.length < maxParticles) {
      particles.push(new Particle(e.clientX, e.clientY));
    }
  });

  function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    for (let i = particles.length - 1; i >= 0; i--) {
      particles[i].update();
      particles[i].draw();
      
      if (particles[i].life <= 0) {
        particles.splice(i, 1);
      }
    }
    
    requestAnimationFrame(animateParticles);
  }

  animateParticles();

  window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  });

  // ========== SMOOTH SCROLL ENHANCED ==========
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const href = this.getAttribute('href');
      if (href === '#' || href === '#top') {
        e.preventDefault();
        window.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
      } else {
        const target = document.querySelector(href);
        if (target) {
          e.preventDefault();
          target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
          });
        }
      }
    });
  });

  // ========== THEME SWITCHER (Bonus) ==========
  // Vous pouvez ajouter un bouton pour changer les couleurs dynamiquement
  const themes = {
    purple: { primary: '#b794ff', secondary: '#7058ff' },
    blue: { primary: '#5865f2', secondary: '#4752c4' },
    green: { primary: '#00ff7f', secondary: '#00c060' },
    red: { primary: '#ff4655', secondary: '#e0304a' }
  };

  window.switchTheme = function(themeName) {
    const theme = themes[themeName];
    if (theme) {
      document.documentElement.style.setProperty('--theme-primary', theme.primary);
      document.documentElement.style.setProperty('--theme-secondary', theme.secondary);
    }
  };

  // ========== LAZY LOADING IMAGES ==========
  const images = document.querySelectorAll('img[loading="lazy"]');
  
  if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src || img.src;
          imageObserver.unobserve(img);
        }
      });
    });

    images.forEach(img => imageObserver.observe(img));
  }

  // ========== PERFORMANCE MONITORING ==========
  console.log('%c🌙 Nightfall RP', 'font-size: 24px; font-weight: bold; color: #b794ff;');
  console.log('%cSite optimisé et chargé avec succès!', 'font-size: 14px; color: #00ff7f;');
  
  // Log performance
  window.addEventListener('load', () => {
    const loadTime = performance.now();
    console.log(`⚡ Page chargée en ${Math.round(loadTime)}ms`);
  });

})();
