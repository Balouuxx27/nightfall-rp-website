// Effets dynamiques ultra spectaculaires
(function() {
  'use strict';

  // Parallax sur les sections au scroll
  let ticking = false;
  
  function updateParallax() {
    const scrolled = window.pageYOffset;
    
    // Parallax sur le hero
    const hero = document.querySelector('.hero');
    if (hero) {
      hero.style.transform = `translateY(${scrolled * 0.3}px)`;
    }

    // Parallax sur les cards d'histoire
    const histoireItems = document.querySelectorAll('.histoire-item');
    histoireItems.forEach((item, index) => {
      const rect = item.getBoundingClientRect();
      const offset = (window.innerHeight - rect.top) * 0.05;
      if (rect.top < window.innerHeight && rect.bottom > 0) {
        item.style.transform = `translateY(${-offset}px)`;
      }
    });

    ticking = false;
  }

  window.addEventListener('scroll', () => {
    if (!ticking) {
      window.requestAnimationFrame(updateParallax);
      ticking = true;
    }
  });

  // Effet de particules qui suivent la souris
  const canvas = document.createElement('canvas');
  canvas.style.position = 'fixed';
  canvas.style.top = '0';
  canvas.style.left = '0';
  canvas.style.width = '100%';
  canvas.style.height = '100%';
  canvas.style.pointerEvents = 'none';
  canvas.style.zIndex = '9998';
  canvas.style.opacity = '0.6';
  document.body.appendChild(canvas);

  const ctx = canvas.getContext('2d');
  let particles = [];
  let mouseX = 0;
  let mouseY = 0;

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  class Particle {
    constructor(x, y) {
      this.x = x;
      this.y = y;
      this.size = Math.random() * 3 + 1;
      this.speedX = Math.random() * 3 - 1.5;
      this.speedY = Math.random() * 3 - 1.5;
      this.life = 100;
      this.color = Math.random() > 0.5 ? 'rgba(183, 148, 255, 0.8)' : 'rgba(53, 209, 255, 0.8)';
    }

    update() {
      this.x += this.speedX;
      this.y += this.speedY;
      this.life -= 2;
      if (this.size > 0.2) this.size -= 0.05;
    }

    draw() {
      ctx.fillStyle = this.color;
      ctx.shadowBlur = 15;
      ctx.shadowColor = this.color;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function createParticles(x, y) {
    for (let i = 0; i < 3; i++) {
      particles.push(new Particle(x, y));
    }
  }

  function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    particles = particles.filter(p => p.life > 0);
    
    particles.forEach(particle => {
      particle.update();
      particle.draw();
    });

    requestAnimationFrame(animateParticles);
  }

  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    
    if (Math.random() > 0.8) {
      createParticles(mouseX, mouseY);
    }
  });

  animateParticles();

  // Animations au scroll avec IntersectionObserver
  const observerOptions = {
    threshold: 0.15,
    rootMargin: '0px 0px -50px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0) scale(1)';
      }
    });
  }, observerOptions);

  // Observer les tiles, steps, etc.
  document.addEventListener('DOMContentLoaded', () => {
    const animatedElements = document.querySelectorAll('.tile, .step, .acc, .callout');
    animatedElements.forEach((el, index) => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(30px) scale(0.95)';
      el.style.transition = `all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) ${index * 0.1}s`;
      observer.observe(el);
    });

    // Effet de shake sur les boutons au hover
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(btn => {
      btn.addEventListener('mouseenter', () => {
        btn.style.animation = 'btnShake 0.5s ease';
      });
      btn.addEventListener('animationend', () => {
        btn.style.animation = '';
      });
    });
  });

  // Animation CSS pour le shake
  const style = document.createElement('style');
  style.textContent = `
    @keyframes btnShake {
      0%, 100% { transform: translateX(0) translateY(0); }
      10%, 30%, 50%, 70%, 90% { transform: translateX(-2px) translateY(-2px); }
      20%, 40%, 60%, 80% { transform: translateX(2px) translateY(2px); }
    }
  `;
  document.head.appendChild(style);

  // Effet de glow pulsant sur le logo
  const brandMark = document.querySelector('.brand__mark');
  if (brandMark) {
    setInterval(() => {
      brandMark.style.animation = 'none';
      setTimeout(() => {
        brandMark.style.animation = 'logoPulse 2.2s ease-in-out infinite';
      }, 10);
    }, 5000);
  }

  // Effet de ripple sur les clics
  document.addEventListener('click', (e) => {
    const ripple = document.createElement('div');
    ripple.style.position = 'fixed';
    ripple.style.left = e.clientX + 'px';
    ripple.style.top = e.clientY + 'px';
    ripple.style.width = '10px';
    ripple.style.height = '10px';
    ripple.style.borderRadius = '50%';
    ripple.style.background = 'rgba(183, 148, 255, 0.6)';
    ripple.style.boxShadow = '0 0 20px rgba(183, 148, 255, 0.8)';
    ripple.style.transform = 'translate(-50%, -50%)';
    ripple.style.pointerEvents = 'none';
    ripple.style.zIndex = '9999';
    ripple.style.animation = 'rippleEffect 0.8s ease-out forwards';
    
    document.body.appendChild(ripple);
    
    setTimeout(() => ripple.remove(), 800);
  });

  const rippleStyle = document.createElement('style');
  rippleStyle.textContent = `
    @keyframes rippleEffect {
      0% {
        width: 10px;
        height: 10px;
        opacity: 1;
      }
      100% {
        width: 100px;
        height: 100px;
        opacity: 0;
      }
    }
  `;
  document.head.appendChild(rippleStyle);

})();
