// Lightbox ultra dynamique pour les images
(function() {
  'use strict';

  // Créer le modal lightbox
  const lightbox = document.createElement('div');
  lightbox.className = 'lightbox-modal';
  lightbox.innerHTML = `
    <div class="lightbox-content">
      <div class="lightbox-close">×</div>
      <img src="" alt="">
      <div class="lightbox-info">
        <h3></h3>
        <p></p>
      </div>
    </div>
  `;
  document.body.appendChild(lightbox);

  const lightboxImg = lightbox.querySelector('img');
  const lightboxTitle = lightbox.querySelector('h3');
  const lightboxDesc = lightbox.querySelector('p');
  const closeBtn = lightbox.querySelector('.lightbox-close');

  // Fonction pour ouvrir la lightbox
  function openLightbox(imgSrc, title, description) {
    lightboxImg.src = imgSrc;
    lightboxTitle.textContent = title;
    lightboxDesc.textContent = description;
    lightbox.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  // Fonction pour fermer la lightbox
  function closeLightbox() {
    lightbox.classList.remove('active');
    document.body.style.overflow = '';
    lightbox.scrollTop = 0;
  }

  // Event listeners
  closeBtn.addEventListener('click', closeLightbox);
  
  lightbox.addEventListener('click', (e) => {
    if (e.target === lightbox) {
      closeLightbox();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && lightbox.classList.contains('active')) {
      closeLightbox();
    }
  });

  // Ajouter les events sur toutes les images d'histoire
  document.addEventListener('DOMContentLoaded', () => {
    const histoireItems = document.querySelectorAll('.histoire-item');
    
    histoireItems.forEach(item => {
      item.addEventListener('click', () => {
        const img = item.querySelector('img');
        const title = item.querySelector('h3').textContent;
        const desc = item.querySelector('p').textContent;
        openLightbox(img.src, title, desc);
      });
    });
  });
})();
