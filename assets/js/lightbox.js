// Lightbox ultra dynamique pour les images
(function() {
  'use strict';

  // Créer le modal lightbox - SÉCURISÉ sans innerHTML
  const lightbox = document.createElement('div');
  lightbox.className = 'lightbox-modal';
  
  const content = document.createElement('div');
  content.className = 'lightbox-content';
  
  const closeBtn = document.createElement('div');
  closeBtn.className = 'lightbox-close';
  closeBtn.textContent = '×';
  
  const img = document.createElement('img');
  img.src = '';
  img.alt = '';
  
  const info = document.createElement('div');
  info.className = 'lightbox-info';
  
  const title = document.createElement('h3');
  const desc = document.createElement('p');
  
  info.appendChild(title);
  info.appendChild(desc);
  
  content.appendChild(closeBtn);
  content.appendChild(img);
  content.appendChild(info);
  
  lightbox.appendChild(content);
  document.body.appendChild(lightbox);

  const lightboxImg = img;
  const lightboxTitle = title;
  const lightboxDesc = desc;

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
