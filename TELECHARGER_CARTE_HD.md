# CARTE SATELLITE HD POUR GTA V

## Option 1: Atlas HD (RECOMMANDÉ)
**Télécharge cette carte satellite HD 4096x4096:**
https://cdn.discordapp.com/attachments/687942165696086028/784114590957477918/gta_map_satellite.jpg

Renomme-la en `gta-map.jpg` et remplace le fichier dans `assets/img/`

## Option 2: GitHub Atlas
https://github.com/Sighmir/fivem-minimap/raw/master/assets/satellite.jpg

## Option 3: Carte vectorielle propre
https://s2.gta.fandom.com/pl/images/3/3c/LOSSanctuario.jpg

## Installation

1. Télécharge une des images ci-dessus
2. Renomme-la en `gta-map.jpg`
3. Remplace le fichier dans: `c:\Users\Balouuxx\Documents\Page Web\assets\img\gta-map.jpg`
4. Actualise la page staff (Ctrl+F5)

## Caractéristiques de la meilleure carte

- **Résolution**: 4096x4096 pixels
- **Format**: JPEG ou PNG
- **Poids**: Entre 500 KB et 2 MB (compression optimale)
- **Type**: Satellite/aérienne pour correspondre aux coordonnées GTA V
- **Orientation**: Nord en haut

## Vérification

Après remplacement, vérifie la taille:
```powershell
(Get-Item "assets/img/gta-map.jpg").Length / 1KB
```

Devrait être entre 500 et 2000 KB pour une bonne qualité.

## Coordonnées ajustées

J'ai déjà modifié `staff.js` avec les bounds corrects:
- minX: -4000, maxX: 4000
- minY: -4000, maxY: 8000

Cela correspond mieux à la carte satellite standard de GTA V.
