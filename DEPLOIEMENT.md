# 🚀 Guide de Déploiement - Nightfall RP

## ⚠️ IMPORTANT : Sécurité

**Ne jamais héberger sur ton PC personnel !**
- ❌ Ton IP publique sera exposée
- ❌ Pas de protection contre les attaques DDoS
- ❌ Risque d'accès à ton réseau domestique
- ❌ Aucune protection firewall professionnelle

**✅ Solution recommandée : Hébergement cloud gratuit**

---

## 🎯 Option 1 : Render.com (RECOMMANDÉ - Gratuit)

### Avantages
- ✅ 100% gratuit (avec limitations)
- ✅ Protection DDoS intégrée
- ✅ SSL/HTTPS automatique
- ✅ Sous-domaine gratuit : `nightfallrp.onrender.com`
- ✅ Backups automatiques
- ✅ Logs de sécurité

### Limitations (Plan gratuit)
- ⏱️ Site dort après 15 min d'inactivité (redémarre en ~30 secondes)
- 📊 750 heures/mois (suffisant pour un serveur RP)

### Étapes de déploiement

1. **Créer un compte GitHub** (si pas déjà fait)
   - Va sur https://github.com
   - Crée un compte gratuit

2. **Créer un dépôt GitHub**
   - Clique sur "New repository"
   - Nom : `nightfall-rp-website`
   - Public ou Private (au choix)
   - Clique "Create repository"

3. **Pousser ton code sur GitHub**
   ```powershell
   # Dans VS Code, ouvre un terminal PowerShell
   cd "c:\Users\Balouuxx\Documents\Page Web"
   
   # Initialiser Git
   git init
   git add .
   git commit -m "Site Nightfall RP initial"
   
   # Lier au dépôt GitHub (remplace USERNAME par ton nom d'utilisateur)
   git remote add origin https://github.com/USERNAME/nightfall-rp-website.git
   git branch -M main
   git push -u origin main
   ```

4. **Déployer sur Render**
   - Va sur https://render.com
   - Clique "Sign Up" → "Sign Up with GitHub"
   - Clique "New +" → "Web Service"
   - Sélectionne ton dépôt `nightfall-rp-website`
   - Configuration :
     - **Name** : `nightfallrp`
     - **Environment** : `Node`
     - **Build Command** : `npm install`
     - **Start Command** : `npm start`
     - **Plan** : `Free`
   - Clique "Create Web Service"

5. **Variables d'environnement** (dans Render)
   - Va dans l'onglet "Environment"
   - Ajoute :
     - `PORT` = `5173`
     - `STAFF_PASSWORD` = `2025`
     - `NODE_ENV` = `production`

6. **Ton site sera accessible à :**
   - `https://nightfallrp.onrender.com`

---

## 🚂 Option 2 : Railway.app (Gratuit au début)

### Avantages
- ✅ Pas de mise en veille (reste actif 24/7)
- ✅ 500 heures gratuites/mois pour commencer
- ✅ Plus rapide que Render
- ✅ Sous-domaine : `nightfallrp.up.railway.app`

### Coût après période gratuite
- 💰 ~$5/mois après épuisement des heures gratuites

### Étapes de déploiement

1. **Installer Railway CLI**
   ```powershell
   npm install -g @railway/cli
   ```

2. **Se connecter et déployer**
   ```powershell
   cd "c:\Users\Balouuxx\Documents\Page Web"
   railway login
   railway init
   railway up
   ```

3. **Configurer les variables**
   ```powershell
   railway variables set STAFF_PASSWORD=2025
   railway variables set NODE_ENV=production
   ```

4. **Obtenir l'URL**
   ```powershell
   railway domain
   ```

---

## 🌊 Option 3 : Vercel (Gratuit)

### Limitations
- ⚠️ Optimisé pour sites statiques (nécessite adaptation)
- Requiert conversion en API Routes (plus technique)

---

## 🏠 Option 4 : Hébergement personnel avec DuckDNS (Déconseillé)

**Si tu insistes vraiment**, voici comment minimiser les risques :

### Prérequis
1. Routeur/Box internet avec accès admin
2. Ordinateur allumé 24/7
3. Connexion internet stable

### Configuration DuckDNS (Sous-domaine gratuit)

1. **Créer un compte DuckDNS**
   - Va sur https://www.duckdns.org
   - Connecte-toi avec Google/GitHub
   - Crée un sous-domaine : `nightfallrp.duckdns.org`

2. **Installer le client DuckDNS** (pour mettre à jour ton IP)
   - Télécharge le client Windows
   - Configure-le avec ton token
   - Lance-le au démarrage de Windows

3. **Ouvrir le port sur ta box**
   - Accède à l'interface de ta box (192.168.1.1 ou 192.168.0.1)
   - Trouve "NAT/PAT" ou "Redirection de ports"
   - Redirige le port **80** vers ton PC port **5173**
   - Trouve l'IP locale de ton PC : `ipconfig` dans PowerShell

4. **Modifier le port du serveur** (pour le port 80)
   - Dans `server.js`, change `const PORT = 5173;` en `const PORT = 80;`

5. **Lancer le serveur**
   ```powershell
   cd "c:\Users\Balouuxx\Documents\Page Web"
   npm start
   ```

6. **Ton site sera accessible à :**
   - `http://nightfallrp.duckdns.org`

### Mesures de sécurité supplémentaires
- 🔒 Active le pare-feu Windows
- 🔒 Ne partage JAMAIS ton IP ou sous-domaine publiquement
- 🔒 Surveille les logs du serveur
- 🔒 Change régulièrement le mot de passe staff
- 🔒 Garde ton PC à jour (Windows Update)

---

## 💰 Option 5 : VPS Payant (Le plus professionnel)

### Services recommandés
- **Contabo** : ~4€/mois (200 GB, 4 GB RAM)
- **OVH** : ~3-5€/mois
- **Ionos** : ~1€/mois (premier mois)

### Avantages
- ✅ Contrôle total
- ✅ Performances maximales
- ✅ Aucune limitation
- ✅ IP dédiée

### Configuration VPS (Ubuntu)

```bash
# Se connecter en SSH
ssh root@TON_IP

# Installer Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Installer PM2 (gestionnaire de processus)
npm install -g pm2

# Cloner le projet
git clone https://github.com/USERNAME/nightfall-rp-website.git
cd nightfall-rp-website
npm install

# Lancer avec PM2
pm2 start server.js --name nightfallrp
pm2 startup
pm2 save

# Installer Nginx (proxy)
apt install nginx

# Configurer Nginx
nano /etc/nginx/sites-available/nightfallrp
```

**Configuration Nginx :**
```nginx
server {
    listen 80;
    server_name nightfallrp.ton-domaine.com;

    location / {
        proxy_pass http://localhost:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Activer le site
ln -s /etc/nginx/sites-available/nightfallrp /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx

# Installer SSL gratuit (Let's Encrypt)
apt install certbot python3-certbot-nginx
certbot --nginx -d nightfallrp.ton-domaine.com
```

---

## 🔧 Fichiers nécessaires avant déploiement

### `.gitignore` (à créer)
```
node_modules/
.env
api/*.json
*.log
```

### `.env` (à créer pour variables sensibles)
```
PORT=5173
STAFF_PASSWORD=2025
NODE_ENV=production
```

### Mettre à jour `server.js` pour lire les variables d'environnement
```javascript
const PORT = process.env.PORT || 5173;
const STAFF_PASSWORD = process.env.STAFF_PASSWORD || '2025';
```

---

## 📋 Checklist avant déploiement

- [ ] Créer `.gitignore`
- [ ] Créer `.env` (ne PAS le commiter !)
- [ ] Tester localement : `npm start`
- [ ] Vérifier que toutes les images chargent
- [ ] Tester le panel staff
- [ ] Vérifier la carte live
- [ ] Configurer les variables d'environnement sur Render/Railway
- [ ] Pousser le code sur GitHub
- [ ] Déployer sur la plateforme choisie

---

## 🔗 Liens utiles

- **Render** : https://render.com
- **Railway** : https://railway.app
- **GitHub** : https://github.com
- **DuckDNS** : https://www.duckdns.org
- **Let's Encrypt** : https://letsencrypt.org

---

## 📞 Support

En cas de problème :
1. Vérifie les logs du serveur
2. Vérifie que le port 5173 est bien ouvert
3. Vérifie les variables d'environnement
4. Redémarre le service

---

## 🎯 Recommandation finale

**Pour un serveur FiveM public : Utilise Render.com (gratuit)**

C'est le meilleur compromis entre :
- Sécurité
- Simplicité
- Coût (gratuit)
- Performance acceptable

Tu pourras toujours migrer vers un VPS payant plus tard si ton serveur décolle !
