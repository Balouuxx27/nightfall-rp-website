# 🔄 Mise à jour du Bridge FiveM

## ⚠️ Action requise sur le serveur FiveM

Le bridge FiveM a été mis à jour pour envoyer les données complètes des joueurs au site web. Tu dois **remplacer le fichier** sur ton serveur FiveM.

### 📍 Emplacement du fichier

```
h:\Serveur fivem\txData\QBCore_C5E87A.base\resources\nightfall_web_bridge\server.lua
```

### 🔧 Instructions

1. **Arrête le serveur FiveM**
2. **Copie le nouveau fichier** depuis :
   ```
   c:\Users\Balouuxx\Documents\Page Web\nightfall_web_bridge\server.lua
   ```
   vers :
   ```
   h:\Serveur fivem\txData\QBCore_C5E87A.base\resources\nightfall_web_bridge\server.lua
   ```
3. **Redémarre le serveur FiveM**

### 📦 Ce qui a changé

**Avant :**
- Envoyait uniquement : nom, job, position, ping

**Maintenant :**
- Envoie **toutes les données** :
  - Discord ID
  - Citizen ID
  - Charinfo (prénom, nom, téléphone, date de naissance)
  - Job complet (nom, label, grade)
  - Argent (cash, banque)
  - Position
  - Véhicules (à venir)

### ✅ Avantages

- ✅ **Plus de problème de firewall MySQL** (ETIMEDOUT résolu)
- ✅ **Suppression de 5 variables d'environnement** sur Render
- ✅ **Données en temps réel** (mise à jour toutes les 2 secondes)
- ✅ **Moins de latence** (pas de requête MySQL depuis Render)
- ✅ **Architecture plus simple** et robuste

### 🗑️ Variables à supprimer sur Render

Une fois que le bridge est mis à jour et que tout fonctionne, tu peux **supprimer ces variables d'environnement** sur Render :

- `DB_HOST`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `DB_PORT`

Ces variables ne sont plus utilisées par le site web.

### 🧪 Test

1. Connecte-toi au serveur FiveM
2. Va sur https://nightfall-rp.onrender.com/player
3. Tu devrais voir ton profil avec toutes les données
4. Les données se mettent à jour toutes les 2 secondes quand tu es connecté

### 📋 Logs

Le bridge affiche maintenant moins de logs (pas de spam) :
- ✅ Succès : silencieux (pas de log toutes les 2 secondes)
- ❌ Erreur : log détaillé (403, timeout, etc.)

---

## 💡 Note technique

**Architecture actuelle :**
```
FiveM (accès DB local) → Webhook Render → Cache mémoire → API /player
```

Le serveur FiveM accède directement à sa base de données MySQL locale (pas de problème de firewall), puis envoie les données à Render via HTTPS. Render stocke ces données en mémoire et les sert aux utilisateurs.
