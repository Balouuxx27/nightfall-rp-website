# 🔄 Mise à jour du Bridge FiveM - V2.0

## ⚠️ Action requise sur le serveur FiveM

Le bridge FiveM a été **complètement refondu** pour permettre l'accès aux profils **même hors ligne**.

### 📍 Fichiers à copier

Copie **TOUT LE DOSSIER** depuis :
```
c:\Users\Balouuxx\Documents\Page Web\nightfall_web_bridge\
```

Vers :
```
h:\Serveur fivem\txData\QBCore_C5E87A.base\resources\nightfall_web_bridge\
```

**Fichiers inclus :**
- ✅ `fxmanifest.lua` (mis à jour)
- ✅ `server.lua` (amélioré)
- ✅ `http_api.lua` (NOUVEAU)

### 🔧 Instructions

1. **Arrête le serveur FiveM**
2. **Copie tout le dossier** (remplace les anciens fichiers)
3. **Redémarre le serveur FiveM**

### 📦 Ce qui a changé

**Version 1.0 (ancienne) :**
- Envoi de données basiques toutes les 2 secondes
- Profil accessible **uniquement si connecté**

**Version 2.0 (nouvelle) :**
- ✅ Envoi de **données complètes** (Discord ID, charinfo, job, money, vehicles)
- ✅ **Serveur HTTP intégré** pour requêtes de profil
- ✅ Profil accessible **même hors ligne**
- ✅ Pas de problème de firewall (bridge a accès local à MySQL)

### 🎯 Fonctionnement

**Joueur CONNECTÉ :**
```
FiveM → Webhook Render (toutes les 2s) → Cache → API /player
```

**Joueur DÉCONNECTÉ :**
```
Render → HTTP Request FiveM → Bridge cherche dans DB locale → Retourne profil
```

### ✅ Avantages

- ✅ **Profil accessible 24/7** (même déconnecté)
- ✅ **Toutes les données** : stats, santé, argent, véhicules, job
- ✅ **Pas de firewall MySQL** (ETIMEDOUT résolu)
- ✅ **Données en temps réel** quand connecté
- ✅ **Dernières données sauvegardées** quand déconnecté

### 🌐 Route HTTP exposée

Le bridge expose maintenant :
```
GET http://IP_SERVEUR:30120/player?discordId=XXXXX
Header: x-nightfall-secret: SECRET
```

Cette route permet à Render de récupérer les données depuis la base MySQL locale du serveur FiveM.

### 🧪 Test

1. **Test ONLINE** : Connecte-toi au serveur → Va sur `/player` → Données en temps réel
2. **Test OFFLINE** : Déconnecte-toi du serveur → Rafraîchis `/player` → Dernières données affichées

### 📋 Logs

**Démarrage :**
```lua
[Nightfall Web] QBCore détecté
[Nightfall Web] Resource démarrée
[Nightfall API] HTTP Handler enregistré
[Nightfall API] Route: GET /player?discordId=XXXXX
```

**Requête profil hors ligne :**
```lua
[Nightfall API] Recherche du profil pour Discord ID: 543121916114894848
[Nightfall API] License trouvée: license2:XXXXX
[Nightfall API] Personnage trouvé: ABC123
[Nightfall API] Profil envoyé: 5 véhicules
```

---

## 🗑️ Variables Render (GARDER)

Tu dois **GARDER** ces variables d'environnement sur Render :

- ✅ `FIVEM_SERVER_IP` = `vavagame.perf-host.online:30120` (pour HTTP requests)
- ✅ `FIVEM_SECRET` = ton secret
- ❌ `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT` (PAS UTILISÉES)

---

## 💡 Architecture finale

```
┌─────────────────────────────────────────────────────────┐
│                    JOUEUR CONNECTÉ                      │
│  FiveM Server → Webhook Render → Cache → API /player   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   JOUEUR DÉCONNECTÉ                     │
│  Render → HTTP Request → FiveM Bridge → MySQL Local     │
│                       → Retourne profil                 │
└─────────────────────────────────────────────────────────┘
```

**Résultat** : Profil accessible 24/7, données à jour quand connecté, dernières données quand déconnecté !
