# Nightfall RP - Web Integration

## Installation

1. **Copie ce dossier** dans ton serveur FiveM:
   ```
   resources/[local]/nightfall-web/
   ```

2. **Modifie `server.lua`** si nécessaire:
   - Change `WEBHOOK_URL` si ton site web n'est pas sur `127.0.0.1:5173`
   - Change `SECRET` pour correspondre à `api/staff_config.json`

3. **Ajoute dans `server.cfg`**:
   ```cfg
   ensure nightfall-web
   ```

4. **Redémarre ton serveur FiveM** ou tape:
   ```
   restart nightfall-web
   ```

## Vérification

Dans la console FiveM, tu devrais voir:
```
[Nightfall Web] Resource démarrée
[Nightfall Web] ESX détecté (ou QBCore)
[Nightfall Web] Données envoyées: X joueur(s)
```

## Configuration

### Si ton site web est sur un autre serveur

Change l'IP dans `server.lua`:
```lua
local WEBHOOK_URL = "http://TON_IP_PUBLIQUE:5173/api/fivem/players"
```

### Si tu as un autre framework

Le script détecte automatiquement ESX et QBCore.
Si tu n'as pas de framework, les jobs seront affichés comme "unemployed".

## Troubleshooting

### Erreur 403 (Forbidden)
- Vérifie que `SECRET` dans `server.lua` correspond à `fivemSecret` dans `api/staff_config.json`

### Erreur de connexion
- Vérifie que ton site Node.js est bien démarré sur le port 5173
- Vérifie l'URL dans `WEBHOOK_URL`

### Pas de données sur le site
1. Vérifie la console FiveM pour les erreurs
2. Connecte-toi au panel staff avec le mot de passe `2025`
3. Les joueurs devraient apparaître après 2 secondes
