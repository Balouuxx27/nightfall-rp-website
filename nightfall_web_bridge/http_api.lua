-- ============================================
-- NIGHTFALL RP - HTTP API POUR PROFILS
-- ============================================
-- Endpoint HTTP pour permettre à Render de récupérer
-- les données des joueurs même hors ligne

local SECRET = "7eaee28859e8fdc081956912cae6a2fb7bd90918dc605a09f3d505b1b795788f"

-- Route HTTP: /player?discordId=XXXXX OU /all-players
SetHttpHandler(function(req, res)
    -- Vérifier la méthode
    if req.method ~= 'GET' then
        res.writeHead(405, { ['Content-Type'] = 'application/json' })
        res.send(json.encode({ error = 'Method not allowed' }))
        return
    end
    
    -- Vérifier le secret
    local authHeader = req.headers['x-nightfall-secret'] or ''
    if authHeader ~= SECRET then
        res.writeHead(403, { ['Content-Type'] = 'application/json' })
        res.send(json.encode({ error = 'Forbidden' }))
        return
    end
    
    -- Parser l'URL
    local path = req.path or ''
    
    -- ROUTE 1: /all-players - Récupérer tous les joueurs
    if path == '/all-players' or string.match(path, '^/all%-players%?') then
        print("^3[Nightfall API] Récupération de tous les joueurs^0")
        
        MySQL.Async.fetchAll('SELECT citizenid, charinfo, job, money, last_updated FROM players ORDER BY last_updated DESC LIMIT 200', {}, function(playersData)
            if not playersData or #playersData == 0 then
                res.writeHead(200, { ['Content-Type'] = 'application/json' })
                res.send(json.encode({ players = {}, count = 0 }))
                return
            end
            
            local players = {}
            for _, row in ipairs(playersData) do
                local charinfo = json.decode(row.charinfo or '{}')
                local job = json.decode(row.job or '{}')
                local money = json.decode(row.money or '{}')
                
                table.insert(players, {
                    citizenid = row.citizenid,
                    firstname = charinfo.firstname or 'Unknown',
                    lastname = charinfo.lastname or 'Player',
                    phone = charinfo.phone or 'N/A',
                    birthdate = charinfo.birthdate or 'N/A',
                    gender = charinfo.gender or 0,
                    job = {
                        name = job.name or 'unemployed',
                        label = job.label or 'Sans emploi',
                        grade = job.grade or { name = '0', level = 0 }
                    },
                    money = {
                        cash = money.cash or 0,
                        bank = money.bank or 0
                    },
                    last_updated = row.last_updated
                })
            end
            
            print("^2[Nightfall API] " .. #players .. " joueurs envoyés^0")
            
            res.writeHead(200, { ['Content-Type'] = 'application/json' })
            res.send(json.encode({ players = players, count = #players }))
        end)
        return
    end
    
    -- ROUTE 2: /player?discordId=XXXXX - Récupérer un joueur spécifique
    local discordId = nil
    if string.match(path, '^/player%?discordId=') then
        discordId = string.match(path, 'discordId=([^&]+)')
    end
    
    if not discordId then
        res.writeHead(400, { ['Content-Type'] = 'application/json' })
        res.send(json.encode({ error = 'Discord ID required or use /all-players' }))
        return
    end
    
    print("^3[Nightfall API] Recherche du profil pour Discord ID: " .. discordId .. "^0")
    
    -- Chercher dans discord_ids
    MySQL.Async.fetchAll('SELECT license2 FROM discord_ids WHERE discord_id = @discordId', {
        ['@discordId'] = discordId
    }, function(result)
        if not result or #result == 0 then
            print("^1[Nightfall API] Aucune licence trouvée pour Discord ID: " .. discordId .. "^0")
            res.writeHead(404, { ['Content-Type'] = 'application/json' })
            res.send(json.encode({ error = 'No license found' }))
            return
        end
        
        local license2 = result[1].license2
        local fullLicense = 'license2:' .. license2
        
        print("^3[Nightfall API] License trouvée: " .. fullLicense .. "^0")
        
        -- Récupérer les données du joueur
        MySQL.Async.fetchAll('SELECT * FROM players WHERE license2 = @license LIMIT 1', {
            ['@license'] = fullLicense
        }, function(playerData)
            if not playerData or #playerData == 0 then
                print("^1[Nightfall API] Aucun personnage trouvé pour license: " .. fullLicense .. "^0")
                res.writeHead(404, { ['Content-Type'] = 'application/json' })
                res.send(json.encode({ error = 'No character found' }))
                return
            end
            
            local row = playerData[1]
            
            print("^2[Nightfall API] Personnage trouvé: " .. row.citizenid .. "^0")
            
            -- Récupérer les véhicules
            MySQL.Async.fetchAll('SELECT vehicle, plate, state, engine, body FROM player_vehicles WHERE citizenid = @citizenid ORDER BY vehicle ASC', {
                ['@citizenid'] = row.citizenid
            }, function(vehicles)
                -- Parser les JSON
                local charinfo = json.decode(row.charinfo or '{}')
                local job = json.decode(row.job or '{}')
                local money = json.decode(row.money or '{}')
                local position = json.decode(row.position or '{}')
                local metadata = json.decode(row.metadata or '{}')
                
                -- Construire la réponse complète avec métadonnées
                local response = {
                    discordId = discordId,
                    citizenid = row.citizenid,
                    charinfo = charinfo,
                    job = job,
                    money = money,
                    position = position,
                    metadata = {
                        hunger = metadata.hunger or 100,
                        thirst = metadata.thirst or 100,
                        stress = metadata.stress or 0,
                        health = metadata.health or 200,
                        maxHealth = 200,
                        armor = metadata.armor or 0,
                        isdead = metadata.isdead or false,
                        inlaststand = metadata.inlaststand or false
                    },
                    vehicles = vehicles or {},
                    lastUpdated = row.last_updated,
                    source = 'database'
                }
                
                print("^2[Nightfall API] Profil envoyé: " .. #(vehicles or {}) .. " véhicules^0")
                
                res.writeHead(200, { ['Content-Type'] = 'application/json' })
                res.send(json.encode(response))
            end)
        end)
    end)
end)

print("^2[Nightfall API] HTTP Handler enregistré^0")
print("^2[Nightfall API] Routes disponibles:^0")
print("^2[Nightfall API]   - GET /player?discordId=XXXXX^0")
print("^2[Nightfall API]   - GET /all-players^0")
