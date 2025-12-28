-- ============================================
-- NIGHTFALL RP - HTTP API POUR PROFILS
-- ============================================
-- Endpoint HTTP pour permettre à Render de récupérer
-- les données des joueurs même hors ligne

local SECRET = "7eaee28859e8fdc081956912cae6a2fb7bd90918dc605a09f3d505b1b795788f"

-- Route HTTP: /player?discordId=XXXXX
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
    local discordId = nil
    
    -- Extraire le discordId depuis /player?discordId=XXXXX
    if string.match(path, '^/player%?discordId=') then
        discordId = string.match(path, 'discordId=([^&]+)')
    end
    
    if not discordId then
        res.writeHead(400, { ['Content-Type'] = 'application/json' })
        res.send(json.encode({ error = 'Discord ID required' }))
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
                
                -- Construire la réponse
                local response = {
                    discordId = discordId,
                    citizenid = row.citizenid,
                    charinfo = charinfo,
                    job = job,
                    money = money,
                    position = position,
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
print("^2[Nightfall API] Route: GET /player?discordId=XXXXX^0")
