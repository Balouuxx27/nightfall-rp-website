-- ============================================
-- NIGHTFALL RP - WEB INTEGRATION
-- ============================================
-- Ce script envoie les données joueurs vers le site web
-- toutes les 2 secondes pour afficher les blips en temps réel

-- CONFIGURATION
local WEBHOOK_URL = "https://nightfall-rp.onrender.com/api/fivem/players"  -- URL du site web déployé sur Render
local SECRET = "7eaee28859e8fdc081956912cae6a2fb7bd90918dc605a09f3d505b1b795788f"  -- Doit correspondre au FIVEM_SECRET dans .env
local UPDATE_INTERVAL = 2000  -- Mise à jour toutes les 2 secondes (2000ms)
local HTTP_PORT = 30121  -- Port HTTP pour les requêtes de profil (FiveM server port + 1)

-- Framework detection
local Framework = nil
local FrameworkName = "none"

Citizen.CreateThread(function()
    -- Détection ESX
    if GetResourceState('es_extended') == 'started' then
        ESX = exports['es_extended']:getSharedObject()
        Framework = ESX
        FrameworkName = "esx"
        print("^2[Nightfall Web] ESX détecté^0")
    -- Détection QBCore
    elseif GetResourceState('qb-core') == 'started' then
        QBCore = exports['qb-core']:GetCoreObject()
        Framework = QBCore
        FrameworkName = "qbcore"
        print("^2[Nightfall Web] QBCore détecté^0")
    else
        print("^3[Nightfall Web] Aucun framework détecté (ESX/QBCore) - Job sera 'unemployed'^0")
    end
end)

-- Fonction pour récupérer les données complètes du joueur
function GetPlayerData(playerId)
    local defaultData = {
        discordId = nil,
        citizenid = nil,
        charinfo = { firstname = "Unknown", lastname = "Player", phone = "N/A", birthdate = "N/A" },
        job = { name = "unemployed", label = "Unemployed", grade = { name = "0", level = 0 } },
        money = { cash = 0, bank = 0 },
        position = { x = 0, y = 0, z = 0 },
        vehicles = {}
    }

    -- Récupérer Discord ID
    local identifiers = GetPlayerIdentifiers(playerId)
    for _, id in ipairs(identifiers) do
        if string.match(id, "discord:") then
            defaultData.discordId = string.gsub(id, "discord:", "")
            break
        end
    end

    if FrameworkName == "qbcore" and Framework then
        local Player = Framework.Functions.GetPlayer(playerId)
        if Player and Player.PlayerData then
            local pd = Player.PlayerData
            
            -- Récupérer l'entité du ped pour les stats en temps réel
            local ped = GetPlayerPed(playerId)
            local health = GetEntityHealth(ped)
            local maxHealth = GetEntityMaxHealth(ped)
            local armor = GetPedArmour(ped)
            
            -- Récupérer le téléphone depuis lb-phone
            local phoneNumber = pd.charinfo and pd.charinfo.phone or "N/A"
            if pd.citizenid then
                local phoneResult = MySQL.Sync.fetchAll('SELECT phone_number FROM phone_phones WHERE id = @citizenid LIMIT 1', {
                    ['@citizenid'] = pd.citizenid
                })
                if phoneResult and #phoneResult > 0 then
                    phoneNumber = phoneResult[1].phone_number
                end
            end
            
            return {
                discordId = defaultData.discordId,
                citizenid = pd.citizenid or nil,
                charinfo = {
                    firstname = pd.charinfo and pd.charinfo.firstname or "Unknown",
                    lastname = pd.charinfo and pd.charinfo.lastname or "Player",
                    phone = phoneNumber,
                    birthdate = pd.charinfo and pd.charinfo.birthdate or "N/A",
                    gender = pd.charinfo and pd.charinfo.gender or 0  -- 0 = homme, 1 = femme
                },
                job = {
                    name = pd.job and pd.job.name or "unemployed",
                    label = pd.job and pd.job.label or "Unemployed",
                    grade = {
                        name = pd.job and pd.job.grade and pd.job.grade.name or "0",
                        level = pd.job and pd.job.grade and pd.job.grade.level or 0
                    }
                },
                money = {
                    cash = pd.money and pd.money.cash or 0,
                    bank = pd.money and pd.money.bank or 0
                },
                position = {
                    x = math.floor(GetEntityCoords(ped).x),
                    y = math.floor(GetEntityCoords(ped).y),
                    z = math.floor(GetEntityCoords(ped).z)
                },
                metadata = {
                    hunger = pd.metadata and pd.metadata.hunger or 100,
                    thirst = pd.metadata and pd.metadata.thirst or 100,
                    stress = pd.metadata and pd.metadata.stress or 0,
                    health = health,
                    maxHealth = maxHealth,
                    armor = armor,
                    isdead = pd.metadata and pd.metadata.isdead or false,
                    inlaststand = pd.metadata and pd.metadata.inlaststand or false
                },
                vehicles = {} -- Véhicules chargés depuis la DB plus tard si besoin
            }
        end
    elseif FrameworkName == "esx" and Framework then
        local xPlayer = Framework.GetPlayerFromId(playerId)
        if xPlayer then
            return {
                discordId = defaultData.discordId,
                citizenid = xPlayer.identifier or nil,
                charinfo = {
                    firstname = xPlayer.getName() or "Unknown",
                    lastname = "Player",
                    phone = "N/A",
                    birthdate = "N/A"
                },
                job = {
                    name = xPlayer.job.name or "unemployed",
                    label = xPlayer.job.label or "Unemployed",
                    grade = {
                        name = xPlayer.job.grade_label or "0",
                        level = xPlayer.job.grade or 0
                    }
                },
                money = {
                    cash = xPlayer.getMoney() or 0,
                    bank = xPlayer.getAccount('bank').money or 0
                },
                position = {
                    x = math.floor(GetEntityCoords(GetPlayerPed(playerId)).x),
                    y = math.floor(GetEntityCoords(GetPlayerPed(playerId)).y),
                    z = math.floor(GetEntityCoords(GetPlayerPed(playerId)).z)
                },
                vehicles = {}
            }
        end
    end
    
    return defaultData
end

-- Thread principal pour envoyer les données
Citizen.CreateThread(function()
    while true do
        Citizen.Wait(UPDATE_INTERVAL)
        
        local players = {}
        local playerList = GetPlayers()
        
        for _, playerId in ipairs(playerList) do
            local ped = GetPlayerPed(playerId)
            if ped and DoesEntityExist(ped) then
                local playerData = GetPlayerData(playerId)
                
                -- Ajouter les données de base pour la map
                playerData.id = tonumber(playerId)
                playerData.name = GetPlayerName(playerId)
                playerData.ping = GetPlayerPing(playerId)
                playerData.x = playerData.position.x
                playerData.y = playerData.position.y
                playerData.z = playerData.position.z
                playerData.job = playerData.job and playerData.job.name or "unemployed"
                playerData.jobGrade = playerData.job and playerData.job.grade and playerData.job.grade.name or "0"
                
                table.insert(players, playerData)
            end
        end
        
        -- Envoi des données au serveur web
        PerformHttpRequest(WEBHOOK_URL, function(statusCode, responseText, headers)
            -- Ignorer silencieusement si le site est inactif (pas de spam console)
            if not statusCode or statusCode == 0 then
                return
            end
            
            if statusCode == 200 then
                -- Succès silencieux
            elseif statusCode == 403 then
                print("^1[Nightfall Web] ERREUR 403: Secret invalide! Vérifie FIVEM_SECRET^0")
            else
                local errorMsg = responseText or "Aucune réponse du serveur"
                print("^1[Nightfall Web] ERREUR HTTP " .. statusCode .. ": " .. errorMsg .. "^0")
            end
        end, "POST", json.encode({
            serverName = "Nightfall RP",
            serverId = "production",
            players = players
        }), {
            ["Content-Type"] = "application/json",
            ["x-nightfall-secret"] = SECRET
        })
    end
end)

print("^2========================================^0")
print("^2[Nightfall Web] Resource démarrée^0")
print("^2URL: " .. WEBHOOK_URL .. "^0")
print("^2Framework: " .. FrameworkName .. "^0")
print("^2Port HTTP: " .. HTTP_PORT .. "^0")
print("^2========================================^0")

-- ============================================
-- HTTP SERVER - Endpoints pour le site web
-- ============================================

-- Endpoint: GET /nightfall_web_bridge/player?citizenid=XXX
-- Récupère les détails d'un joueur depuis la database
SetHttpHandler(function(req, res)
    local path = req.path
    local headers = req.headers
    local method = req.method
    
    -- Vérifier le secret
    local secret = headers['x-nightfall-secret']
    if secret ~= SECRET then
        res.writeHead(403, { ["Content-Type"] = "application/json" })
        res.send(json.encode({ error = "Forbidden" }))
        return
    end
    
    -- Endpoint: Récupérer un joueur par citizenid
    if method == "GET" and string.match(path, "^/nightfall_web_bridge/player") then
        local citizenid = req.query and req.query.citizenid
        
        if not citizenid then
            res.writeHead(400, { ["Content-Type"] = "application/json" })
            res.send(json.encode({ error = "citizenid parameter required" }))
            return
        end
        
        -- Interroger la database
        MySQL.Async.fetchAll('SELECT citizenid, charinfo, job, money, last_updated FROM players WHERE citizenid = @citizenid LIMIT 1', {
            ['@citizenid'] = citizenid
        }, function(result)
            if not result or #result == 0 then
                res.writeHead(404, { ["Content-Type"] = "application/json" })
                res.send(json.encode({ error = "Player not found" }))
                return
            end
            
            local player = result[1]
            local charinfo = json.decode(player.charinfo) or {}
            local job = json.decode(player.job) or {}
            local money = json.decode(player.money) or {}
            
            -- Récupérer le téléphone depuis phone_phones
            MySQL.Async.fetchAll('SELECT phone_number FROM phone_phones WHERE citizenid = @citizenid LIMIT 1', {
                ['@citizenid'] = citizenid
            }, function(phoneResult)
                local phone = "N/A"
                if phoneResult and #phoneResult > 0 then
                    phone = phoneResult[1].phone_number
                end
                
                res.writeHead(200, { ["Content-Type"] = "application/json" })
                res.send(json.encode({
                    player = {
                        citizenid = player.citizenid,
                        firstname = charinfo.firstname or "Unknown",
                        lastname = charinfo.lastname or "Player",
                        phone = phone,
                        birthdate = charinfo.birthdate or "N/A",
                        gender = charinfo.gender or 0,
                        job = {
                            name = job.name or "unemployed",
                            label = job.label or "Sans emploi",
                            grade = {
                                name = job.grade and job.grade.name or "0",
                                level = job.grade and job.grade.level or 0
                            }
                        },
                        money = {
                            cash = money.cash or 0,
                            bank = money.bank or 0
                        },
                        last_updated = player.last_updated
                    }
                }))
            end)
        end)
        return
    end
    
    -- 404 pour les autres routes
    res.writeHead(404, { ["Content-Type"] = "text/plain" })
    res.send("Not Found")
end)