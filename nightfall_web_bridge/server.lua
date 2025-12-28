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
            
            return {
                discordId = defaultData.discordId,
                citizenid = pd.citizenid or nil,
                charinfo = {
                    firstname = pd.charinfo and pd.charinfo.firstname or "Unknown",
                    lastname = pd.charinfo and pd.charinfo.lastname or "Player",
                    phone = pd.charinfo and pd.charinfo.phone or "N/A",
                    birthdate = pd.charinfo and pd.charinfo.birthdate or "N/A"
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
                    x = math.floor(GetEntityCoords(GetPlayerPed(playerId)).x),
                    y = math.floor(GetEntityCoords(GetPlayerPed(playerId)).y),
                    z = math.floor(GetEntityCoords(GetPlayerPed(playerId)).z)
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
            if statusCode == 200 then
                -- Log commenté pour éviter spam
                -- print("^2[Nightfall Web] Données envoyées: " .. #players .. " joueur(s)^0")
            elseif statusCode == 403 then
                print("^1[Nightfall Web] ERREUR 403: Secret invalide! Vérifie FIVEM_SECRET^0")
            else
                print("^1[Nightfall Web] ERREUR HTTP " .. statusCode .. ": " .. responseText .. "^0")
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
print("^2========================================^0")

