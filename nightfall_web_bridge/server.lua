-- ============================================
-- NIGHTFALL RP - WEB INTEGRATION
-- ============================================
-- Ce script envoie les données joueurs vers le site web
-- toutes les 2 secondes pour afficher les blips en temps réel

-- CONFIGURATION
local WEBHOOK_URL = "http://127.0.0.1:5173/api/fivem/players"  -- Change l'IP si le site web est sur un autre serveur
local SECRET = "2025"  -- Doit correspondre au fivemSecret dans api/staff_config.json
local UPDATE_INTERVAL = 2000  -- Mise à jour toutes les 2 secondes (2000ms)

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

-- Fonction pour récupérer le job selon le framework
function GetPlayerJob(playerId)
    if FrameworkName == "esx" and Framework then
        local xPlayer = Framework.GetPlayerFromId(playerId)
        if xPlayer then
            return xPlayer.job.name or "unemployed", xPlayer.job.grade_label or "0"
        end
    elseif FrameworkName == "qbcore" and Framework then
        local Player = Framework.Functions.GetPlayer(playerId)
        if Player then
            return Player.PlayerData.job.name or "unemployed", Player.PlayerData.job.grade.name or "0"
        end
    end
    
    return "unemployed", "0"
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
                local coords = GetEntityCoords(ped)
                local job, jobGrade = GetPlayerJob(playerId)
                
                table.insert(players, {
                    id = tonumber(playerId),
                    name = GetPlayerName(playerId),
                    job = job,
                    jobGrade = jobGrade,
                    ping = GetPlayerPing(playerId),
                    x = math.floor(coords.x),
                    y = math.floor(coords.y),
                    z = math.floor(coords.z)
                })
            end
        end
        
        -- Envoi des données au serveur web
        PerformHttpRequest(WEBHOOK_URL, function(statusCode, responseText, headers)
            if statusCode == 200 then
                print("^2[Nightfall Web] Données envoyées: " .. #players .. " joueur(s)^0")
            elseif statusCode == 403 then
                print("^1[Nightfall Web] ERREUR 403: Secret invalide! Vérifie api/staff_config.json^0")
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
