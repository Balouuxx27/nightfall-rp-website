fx_version 'cerulean'
game 'gta5'

author 'Nightfall RP'
description 'Envoie les données joueurs vers le site web + API HTTP pour profils'
version '2.0.0'

server_scripts {
    '@oxmysql/lib/MySQL.lua',
    'server.lua',
    'http_api.lua'
}

server_exports {
    'getPlayerProfile'
}
