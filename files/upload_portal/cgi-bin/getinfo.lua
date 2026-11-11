#!/usr/bin/env lua
local dkjson = require("dkjson")

function GetAllContentForConfig(Config)
    local uci = require("uci")
    local x = uci.cursor()
    return x:get_all(Config, "portal_cfg")
end

function getLocalPortalfornac(Config)
	local response = {}
	local list = GetAllContentForConfig(Config)
	if list then
		response = {
			login = {
				title = list.auth,
				weltitle = list.weltitle
			},
			success = {
				title = list.success,
				subtitle = list.subtitle,
				introduction = list.intrdt
			}
		}
	end
	return response
end

function json_encode( obj )
        local str = dkjson.encode(obj, {indent = false})
        return str
end

local response = getLocalPortalfornac("nac")
ngx.say(json_encode(response))
