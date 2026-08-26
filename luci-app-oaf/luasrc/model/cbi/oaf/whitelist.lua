local nfs = require "nixio.fs"
local config = "fwx_record"

if nfs.access("/etc/config/appfilter") then
	config = "appfilter"
elseif nfs.access("/etc/config/macfilter") then
	config = "macfilter"
end

local m = Map(config, translate(""), translate(""))
local s = m:section(SimpleSection)

s.template = "oaf/whitelist"

return m