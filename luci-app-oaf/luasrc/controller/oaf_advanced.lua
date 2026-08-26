module("luci.controller.oaf_advanced", package.seeall)

local util = require "luci.util"

function index()
	entry({"admin", "services", "oaf", "advanced"}, template("oaf/advanced"), _("Settings"), 90).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "get_system_info"}, call("get_system_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "set_system_info"}, call("set_system_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "get_work_mode"}, call("get_work_mode"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "set_work_mode"}, call("set_work_mode"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "get_tcp_rst"}, call("get_tcp_rst"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "set_tcp_rst"}, call("set_tcp_rst"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "get_advanced_settings"}, call("get_advanced_settings"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "system", "set_advanced_settings"}, call("set_advanced_settings"), nil).leaf = true
end

local function ubus_call(api, payload)
	payload = payload or {}
	payload.api = api
	return util.ubus("fwx", "common", payload) or {code = 1}
end

function get_system_info()
	local http = require "luci.http"
	local resp = ubus_call("get_system_info", {data = {}})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function set_system_info()
	local http = require "luci.http"
	local lan_ifname = http.formvalue("lan_ifname") or ""
	local theme_mode = tonumber(http.formvalue("theme_mode") or "0") or 0

	if theme_mode ~= 0 and theme_mode ~= 1 then
		theme_mode = 0
	end

	local resp = ubus_call("set_system_info", {
		data = {
			fwx = {
				lan_ifname = lan_ifname,
				theme_mode = theme_mode
			}
		}
	})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function get_work_mode()
	local http = require "luci.http"
	local resp = ubus_call("get_work_mode", {data = {}})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function set_work_mode()
	local http = require "luci.http"
	local work_mode = tonumber(http.formvalue("work_mode") or "0") or 0

	if work_mode ~= 0 and work_mode ~= 1 then
		http.prepare_content("application/json")
		http.write_json({code = 1})
		return
	end

	local resp = ubus_call("set_work_mode", {
		data = {
			work_mode = work_mode
		}
	})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function get_tcp_rst()
	local http = require "luci.http"
	local resp = ubus_call("get_tcp_rst", {data = {}})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function set_tcp_rst()
	local http = require "luci.http"
	local tcp_rst = tonumber(http.formvalue("tcp_rst") or "1") or 1

	tcp_rst = tcp_rst == 0 and 0 or 1

	local resp = ubus_call("set_tcp_rst", {
		data = {
			tcp_rst = tcp_rst
		}
	})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function get_advanced_settings()
	local http = require "luci.http"
	local resp = ubus_call("get_advanced_settings", {data = {}})

	http.prepare_content("application/json")
	http.write_json(resp)
end

function set_advanced_settings()
	local http = require "luci.http"
	local disable_hnat = tonumber(http.formvalue("disable_hnat") or "0") or 0

	disable_hnat = disable_hnat == 1 and 1 or 0

	local resp = ubus_call("set_advanced_settings", {
		data = {
			disable_hnat = disable_hnat
		}
	})

	http.prepare_content("application/json")
	http.write_json(resp)
end
