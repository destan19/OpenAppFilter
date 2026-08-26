module("luci.controller.oaf_feature", package.seeall)

function index()
	entry({"admin", "services", "oaf", "feature"},
		template("oaf/feature"),
		_("Feature Library"), 80).dependent = true
	entry({"admin", "services", "oaf", "feature", "info"}, call("get_feature_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "class_list"}, call("get_feature_class_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "online_config"}, call("get_feature_online_config"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "online_save"}, call("set_feature_online_config"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "online_list"}, call("get_feature_online_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "online_start"}, call("start_feature_online_update"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "online_status"}, call("get_feature_online_update_status"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "custom_list"}, call("get_custom_feature_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "custom_class_list"}, call("get_custom_feature_class_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "feature", "custom_save"}, call("set_custom_feature_list"), nil).leaf = true
end

function get_feature_info()
	local json = require "luci.jsonc"
	local util = require "luci.util"
	local http = require "luci.http"
	local resp = util.ubus("fwx", "common", {api = "get_feature_info", data = {}})

	http.prepare_content("application/json")
	http.write(json.stringify(resp or {code = 4000}))
end

local function write_fwx_response(api, data)
	local json = require "luci.jsonc"
	local util = require "luci.util"
	local http = require "luci.http"
	local resp = util.ubus("fwx", "common", {api = api, data = data or {}})

	http.prepare_content("application/json")
	http.write(json.stringify(resp or {code = 4000}))
end

function get_feature_online_config()
	write_fwx_response("get_feature_online_config", {})
end

function set_feature_online_config()
	local http = require "luci.http"
	write_fwx_response("set_feature_online_config", {
		token = http.formvalue("token") or ""
	})
end

function get_feature_online_list()
	local http = require "luci.http"
	local lang = http.formvalue("lang") or "cn"
	local refresh = tonumber(http.formvalue("refresh") or "0") or 0
	if lang ~= "cn" and lang ~= "en" then
		lang = "cn"
	end
	write_fwx_response("get_feature_online_list", {
		lang = lang,
		device_lang = http.formvalue("device_lang") or "",
		refresh = refresh
	})
end

function start_feature_online_update()
	local http = require "luci.http"
	local lang = http.formvalue("lang") or "cn"
	if lang ~= "cn" and lang ~= "en" then
		lang = "cn"
	end
	write_fwx_response("start_feature_online_update", {
		id = http.formvalue("id") or "",
		lang = lang,
		md5 = http.formvalue("md5") or ""
	})
end

function get_feature_online_update_status()
	write_fwx_response("get_feature_online_update_status", {})
end

function get_custom_feature_list()
	write_fwx_response("get_custom_feature", {})
end

function get_custom_feature_class_list()
	write_fwx_response("get_custom_feature_class_list", {})
end

function set_custom_feature_list()
	local json = require "luci.jsonc"
	local http = require "luci.http"
	local data_str = http.formvalue("data")
	local ok, data_obj = pcall(json.parse, data_str or "")

	if not ok then
		data_obj = nil
	end
	if type(data_obj) ~= "table" or type(data_obj.app_list) ~= "table" then
		http.prepare_content("application/json")
		http.write(json.stringify({code = 4000, data = {error = "invalid request data"}}))
		return
	end
	write_fwx_response("set_custom_feature", data_obj)
end

function get_feature_class_list()
	local json = require "luci.jsonc"
	local util = require "luci.util"
	local http = require "luci.http"
	local resp = util.ubus("fwx", "common", {CopyRight = "www.fanchmwrt.com", api = "class_list", data = {}})

	http.prepare_content("application/json")
	if resp and resp.code == 2000 and resp.data then
		http.write(json.stringify(resp.data))
	else
		http.write(json.stringify({class_list = {}}))
	end
end
