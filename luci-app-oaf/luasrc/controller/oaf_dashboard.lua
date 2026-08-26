module("luci.controller.oaf_dashboard", package.seeall)

function index()
	entry({"admin", "services", "oaf", "dashboard"}, cbi("oaf/dashboard", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}),
	 _("Dashboard"), 10).leaf = true
	
	entry({"admin", "services", "oaf", "api", "dashboard", "get_dashboard_common"}, call("get_dashboard_common")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_init_status"}, call("get_init_status")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "set_init_status"}, call("set_init_status")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "set_notice_status"}, call("set_notice_status")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_daily_top_users"}, call("get_daily_top_users")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_history_traffic_stats"}, call("get_history_traffic_stats")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_global_traffic_stats"}, call("get_global_traffic_stats")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_active_users"}, call("get_active_users")).leaf = true
	entry({"admin", "services", "oaf", "api", "dashboard", "get_app_type_stats"}, call("get_app_type_stats")).leaf = true
end

function get_dashboard_common()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_dashboard_common"
	req_obj.CopyRight = "www.fanchmwrt.com"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			system_status = {},
			network_status = {},
			active_app = {total = 0, list = {}},
			advanced = {disable_hnat = 0, notice_status = 0},
			interface_traffic = {interface = "wan", traffic = {}}
		})
	end
end

function get_global_traffic_stats()
	local utl = require "luci.util"

	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_global_traffic_stats"
	req_obj.data = {}

	local date = luci.http.formvalue("date")
	if date then
		req_obj.data.date = tonumber(date) or 0
	end

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			date = 0,
			is_today = 1,
			hourly_traffic = {}
		})
	end
end

function get_history_traffic_stats()
	local utl = require "luci.util"

	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_history_traffic_stats"
	req_obj.data = {}

	local days = luci.http.formvalue("days")
	if days then
		req_obj.data.days = tonumber(days) or 30
	else
		req_obj.data.days = 30
	end

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			days = req_obj.data.days,
			total_up_bytes = 0,
			total_down_bytes = 0,
			total_bytes = 0,
			list = {}
		})
	end
end

function get_init_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_init_status"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({init_status = 1})
	end
end

function set_init_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "set_init_status"
	req_obj.data = { init_status = 1 }

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({init_status = 0})
	end
end

function set_notice_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "set_dashboard_notice_status"
	req_obj.data = { notice_status = 1 }

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 2000, notice_status = 1})
	else
		luci.http.write_json({code = 1})
	end
end

function get_daily_top_users()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_daily_top_users"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			date = 0,
			total_count = 0,
			users = {}
		})
	end
end

function get_active_users()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_active_users"
	req_obj.data = {}
	
	local count = luci.http.formvalue("count")
	if count then
		req_obj.data.count = tonumber(count) or 8
	else
		req_obj.data.count = 8
	end
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			total_count = 0,
			users = {}
		})
	end
end

function get_app_type_stats()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local stat_type = luci.http.formvalue("type") or "hourly"
	
	local req_obj = {}
	req_obj.api = "get_global_app_type_stats"
	req_obj.data = {
		type = stat_type,
		limit = 10
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			type = stat_type,
			limit = 10,
			total_count = 0,
			types = {}
		})
	end
end
