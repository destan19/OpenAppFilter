module("luci.controller.oaf_mac_filter", package.seeall)
local utl = require "luci.util"

function index()
	local fs = require "nixio.fs"
	if not fs.access("/etc/config/macfilter") then
		return
	end

	entry({"admin", "services", "oaf", "mac_filter"}, alias("admin", "services", "oaf", "mac_filter", "rules"), _("Access Control"), 40).dependent = true
	entry({"admin", "services", "oaf", "mac_filter", "rules"}, cbi("oaf/mac_filter/rules", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("Filter Rules"), 10).leaf=true

	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mac_filter_base"}, call("get_mac_filter_base"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "set_mac_filter_base"}, call("set_mac_filter_base"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "set_mac_filter_time"}, call("set_mac_filter_time"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mac_filter_time"}, call("get_mac_filter_time"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mac_filter_user"}, call("get_mac_filter_user"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "set_mac_filter_user"}, call("set_mac_filter_user"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "del_mac_filter_user"}, call("del_mac_filter_user"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "add_mac_filter_user"}, call("add_mac_filter_user"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mf_status"}, call("get_mf_status"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mac_filter_whitelist"}, call("get_mac_filter_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "del_mac_filter_whitelist"}, call("del_mac_filter_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "add_mac_filter_whitelist"}, call("add_mac_filter_whitelist"), nil).leaf = true
	
	
	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mac_filter_rules"}, call("get_mac_filter_rules"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "add_mac_filter_rule"}, call("add_mac_filter_rule"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "update_mac_filter_rule"}, call("update_mac_filter_rule"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "delete_mac_filter_rule"}, call("delete_mac_filter_rule"), nil).leaf = true
	
	
	entry({"admin", "services", "oaf", "api", "mac_filter", "get_mac_filter_adv"}, call("get_mac_filter_adv"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "mac_filter", "set_mac_filter_adv"}, call("set_mac_filter_adv"), nil).leaf = true
end

function get_mf_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "get_mf_status"
	req_obj.data = {}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end

function get_mac_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "get_mac_filter_user"
	req_obj.data = {}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end

function del_mac_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	local mac = luci.http.formvalue("mac")
	llog("del macfilter user "..mac);
	req_obj.api = "del_mac_filter_user"
	req_obj.data = {
		mac = mac
	}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end

function add_mac_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "add_mac_filter_user"
	local data_str = luci.http.formvalue("data")
	local data = json.parse(data_str)
	req_obj.data = data

	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end


function get_mac_filter_base()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "get_mac_filter_base"
	req_obj.data = {}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end

function set_mac_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "set_mac_filter_user"
	local mode = luci.http.formvalue("mode")
	req_obj.data = {
		mode = mode
	}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end

function set_mac_filter_base()
	local json = require "luci.jsonc"
	llog("set macfilter base");
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "set_mac_filter_base"
	local enable = luci.http.formvalue("enable")
	req_obj.data = {
		enable = enable
	}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end



function set_mac_filter_time()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "set_mac_filter_time"
	local data_str = luci.http.formvalue("data")
	local data = json.parse(data_str)
	req_obj.data = data
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end

function get_mac_filter_time()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "get_mac_filter_time"
	req_obj.data = {}
	local resp_obj=utl.ubus("fwx", "common", req_obj);
	luci.http.write_json(resp_obj);
end


function get_mac_filter_whitelist()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	
	local req_obj = {}
	req_obj.api = "get_mac_filter_whitelist"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({code = 2000, data = resp_obj.data, message = "success"})
	else
		
		luci.http.write_json({code = 2000, data = {list = {}}, message = "success"})
	end
end


function add_mac_filter_whitelist()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local data_str = luci.http.formvalue("data")
	if not data_str then
		luci.http.write_json({code = 1, message = "Invalid request data"})
		return
	end
	
	local whitelist_data = json.parse(data_str)
	llog("add_mac_filter_whitelist: " .. json.stringify(whitelist_data))
	
	if not whitelist_data.mac_list or type(whitelist_data.mac_list) ~= "table" then
		luci.http.write_json({code = 1, message = "Invalid mac_list"})
		return
	end
	
	
	local req_obj = {}
	req_obj.api = "add_mac_filter_whitelist"
	req_obj.data = whitelist_data
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 then
		
		luci.http.write_json({code = 2000, message = "Whitelist added successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to add whitelist"})
	end
end


function del_mac_filter_whitelist()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local mac = luci.http.formvalue("mac")
	if not mac then
		luci.http.write_json({code = 1, message = "Invalid mac address"})
		return
	end
	
	llog("del_mac_filter_whitelist: " .. mac)
	
	
	local req_obj = {}
	req_obj.api = "del_mac_filter_whitelist"
	req_obj.data = {
		mac = mac
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 then
		
		luci.http.write_json({code = 2000, message = "Whitelist deleted successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to delete whitelist"})
	end
end

function llog(message)
    local log_file = "/tmp/log/oaf_luci.log"  
    local fd = io.open(log_file, "a")  
    if fd then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")  
        fd:write(string.format("[%s] %s\n", timestamp, message))  
        fd:close()  
    end
end


function get_mac_filter_rules()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	
	local req_obj = {}
	req_obj.api = "get_mac_filter_rules"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data and resp_obj.data.list then
		local rules_data = resp_obj.data.list
		local json_str = json.stringify({code = 0, data = rules_data, message = "success"})
		luci.http.write(json_str)
	else
		
		local json_str = json.stringify({code = 0, data = {}, message = "success"})
		luci.http.write(json_str)
	end
end


function add_mac_filter_rule()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local data_str = luci.http.formvalue("data")
	if not data_str then
		luci.http.write_json({code = 1, message = "Invalid request data"})
		return
	end
	
	local rule_data = json.parse(data_str)
	llog("add_mac_filter_rule: " .. json.stringify(rule_data))
	
	
	if not rule_data.name or not rule_data.mode then
		luci.http.write_json({code = 1, message = "Missing required fields"})
		return
	end

	local time_mode = tonumber(rule_data.time_mode) or 1
	if time_mode == 1 then
		if (not rule_data.time_list or #rule_data.time_list == 0) and (not rule_data.time_rules or #rule_data.time_rules == 0) then
			luci.http.write_json({code = 1, message = "Missing required time_list"})
			return
		end
	elseif time_mode == 2 then
		if (not rule_data.time_limit or rule_data.time_limit == "") and (not rule_data.time_rules or #rule_data.time_rules == 0) then
			luci.http.write_json({code = 1, message = "Missing required time_limit"})
			return
		end
	elseif time_mode == 3 then
		if (not rule_data.flow_limit or rule_data.flow_limit == "") and (not rule_data.time_rules or #rule_data.time_rules == 0) then
			luci.http.write_json({code = 1, message = "Missing required flow_limit"})
			return
		end
	end
	
	
	local get_req_obj = {}
	get_req_obj.api = "get_mac_filter_rules"
	get_req_obj.data = {}
	local get_resp_obj = utl.ubus("fwx", "common", get_req_obj)
	
	if get_resp_obj and get_resp_obj.code == 2000 and get_resp_obj.data and get_resp_obj.data.data then
		local existing_rules = get_resp_obj.data.data
		if #existing_rules >= 32 then
			luci.http.write_json({code = 1, message = "Maximum 32 rules allowed"})
			return
		end
	end
	
	
	local req_obj = {}
	req_obj.api = "add_mac_filter_rule"
	req_obj.data = rule_data
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "Rule added successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to add rule"})
	end
end


function update_mac_filter_rule()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local data_str = luci.http.formvalue("data")
	if not data_str then
		luci.http.write_json({code = 1, message = "Invalid request data"})
		return
	end
	
	local rule_data = json.parse(data_str)
	llog("update_mac_filter_rule: " .. json.stringify(rule_data))
	
	if not rule_data.id then
		luci.http.write_json({code = 1, message = "Missing rule id"})
		return
	end
	
	
	local req_obj = {}
	req_obj.api = "update_mac_filter_rule"
	req_obj.data = rule_data
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 then

		luci.http.write_json({code = 0, message = "Rule updated successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to update rule"})
	end
end


function delete_mac_filter_rule()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local rule_id = luci.http.formvalue("rule_id")
	if not rule_id then
		luci.http.write_json({code = 1, message = "Invalid rule_id"})
		return
	end
	
	llog("delete_mac_filter_rule: " .. rule_id)
	
	
	local req_obj = {}
	req_obj.api = "delete_mac_filter_rule"
	req_obj.data = {
		id = tonumber(rule_id)
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "Rule deleted successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to delete rule"})
	end
end


function get_mac_filter_adv()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	
	local req_obj = {}
	req_obj.api = "get_mac_filter_adv"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({code = 0, data = resp_obj.data, message = "success"})
	else
		luci.http.write_json({code = 1, message = "Failed to load"})
	end
end


function set_mac_filter_adv()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local enable = tonumber(luci.http.formvalue("enable")) or 0
	
	
	if enable ~= 0 and enable ~= 1 then
		luci.http.write_json({code = 1, message = "Invalid enable value, must be 0 or 1"})
		return
	end
	
	local req_obj = {}
	req_obj.api = "set_mac_filter_adv"
	req_obj.data = {
		enable = enable
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 then
		llog("Set macfilter enable: " .. enable)
		luci.http.write_json({code = 0, message = "Saved successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to save"})
	end
end
