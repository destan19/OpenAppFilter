module("luci.controller.oaf_user", package.seeall)
local utl = require "luci.util"

function index()
	local page
	entry({"admin", "services", "oaf", "users"}, alias("admin", "services", "oaf", "users", "list"), _("User List"), 20).dependent = true
	entry({"admin", "services", "oaf", "users", "list"}, cbi("oaf/user_list", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}),
	 nil).leaf = true
	
	entry({"admin", "services", "oaf", "users", "detail"}, cbi("oaf/user_detail", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "user_status"}, call("user_status"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "dev_visit_list"}, call("get_dev_visit_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "dev_visit_time"}, call("get_dev_visit_time"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_class_visit_time"}, call("get_app_class_visit_time"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_class_list"}, call("get_class_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_all_users"}, call("get_all_users"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_system_base_info"}, call("get_system_base_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_mac_blacklist"}, call("get_mac_blacklist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "add_mac_blacklist"}, call("add_mac_blacklist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "del_mac_blacklist"}, call("del_mac_blacklist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_parental_control_detail"}, call("get_parental_control_detail"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "set_nickname"}, call("set_nickname"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_hourly_stats"}, call("get_hourly_stats"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_user_basic_info"}, call("get_user_basic_info"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_online_offline_records"}, call("get_online_offline_records"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "get_user_parental_control_rules"}, call("get_user_parental_control_rules"), nil).leaf = true
end

function get_hostname_by_mac(dst_mac)
    leasefile="/tmp/dhcp.leases"
    local fd = io.open(leasefile, "r")
	if not fd then return end
    while true do
        local ln = fd:read("*l")
        if not ln then
            break
        end
        local ts, mac, ip, name, duid = ln:match("^(%d+) (%S+) (%S+) (%S+) (%S+)")
        if  dst_mac == mac then
            fd:close()
            return name
        end
    end
	fd:close()
    return ""
end


function get_app_name_by_id(appid)
	local class_fd = io.popen("find /tmp/appfilter/ -type f -name *.class |xargs cat |grep "..appid.."|awk '{print $2}'")
	if class_fd then
		local name = class_fd:read("*l")
		class_fd:close()
		if name and name ~= "" then
			return name
		end
	end
	if tonumber(appid) and tonumber(appid) > 0 then
		return "App" .. tostring(appid)
	end
	return ""
end

function cmp_func(a,b)
	return a.latest_time > b.latest_time
end

function normalize_mac(mac)
	if not mac then
		return ""
	end
	return tostring(mac):gsub("^%s+", ""):gsub("%s+$", ""):upper()
end

function call_fwx_common(api, data)
	local req_obj = {}
	req_obj.api = api
	req_obj.data = data or {}
	return utl.ubus("fwx", "common", req_obj)
end

function user_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local fd = io.open("/proc/net/af_client","r")
	status_buf=fd:read('*a')
	fd:close()
	user_array=json.parse(status_buf)
	
	local req_obj = {}
	req_obj.api = "visit_list"
	req_obj.data = {}
	local visit_obj = utl.ubus("fwx", "common", req_obj)
	
	local user_array = {}
	if visit_obj and visit_obj.code == 2000 and visit_obj.data and visit_obj.data.dev_list then
		user_array = visit_obj.data.dev_list
	end
	local history={}
	for i, v in pairs(user_array) do
		visit_array=user_array[i].visit_info
		for j,s in pairs(visit_array) do
			print(user_array[i].mac, user_array[i].ip,visit_array[j].appid, visit_array[j].latest_time)
			total_time=visit_array[j].latest_time - visit_array[j].first_time;
			history[#history+1]={
				mac=user_array[i].mac,
				ip=user_array[i].ip,
				hostname=get_hostname_by_mac(user_array[i].mac),
				appid=visit_array[j].appid,
				appname=get_app_name_by_id(visit_array[j].appid),
				total_num=0,
				drop_num=0,
				latest_action=visit_array[j].latest_action,
				latest_time=os.date("%Y/%m/%d %H:%M:%S", visit_array[j].latest_time),
				first_time=os.date("%Y/%m/%d %H:%M:%S", visit_array[j].first_time),
				total_time=total_time
			}
		end
	end
	table.sort(history, cmp_func)
	luci.http.write_json(history);
end

function get_class_list()
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.CopyRight = "www.fanchmwrt.com"
	req_obj.api = "class_list"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({class_list = {}})
	end
end


function get_all_users()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_all_users"
	req_obj.data = {
		flag = luci.http.formvalue("flag"),
		page = luci.http.formvalue("page"),
		page_size = luci.http.formvalue("page_size")
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({data = resp_obj.data})
	else
		luci.http.write_json({data = resp_obj or {}})
	end
end

function get_system_base_info()
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_system_base_info"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			user_session_enable = 0
		})
	end
end

function get_mac_blacklist()
	luci.http.prepare_content("application/json")

	local resp_obj = call_fwx_common("get_mac_blacklist", {})
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({code = 0, data = resp_obj.data, message = "success"})
	else
		luci.http.write_json({code = 1, data = {list = {}}, message = "failed"})
	end
end

function add_mac_blacklist()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")

	local mac_list = {}
	local mac = normalize_mac(luci.http.formvalue("mac"))
	if mac ~= "" then
		table.insert(mac_list, mac)
	else
		local data_str = luci.http.formvalue("data")
		if data_str and data_str ~= "" then
			local data = json.parse(data_str)
			if data and type(data.mac_list) == "table" then
				for _, item in ipairs(data.mac_list) do
					local normalized_mac = normalize_mac(item)
					if normalized_mac ~= "" then
						table.insert(mac_list, normalized_mac)
					end
				end
			end
		end
	end

	if #mac_list == 0 then
		luci.http.write_json({code = 1, message = "Invalid mac"})
		return
	end

	local resp_obj = call_fwx_common("add_mac_blacklist", {mac_list = mac_list})
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "success"})
	else
		luci.http.write_json({code = 1, message = "failed"})
	end
end

function del_mac_blacklist()
	luci.http.prepare_content("application/json")
	local mac = normalize_mac(luci.http.formvalue("mac"))
	if mac == "" then
		luci.http.write_json({code = 1, message = "Invalid mac"})
		return
	end

	local resp_obj = call_fwx_common("del_mac_blacklist", {mac = mac})
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "success"})
	else
		luci.http.write_json({code = 1, message = "failed"})
	end
end

function get_parental_control_detail()
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.api = "get_parental_control_detail"
	req_obj.data = {
		mac = luci.http.formvalue("mac")
	}

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			pc_status = "unlimited",
			pc_status_key = "unlimited",
			af_whitelist = 0,
			mf_whitelist = 0,
			appfilter_rules = {},
			macfilter_rules = {}
		})
	end
end

function get_user_parental_control_rules()
	luci.http.prepare_content("application/json")

	local target_mac = normalize_mac(luci.http.formvalue("mac"))
	if target_mac == "" then
		luci.http.write_json({
			mac = "",
			af_whitelist = 0,
			mf_whitelist = 0,
			list = {}
		})
		return
	end

	local req_obj = {
		api = "get_user_parental_control_rules",
		data = {
			mac = target_mac
		}
	}
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and type(resp_obj.data) == "table" then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			mac = target_mac,
			af_whitelist = 0,
			mf_whitelist = 0,
			list = {}
		})
	end
end

function get_oaf_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_oaf_status"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json(resp_obj or {})
	end
end


function set_nickname()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "set_nickname"
	req_obj.data = {
		mac = luci.http.formvalue("mac"),
		nickname = luci.http.formvalue("nickname")
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj);
	
	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json(resp_obj.data or {})
	else
		luci.http.write_json(resp_obj or {})
	end
end


function get_dev_visit_time(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "dev_visit_time"
	req_obj.data = {
		mac = mac
	}
	
	local visit_obj = utl.ubus("fwx", "common", req_obj)
	
	local visit_list = {}
	if visit_obj and visit_obj.code == 2000 and visit_obj.data and visit_obj.data.list then
		visit_list = visit_obj.data.list
	end
	luci.http.write_json(visit_list)
end

function get_app_class_visit_time(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "app_class_visit_time"
	req_obj.data = {
		mac = mac
	}
	
	local visit_obj = utl.ubus("fwx", "common", req_obj)
	
	local class_array = {}
	if visit_obj and visit_obj.code == 2000 and visit_obj.data and visit_obj.data.class_list then
		class_array = visit_obj.data.class_list
	end
	luci.http.write_json(class_array)
end


function get_dev_visit_list(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "dev_visit_list"
	req_obj.data = {
		mac = mac
	}
	
	local page = luci.http.formvalue("page")
	local page_size = luci.http.formvalue("page_size")
	if page then
		req_obj.data.page = tonumber(page) or 1
	end
	if page_size then
		req_obj.data.page_size = tonumber(page_size) or 15
	end
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json(resp_obj or {})
	end
end

function get_hourly_stats(mac)
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_hourly_top_apps"
	req_obj.data = {
		mac = mac
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			mac = mac,
			date = 0,
			is_today = 1,
			hourly_stats = {}
		})
	end
end

function get_user_basic_info(mac)
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_user_basic_info"
	req_obj.data = {
		mac = mac
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({})
	end
end
