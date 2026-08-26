module("luci.controller.oaf_whitelist", package.seeall)

local util = require "luci.util"
local jsonc = require "luci.jsonc"

local function normalize_mac(mac)
	return string.upper((mac or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function is_valid_mac(mac)
	return mac and mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

local function write_json(data)
	luci.http.prepare_content("application/json")
	luci.http.write_json(data)
end

local function get_record_whitelist_page(page, page_size)
	local req_obj = {
		api = "get_record_whitelist",
		data = {
			page = page,
			page_size = page_size
		}
	}

	return util.ubus("fwx", "common", req_obj)
end

function index()
	local fs = require "nixio.fs"
	local has_app_filter = fs.access("/etc/config/appfilter")
	local has_access_control = fs.access("/etc/config/macfilter")
	local has_record = fs.access("/etc/config/fwx_record")

	if not has_app_filter and not has_access_control and not has_record then
		return
	end

	entry({"admin", "services", "oaf", "whitelist"}, cbi("oaf/whitelist", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("Whitelist"), 50).leaf = true
	entry({"admin", "services", "oaf", "api", "record_whitelist", "get_record_whitelist"}, call("get_record_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "record_whitelist", "get_record_whitelist_all"}, call("get_record_whitelist_all"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "record_whitelist", "add_record_whitelist"}, call("add_record_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "record_whitelist", "del_record_whitelist"}, call("del_record_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "record_whitelist", "get_all_users"}, call("get_all_users"), nil).leaf = true
end

function get_record_whitelist()
	local page = tonumber(luci.http.formvalue("page") or "1") or 1
	local page_size = tonumber(luci.http.formvalue("page_size") or "200") or 200

	if page < 1 then page = 1 end
	if page_size < 1 then page_size = 200 end
	if page_size > 200 then page_size = 200 end

	local resp_obj = get_record_whitelist_page(page, page_size)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		write_json({code = 2000, data = resp_obj.data, message = "success"})
	else
		write_json({code = 2000, data = {total_num = 0, total_page = 1, page = page, page_size = page_size, list = {}}, message = "success"})
	end
end

function get_record_whitelist_all()
	local all_list = {}
	local total_page = 1
	local page = 1
	local page_size = 200

	while page <= total_page do
		local resp_obj = get_record_whitelist_page(page, page_size)
		if not (resp_obj and resp_obj.code == 2000 and resp_obj.data and type(resp_obj.data.list) == "table") then
			break
		end

		local i
		for i = 1, #resp_obj.data.list do
			all_list[#all_list + 1] = resp_obj.data.list[i]
		end

		total_page = tonumber(resp_obj.data.total_page or 1) or 1
		if total_page < 1 then total_page = 1 end
		page = page + 1
	end

	write_json({code = 2000, data = {list = all_list}, message = "success"})
end

function add_record_whitelist()
	local data_str = luci.http.formvalue("data")
	local mac = normalize_mac(luci.http.formvalue("mac"))
	local mac_list = {}

	if data_str and data_str ~= "" then
		local parsed = jsonc.parse(data_str)
		if parsed and type(parsed.mac_list) == "table" then
			local i
			for i = 1, #parsed.mac_list do
				local one_mac = normalize_mac(parsed.mac_list[i])
				if is_valid_mac(one_mac) then
					mac_list[#mac_list + 1] = one_mac
				end
			end
		end
	end

	if #mac_list == 0 and is_valid_mac(mac) then
		mac_list = {mac}
	end

	if #mac_list == 0 then
		write_json({code = 1, message = "Invalid mac_list"})
		return
	end

	local resp_obj = util.ubus("fwx", "common", {
		api = "add_record_whitelist",
		data = {mac_list = mac_list}
	})

	if resp_obj and resp_obj.code == 2000 then
		write_json({code = 2000, message = "Whitelist added successfully"})
	else
		write_json({code = 1, message = "Failed to add whitelist"})
	end
end

function del_record_whitelist()
	local mac = normalize_mac(luci.http.formvalue("mac"))

	if not is_valid_mac(mac) then
		write_json({code = 1, message = "Invalid mac address"})
		return
	end

	local resp_obj = util.ubus("fwx", "common", {
		api = "del_record_whitelist",
		data = {mac = mac}
	})

	if resp_obj and resp_obj.code == 2000 then
		write_json({code = 2000, message = "Whitelist deleted successfully"})
	else
		write_json({code = 1, message = "Failed to delete whitelist"})
	end
end

function get_all_users()
	local all_list = {}
	local total_page = 1
	local page = 1
	local page_size = 200

	while page <= total_page do
		local req_obj = {
			api = "get_all_users",
			data = {
				flag = 2,
				page = page,
				page_size = page_size
			}
		}

		local resp_obj = util.ubus("fwx", "common", req_obj)
		if not (resp_obj and resp_obj.code == 2000 and resp_obj.data and type(resp_obj.data.list) == "table") then
			break
		end

		local i
		for i = 1, #resp_obj.data.list do
			all_list[#all_list + 1] = resp_obj.data.list[i]
		end

		total_page = tonumber(resp_obj.data.total_page or 1) or 1
		if total_page < 1 then total_page = 1 end
		page = page + 1
	end

	write_json({code = 2000, data = {list = all_list}, message = "success"})
end
