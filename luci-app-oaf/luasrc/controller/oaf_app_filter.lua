module("luci.controller.oaf_app_filter", package.seeall)
local utl = require "luci.util"

function index()
	local fs = require "nixio.fs"
	if not fs.access("/etc/config/appfilter") then
		return
	end
	entry({"admin", "services", "oaf", "app_filter"}, alias("admin", "services", "oaf", "app_filter", "rules"), _("App Filter"), 30).dependent = true
	entry({"admin", "services", "oaf", "app_filter", "rules"}, cbi("oaf/app_filter/rules", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("Filter Rules"), 10).leaf=true
	entry({"admin", "services", "oaf", "api", "app_filter", "class_list"}, call("get_class_list"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "get_all_users"}, call("get_all_users"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "get_filter_rules"}, call("get_filter_rules"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "add_filter_rule"}, call("add_filter_rule"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "update_filter_rule"}, call("update_filter_rule"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "delete_filter_rule"}, call("delete_filter_rule"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "get_appfilter_whitelist"}, call("get_appfilter_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "add_appfilter_whitelist"}, call("add_appfilter_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "del_appfilter_whitelist"}, call("del_appfilter_whitelist"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "get_app_filter_adv"}, call("get_app_filter_adv"), nil).leaf = true
	entry({"admin", "services", "oaf", "api", "app_filter", "set_app_filter_adv"}, call("set_app_filter_adv"), nil).leaf = true
end


function get_class_list()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.CopyRight = "www.fanchmwrt.com"
	req_obj.api = "class_list"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		llog("get class list");
		luci.http.write_json(resp_obj.data)
	else
		llog("get class list failed");
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
		page = luci.http.formvalue("page")
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({data = resp_obj.data})
	else
		luci.http.write_json({data = resp_obj or {}})
	end
end



function handle_file_upload()
    local http = require "luci.http"
    local fs = require "nixio.fs"
    local upload_dir = "/tmp/uploads/"
    local file_name = "uploaded_file"
    llog("handle_file_upload started");

    if not fs.access(upload_dir) then
        fs.mkdir(upload_dir)
    end

    llog("Upload directory checked/created");

    local file_path = upload_dir .. file_name
    local fp

    llog("file_path: " .. file_path);
    http.setfilehandler(
        function(meta, chunk, eof)
            llog("File upload metadata: " .. (meta and meta.name or "nil") .. ", " .. (meta and meta.file or "nil"))
            llog("File upload chunk size: " .. (chunk and #chunk or 0))

            if not fp then
                fp = io.open(file_path, "w")
                llog("File opened for writing: " .. file_path)
            end
            if fp and chunk then
                fp:write(chunk)
                llog("Chunk written to file")
            end
            if fp and eof then
                fp:close()
                llog("File upload completed and file closed")
                process_uploaded_file(file_path)
                luci.http.prepare_content("application/json")
                luci.http.write_json({ success = true, message = "File uploaded successfully" })
            end
        end
    )
    llog("handle_file_upload setup complete");
end

function process_uploaded_file(file_path)
    llog("Processing uploaded file: " .. file_path)
    local permanent_path = "/etc/config/" .. file_name
    os.execute("mv " .. file_path .. " " .. permanent_path)
    llog("File moved to: " .. permanent_path)
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

function get_filter_rules()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_filter_rules"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data and resp_obj.data.list then
		local rules_data = resp_obj.data.list
		llog("get_filter_rules: returning " .. #rules_data .. " rules")
		local json_str = json.stringify({code = 0, data = rules_data, message = "success"})
		luci.http.write(json_str)
	else
		llog("get_filter_rules: failed, returning empty array")
		local json_str = json.stringify({code = 0, data = {}, message = "success"})
		luci.http.write(json_str)
	end
end


function add_filter_rule()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local data_str = luci.http.formvalue("data")
	if not data_str then
		luci.http.write_json({code = 1, message = "Invalid request data"})
		return
	end
	
	local rule_data = json.parse(data_str)
	llog("add_filter_rule: " .. json.stringify(rule_data))
	

	if not rule_data.name or not rule_data.mode or not rule_data.time_rules or not rule_data.app_ids then
		luci.http.write_json({code = 1, message = "Missing required fields"})
		return
	end

	local get_req_obj = {}
	get_req_obj.api = "get_filter_rules"
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
	req_obj.api = "add_filter_rule"
	req_obj.data = rule_data
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "Rule added successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to add rule"})
	end
end

function update_filter_rule()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local data_str = luci.http.formvalue("data")
	if not data_str then
		luci.http.write_json({code = 1, message = "Invalid request data"})
		return
	end
	
	local rule_data = json.parse(data_str)
	llog("update_filter_rule: " .. json.stringify(rule_data))
	
	if not rule_data.id then
		luci.http.write_json({code = 1, message = "Missing rule id"})
		return
	end

	local req_obj = {}
	req_obj.api = "update_filter_rule"
	req_obj.data = rule_data
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "Rule updated successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to update rule"})
	end
end

function delete_filter_rule()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local rule_id = luci.http.formvalue("rule_id")
	if not rule_id then
		luci.http.write_json({code = 1, message = "Invalid rule_id"})
		return
	end
	
	llog("delete_filter_rule: " .. rule_id)
	
	local req_obj = {}
	req_obj.api = "delete_filter_rule"
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

function get_appfilter_whitelist()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_appfilter_whitelist"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({code = 2000, data = resp_obj.data, message = "success"})
	else
		luci.http.write_json({code = 2000, data = {list = {}}, message = "success"})
	end
end

function add_appfilter_whitelist()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local data_str = luci.http.formvalue("data")
	if not data_str then
		luci.http.write_json({code = 1, message = "Invalid request data"})
		return
	end
	
	local whitelist_data = json.parse(data_str)
	llog("add_appfilter_whitelist: " .. json.stringify(whitelist_data))
	
	if not whitelist_data.mac_list or type(whitelist_data.mac_list) ~= "table" then
		luci.http.write_json({code = 1, message = "Invalid mac_list"})
		return
	end
	
	local req_obj = {}
	req_obj.api = "add_appfilter_whitelist"
	req_obj.data = whitelist_data
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 2000, message = "Whitelist added successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to add whitelist"})
	end
end

function del_appfilter_whitelist()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local mac = luci.http.formvalue("mac")
	if not mac then
		luci.http.write_json({code = 1, message = "Invalid mac address"})
		return
	end
	
	llog("del_appfilter_whitelist: " .. mac)
	
	local req_obj = {}
	req_obj.api = "del_appfilter_whitelist"
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

function get_app_filter_adv()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_app_filter_adv"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json({code = 0, data = resp_obj.data, message = "success"})
	end
end

function set_app_filter_adv()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")
	
	local enable = tonumber(luci.http.formvalue("enable")) or 1

	local req_obj = {}
	req_obj.api = "set_app_filter_adv"
	req_obj.data = {
		enable = enable,
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)

	if resp_obj and resp_obj.code == 2000 then
		luci.http.write_json({code = 0, message = "Saved successfully"})
	else
		luci.http.write_json({code = 1, message = "Failed to save"})
	end
end
