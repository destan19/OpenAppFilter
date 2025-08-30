module("luci.controller.appfilter", package.seeall)
local utl = require "luci.util"

function index()
	if not nixio.fs.access("/etc/config/appfilter") then
		return
	end
	
	local page
	entry({"admin", "services", "appfilter"}, alias("admin", "services", "appfilter", "app_filter"),_("App Filter"), 10).dependent = true


	entry({"admin", "services", "appfilter", "user_list"}, 
		arcombine(cbi("appfilter/user_list",{hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), 
		cbi("appfilter/dev_status", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true})),
		_("User List"), 20).leaf=true

	-- entry({"admin", "services", "appfilter", "base_setting"}, cbi("appfilter/base_setting"), _("Basic Settings"), 22).leaf=true
	-- entry({"admin", "services", "appfilter", "user_setting"}, cbi("appfilter/user_setting"), _("Effective User"), 23).leaf=true
	entry({"admin", "services", "appfilter", "time"}, cbi("appfilter/time", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("Time Configuration"), 25).leaf=true
	entry({"admin", "services", "appfilter", "app_filter"}, cbi("appfilter/app_filter", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("App Filter"), 21).leaf=true
	entry({"admin", "services", "appfilter", "feature"}, cbi("appfilter/feature", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("App Feature"), 26).leaf=true

	entry({"admin", "services", "appfilter", "user"}, cbi("appfilter/user", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("User Configuration"), 24).leaf=true
	entry({"admin", "services", "appfilter", "advance"}, cbi("appfilter/advance", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("Advanced Settings"), 27).leaf=true
	entry({"admin", "network", "user_status"}, call("user_status"), nil).leaf = true
	entry({"admin", "network", "get_user_list"}, call("get_user_list"), nil).leaf = true
	entry({"admin", "network", "dev_visit_list"}, call("get_dev_visit_list"), nil).leaf = true
	entry({"admin", "network", "feature_upgrade"}, call("handle_feature_upgrade"), nil).leaf = true
	entry({"admin", "network", "dev_visit_time"}, call("get_dev_visit_time"), nil).leaf = true
	entry({"admin", "network", "app_class_visit_time"}, call("get_app_class_visit_time"), nil).leaf = true
	entry({"admin", "network", "class_list"}, call("get_class_list"), nil).leaf = true
	entry({"admin", "network", "set_app_filter"}, call("set_app_filter"), nil).leaf = true
	entry({"admin", "network", "get_app_filter"}, call("get_app_filter"), nil).leaf = true
	entry({"admin", "network", "get_app_filter_base"}, call("get_app_filter_base"), nil).leaf = true
	entry({"admin", "network", "set_app_filter_base"}, call("set_app_filter_base"), nil).leaf = true
	entry({"admin", "network", "set_app_filter_time"}, call("set_app_filter_time"), nil).leaf = true
	entry({"admin", "network", "get_app_filter_time"}, call("get_app_filter_time"), nil).leaf = true
	entry({"admin", "network", "get_all_users"}, call("get_all_users"), nil).leaf = true
	entry({"admin", "network", "get_app_filter_user"}, call("get_app_filter_user"), nil).leaf = true
	entry({"admin", "network", "set_app_filter_user"}, call("set_app_filter_user"), nil).leaf = true
	entry({"admin", "network", "del_app_filter_user"}, call("del_app_filter_user"), nil).leaf = true
	entry({"admin", "network", "add_app_filter_user"}, call("add_app_filter_user"), nil).leaf = true
	entry({"admin", "network", "get_whitelist_user"}, call("get_whitelist_user"), nil).leaf = true
	entry({"admin", "network", "add_whitelist_user"}, call("add_whitelist_user"), nil).leaf = true
	entry({"admin", "network", "del_whitelist_user"}, call("del_whitelist_user"), nil).leaf = true
	entry({"admin", "network", "upload_file"}, call("handle_file_upload"), nil).leaf = true
	entry({"admin", "network", "set_nickname"}, call("set_nickname"), nil).leaf = true
	entry({"admin", "network", "get_oaf_status"}, call("get_oaf_status"), nil).leaf = true
	entry({"admin", "network", "get_app_filter_adv"}, call("get_app_filter_adv"), nil).leaf = true
	entry({"admin", "network", "set_app_filter_adv"}, call("set_app_filter_adv"), nil).leaf = true
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


function handle_feature_upgrade()
	local fs = require "nixio.fs"
	local http = require "luci.http"
	local image_tmp = "/tmp/feature.cfg"

	local fp
	http.setfilehandler(
		function(meta, chunk, eof)
	
			fp = io.open(image_tmp, "w")
			
			if fp and chunk then
				fp:write(chunk)
			end
			if fp and eof then
				fp:close()
			end
		end
	)


end

function get_app_name_by_id(appid)
	local class_fd = io.popen("find /tmp/appfilter/ -type f -name *.class |xargs cat |grep "..appid.."|awk '{print $2}'")
	if class_fd then
		local name = class_fd:read("*l")
		class_fd:close()
		return name
	end
	return ""
end

function cmp_func(a,b)
	return a.latest_time > b.latest_time
end


function user_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local fd = io.open("/proc/net/af_client","r")
	status_buf=fd:read('*a')
	fd:close()
	user_array=json.parse(status_buf)
	
	local visit_obj=utl.ubus("appfilter", "visit_list", {});
	local user_array=visit_obj.dev_list
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


function get_user_list()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local visit_obj=utl.ubus("appfilter", "dev_list", {});
	luci.http.write_json(visit_obj);
end

function get_class_list()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local class_obj=utl.ubus("appfilter", "class_list", {});
	llog("get class list");
	luci.http.write_json(class_obj);
end

function get_all_users()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local flag = luci.http.formvalue("flag")
	local page = luci.http.formvalue("page")
	local class_obj=utl.ubus("appfilter", "get_all_users", {flag=flag, page=page});
	luci.http.write_json(class_obj);
end

function get_oaf_status()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_oaf_status", {});
	luci.http.write_json(resp_obj);
end

function get_app_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_app_filter_user", {});
	luci.http.write_json(resp_obj);
end

function del_app_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.mac = luci.http.formvalue("mac")
	llog("del appfilter user "..req_obj.mac);
	local resp_obj=utl.ubus("appfilter", "del_app_filter_user", req_obj);
	luci.http.write_json(resp_obj);
end

function add_app_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	local data_str = luci.http.formvalue("data")
	req_obj = json.parse(data_str)

	local resp_obj=utl.ubus("appfilter", "add_app_filter_user", req_obj);
	luci.http.write_json(resp_obj);
end

function get_whitelist_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_whitelist_user", {});
	luci.http.write_json(resp_obj);
end

function add_whitelist_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	local data_str = luci.http.formvalue("data")
	req_obj = json.parse(data_str)

	local resp_obj=utl.ubus("appfilter", "add_whitelist_user", req_obj);
	luci.http.write_json(resp_obj);
end

function del_whitelist_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.mac = luci.http.formvalue("mac")
	llog("del whitelist user "..req_obj.mac);
	local resp_obj=utl.ubus("appfilter", "del_whitelist_user", req_obj);
	luci.http.write_json(resp_obj);
end

function get_app_filter()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_app_filter", {});
	luci.http.write_json(resp_obj);
end

function set_app_filter()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	
	local app_list_str = luci.http.formvalue("app_list")

	local app_list = {}
	for id in app_list_str:gmatch("([^,]+)") do
		table.insert(app_list, tonumber(id))
	end
	
	local req_obj = {
		app_list = app_list
	}

	local resp_obj = utl.ubus("appfilter", "set_app_filter", req_obj)
	luci.http.write_json(resp_obj)
end

function set_nickname()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.mac = luci.http.formvalue("mac")
	req_obj.nickname = luci.http.formvalue("nickname")
	llog("set nickname "..req_obj.mac.." "..req_obj.nickname);
	local resp_obj=utl.ubus("appfilter", "set_nickname", req_obj);
	luci.http.write_json(resp_obj);
end

function get_app_filter_base()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_app_filter_base", {});
	luci.http.write_json(resp_obj);
end

function set_app_filter_user()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.mode = luci.http.formvalue("mode")
	local resp_obj=utl.ubus("appfilter", "set_app_filter_user", req_obj);
	luci.http.write_json(resp_obj);
end

function set_app_filter_base()
	local json = require "luci.jsonc"
	llog("set appfilter base");
	luci.http.prepare_content("application/json")
	local req_obj = {}


	local enable = luci.http.formvalue("enable")
	local work_mode = luci.http.formvalue("work_mode")
	local record_enable = luci.http.formvalue("record_enable")

	llog("enable: "..enable.." work_mode: "..work_mode.." record_enable: "..record_enable)
	req_obj.enable = enable
	req_obj.work_mode = work_mode
	req_obj.record_enable = record_enable

	local resp_obj=utl.ubus("appfilter", "set_app_filter_base", req_obj);
	luci.http.write_json(resp_obj);
end

function get_app_filter_adv()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_app_filter_adv", {});
	luci.http.write_json(resp_obj);
end
function set_app_filter_adv()
	local json = require "luci.jsonc"
	llog("set appfilter base");
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.lan_ifname = luci.http.formvalue("lan_ifname")
	req_obj.disable_hnat = luci.http.formvalue("disable_hnat")
	req_obj.auto_load_engine = luci.http.formvalue("auto_load_engine")
	local resp_obj=utl.ubus("appfilter", "set_app_filter_adv", req_obj);
	luci.http.write_json(resp_obj);
end

-- data: {"mode":1,"weekday_list":[1,2,3,4,5,6,0],"start_time":"22:22","end_time":"12:00","allow_time":30,"deny_time":5}
function set_app_filter_time()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj = json.parse(luci.http.formvalue("data"))
	local resp_obj=utl.ubus("appfilter", "set_app_filter_time", req_obj);
	luci.http.write_json(resp_obj);
end

function get_app_filter_time()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local resp_obj=utl.ubus("appfilter", "get_app_filter_time", {});
	luci.http.write_json(resp_obj);
end

function get_dev_visit_time(mac)

	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
		local req_obj = {}
	req_obj.mac = mac;
	local visit_obj=utl.ubus("appfilter", "dev_visit_time", req_obj);

	local visit_list=visit_obj.list
	luci.http.write_json(visit_list);
end

function get_app_class_visit_time(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.mac = mac;
	local visit_obj=utl.ubus("appfilter", "app_class_visit_time", req_obj);
	local class_array=visit_obj.class_list
	luci.http.write_json(class_array);
end


function get_dev_visit_list(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.mac = mac;
	local resp_obj=utl.ubus("appfilter", "dev_visit_list", req_obj);
	luci.http.write_json(resp_obj);
end

function handle_file_upload()
    local http = require "luci.http"
    local fs = require "nixio.fs"
    local upload_dir = "/tmp/uploads/"
    local file_name = "uploaded_file"
    llog("handle_file_upload started");

    -- Ensure the upload directory exists
    if not fs.access(upload_dir) then
        fs.mkdir(upload_dir)
    end

    llog("Upload directory checked/created");

    local file_path = upload_dir .. file_name
    local fp

    llog("file_path: " .. file_path);
    http.setfilehandler(
        function(meta, chunk, eof)
            -- Log metadata information
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
                -- Ensure the file is processed or moved to the correct location
                process_uploaded_file(file_path)
                luci.http.prepare_content("application/json")
                luci.http.write_json({ success = true, message = "File uploaded successfully" })
            end
        end
    )
    llog("handle_file_upload setup complete");
end

function process_uploaded_file(file_path)
    -- Add logic here to process the uploaded file
    llog("Processing uploaded file: " .. file_path)
    -- Example: Move the file to a permanent location
    local permanent_path = "/etc/config/" .. file_name
    os.execute("mv " .. file_path .. " " .. permanent_path)
    llog("File moved to: " .. permanent_path)
end

function llog(message)
    local log_file = "/tmp/log/oaf_luci.log"  -- 日志文件路径
    local fd = io.open(log_file, "a")  -- 以追加模式打开文件
    if fd then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")  -- 获取当前时间戳
        fd:write(string.format("[%s] %s\n", timestamp, message))  -- 写入时间戳和日志信息
        fd:close()  -- 关闭文件
    end
end
