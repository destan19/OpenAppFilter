module("luci.controller.appfilter", package.seeall)
local utl = require "luci.util"

function index()
	if not nixio.fs.access("/etc/config/appfilter") then
		return
	end
	
	local page
	entry({"admin", "services", "appfilter"}, alias("admin", "services", "appfilter", "user_list"),_("App Filter"), 10).dependent = true


	entry({"admin", "services", "appfilter", "user_list"}, 
		arcombine(cbi("appfilter/user_list",{hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), 
		cbi("appfilter/dev_status", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true})),
		_("User List"), 20).leaf=true

	entry({"admin", "services", "appfilter", "base_setting"}, cbi("appfilter/base_setting"), _("Basic Settings"), 22).leaf=true
	entry({"admin", "services", "appfilter", "user_setting"}, cbi("appfilter/user_setting"), _("Effective User"), 23).leaf=true
	entry({"admin", "services", "appfilter", "time_setting"}, cbi("appfilter/time_setting"), _("Effective Time"), 24).leaf=true
	entry({"admin", "services", "appfilter", "app_filter"}, cbi("appfilter/app_filter", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("App Filter Rule"), 21).leaf=true
	entry({"admin", "services", "appfilter", "feature"}, cbi("appfilter/feature", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}), _("App Feature"), 25).leaf=true

	entry({"admin", "network", "user_status"}, call("user_status"), nil).leaf = true
	entry({"admin", "network", "dev_app_status"}, call("dev_app_status"), nil).leaf = true
	entry({"admin", "network", "dev_visit_list"}, call("get_dev_visit_list"), nil).leaf = true
	entry({"admin", "network", "feature_upgrade"}, call("handle_feature_upgrade"), nil).leaf = true
	entry({"admin", "network", "dev_visit_time"}, call("get_dev_visit_time"), nil).leaf = true
	entry({"admin", "network", "app_class_visit_time"}, call("get_app_class_visit_time"), nil).leaf = true
	entry({"admin", "network", "class_list"}, call("get_class_list"), nil).leaf = true
	entry({"admin", "network", "set_app_filter"}, call("set_app_filter"), nil).leaf = true
	entry({"admin", "network", "get_app_filter"}, call("get_app_filter"), nil).leaf = true
	entry({"admin", "network", "get_app_filter_base"}, call("get_app_filter_base"), nil).leaf = true
	entry({"admin", "network", "set_app_filter_base"}, call("set_app_filter_base"), nil).leaf = true
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


function dev_app_status()
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

function get_app_filter()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local class_obj=utl.ubus("appfilter", "get_app_filter", {});
	llog("get appfilter");
	luci.http.write_json(class_obj);
end

function set_app_filter()
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj.app_list = luci.http.formvalue("app_list")
	llog("set app filter "..req_obj.app_list);
	req_obj.app_list = json.parse(req_obj.app_list)  -- 将字符串转换为JSON格式
	local class_obj=utl.ubus("appfilter", "set_app_filter", req_obj);
	luci.http.write_json(class_obj);
end


function get_app_filter_base()
	local json = require "luci.jsonc"
	llog("11get appfilter base");
	luci.http.prepare_content("application/json")
	local class_obj=utl.ubus("appfilter", "get_app_filter_base", {});
	llog("22get appfilter base");
	luci.http.write_json(class_obj);
end

function set_app_filter_base()
	local json = require "luci.jsonc"
	llog("set appfilter base");
	luci.http.prepare_content("application/json")
	local req_obj = {}
	req_obj = json.parse(luci.http.formvalue("data"))
	local resp_obj=utl.ubus("appfilter", "set_app_filter_base", req_obj);
	luci.http.write_json(resp_obj);
end

function get_dev_visit_time(mac)
	local json = require "luci.jsonc"
	luci.http.prepare_content("application/json")
	local fd = io.open("/proc/net/af_client","r")
	status_buf=fd:read('*a')
	fd:close()
	user_array=json.parse(status_buf)
	local req_obj = {}
	req_obj.mac = mac;
	local visit_obj=utl.ubus("appfilter", "dev_visit_time", req_obj);
	local user_array=visit_obj.app_list
	luci.http.write_json(user_array);
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

	local visit_obj=utl.ubus("appfilter", "visit_list", req_obj);
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

function llog(message)
    local log_file = "/tmp/log/oaf_luci.log"  -- 日志文件路径
    local fd = io.open(log_file, "a")  -- 以追加模式打开文件
    if fd then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")  -- 获取当前时间戳
        fd:write(string.format("[%s] %s\n", timestamp, message))  -- 写入时间戳和日志信息
        fd:close()  -- 关闭文件
    end
end
