module("luci.controller.oaf_app_record", package.seeall)

local function normalize_page(value, default_value)
    local n = tonumber(value or "") or default_value
    if n < 1 then
        n = default_value
    end
    return n
end

local function write_empty_list(page, page_size)
    luci.http.write_json({
        total_num = 0,
        total_page = 1,
        page = page,
        page_size = page_size,
        list = {}
    })
end

function index()
    entry({"admin", "services", "oaf", "app_record"}, template("oaf/app_record"), _("App Record"), 70).leaf = true
    entry({"admin", "services", "oaf", "api", "app_record", "get_active_app_records"}, call("get_active_app_records")).leaf = true
    entry({"admin", "services", "oaf", "api", "app_record", "get_app_history_records"}, call("get_app_history_records")).leaf = true
end

function get_active_app_records()
    local util = require "luci.util"
    local page = normalize_page(luci.http.formvalue("page"), 1)
    local page_size = normalize_page(luci.http.formvalue("page_size"), 15)

    luci.http.prepare_content("application/json")

    local req_obj = {
        api = "get_active_app_records",
        data = {
            page = page,
            page_size = page_size
        }
    }

    local resp_obj = util.ubus("fwx", "common", req_obj)
    if resp_obj and resp_obj.code == 2000 and resp_obj.data then
        luci.http.write_json(resp_obj.data)
    else
        write_empty_list(page, page_size)
    end
end

function get_app_history_records()
    local util = require "luci.util"
    local mac = luci.http.formvalue("mac")
    local start_time = tonumber(luci.http.formvalue("start_time") or "0") or 0
    local end_time = tonumber(luci.http.formvalue("end_time") or "0") or 0
    local appid = tonumber(luci.http.formvalue("appid") or "0") or 0
    local page = normalize_page(luci.http.formvalue("page"), 1)
    local page_size = normalize_page(luci.http.formvalue("page_size"), 15)

    if appid < 0 then
        appid = 0
    end

    luci.http.prepare_content("application/json")

    local req_obj = {
        api = "get_app_history_records",
        data = {
            mac = mac,
            start_time = start_time,
            end_time = end_time,
            appid = appid,
            page = page,
            page_size = page_size
        }
    }

    local resp_obj = util.ubus("fwx", "common", req_obj)
    if resp_obj and resp_obj.code == 2000 and resp_obj.data then
        luci.http.write_json(resp_obj.data)
    else
        write_empty_list(page, page_size)
    end
end
