#!/usr/bin/lua
-- Copyright (C) 2026 destan19 <www.fanchmwrt.com>

local uci = require "uci"
local os = require "os"
local io = require "io"
local has_jsonc, jsonc = pcall(require, "luci.jsonc")
if not has_jsonc then
    jsonc = nil
end

local CHECK_INTERVAL = 10  
local LOG_FILE = "/tmp/log/rule_manager.log" 
local SINGLE_MAC_FILTER_RULE_ID = 101  
local BLACKLIST_MAC_FILTER_RULE_ID = 102
local USER_PARENTAL_CONTROL_STATUS_FILE = "/tmp/fwx_cache/user_parental_control_status"
local USER_PARENTAL_CONTROL_DETAIL_FILE = "/tmp/fwx_cache/user_parental_control_detail.json"
local TIME_MODE_RANGE = 1
local TIME_MODE_DURATION = 2
local TIME_MODE_FLOW = 3
local MACFILTER_RULE_MODE_ALL_USERS = 1
local MACFILTER_RULE_MODE_SINGLE_USER = 2
local BLACKLIST_RULE_NAME = "Internet Blacklist"
local PC_STATUS_UNLIMITED = "unlimited"
local PC_STATUS_APP_LIMITED = "app_limited"
local PC_STATUS_MAC_BLOCKED = "mac_blocked"

local APPFILTER_STATE_FILE = "/tmp/appfilter_rules_state"
local MACFILTER_STATE_FILE = "/tmp/macfilter_rules_state"
local APPFILTER_WHITELIST_STATE_FILE = "/tmp/appfilter_whitelist_state"
local MACFILTER_WHITELIST_STATE_FILE = "/tmp/macfilter_whitelist_state"
local RECORD_WHITELIST_STATE_FILE = "/tmp/record_whitelist_state"

local appfilter_rules_state = {} 
local macfilter_rules_state = {}

local appfilter_enable_state = nil
local macfilter_enable_state = nil
local record_enable_state = nil  

local function ensure_log_dir()
    os.execute(string.format("mkdir -p %s", string.match(LOG_FILE, "^(.*)/")))
end

local function log(message)
    ensure_log_dir()
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local log_msg = string.format("[%s] %s\n", timestamp, message)
	-- for debug
    --local file = io.open(LOG_FILE, "a")
    --if file then
    --   file:write(log_msg)
    --  file:close()
    --end
    print(log_msg)
end

local function parse_json_obj(output)
    if not jsonc or not jsonc.parse or not output or output == "" then
        return nil
    end
    local ok, obj = pcall(jsonc.parse, output)
    if not ok or type(obj) ~= "table" then
        return nil
    end
    return obj
end

local function get_current_time_info()
    local now = os.time()
    local date = os.date("*t", now)
    
    local weekday = date.wday - 1
    
    local current_minutes = date.hour * 60 + date.min
    
    return {
        weekday = weekday,
        hour = date.hour,
        min = date.min,
        minutes = current_minutes
    }
end

local function parse_time(time_str)
    if not time_str or time_str == "" then
        return nil
    end
    
    local hour, min = time_str:match("(%d+):(%d+)")
    if hour and min then
        return tonumber(hour) * 60 + tonumber(min)
    end
    return nil
end

local function is_time_in_range(time_rules, current_info)
    if not time_rules or #time_rules == 0 then
        return false
    end
    
    for _, time_rule in ipairs(time_rules) do
        if time_rule.weekdays and time_rule.start_time and time_rule.end_time then
            local weekday_match = false
            for _, wd in ipairs(time_rule.weekdays) do
                if wd == current_info.weekday then
                    weekday_match = true
                    break
                end
            end
            
            if weekday_match then
                local start_minutes = parse_time(time_rule.start_time)
                local end_minutes = parse_time(time_rule.end_time)
                
                if start_minutes and end_minutes then
                    if start_minutes <= end_minutes then
                        if current_info.minutes >= start_minutes and current_info.minutes <= end_minutes then
                            return true
                        end
                    else
                        if current_info.minutes >= start_minutes or current_info.minutes <= end_minutes then
                            return true
                        end
                    end
                end
            end
        end
    end
    
    return false
end

local function write_to_dev_fwx(json_str)
    local dev_file = "/dev/fwx"
    local check_cmd = string.format('test -e %s', dev_file)
    local check_result = os.execute(check_cmd)
    if check_result ~= 0 then
        log(string.format("WARNING: Device file %s does not exist, skipping", dev_file))
        return false
    end

    local payload = json_str or ""
    local payload_len = string.len(payload)
    if payload_len > 1024 then
        payload = string.sub(payload, 1, 1024) .. "..."
    end
    log(string.format("write_to_dev_fwx: payload(len=%d): %s", payload_len, payload))
    
    local file = io.open(dev_file, "w")
    if not file then
        log(string.format("ERROR: Failed to open %s for writing", dev_file))
        return false
    end
    
    file:write(json_str)
    file:close()
    return true
end

local function delete_appfilter_rule(rule_id)
    log(string.format("AppFilter: Deleting rule %d", rule_id))
    local json_str = string.format('{"api":"del_app_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: Rule %d deleted successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: Rule %d delete failed", rule_id))
        return false
    end
end

local function create_appfilter_rule(rule_id)
    log(string.format("AppFilter: Creating rule %d", rule_id))
    local json_str = string.format('{"api":"add_app_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: Rule %d created successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: Rule %d create failed", rule_id))
        return false
    end
end


local function set_appfilter_rule_mac_list(rule_id, mac_list)
    log(string.format("AppFilter: Setting MAC list for rule %d, count=%d", rule_id, #mac_list))
    
    local mac_array_str = ""
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
    else
        mac_array_str = "[]"
    end
    
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"mac_action":1,"mac_list":%s}}', 
        rule_id, mac_array_str)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: MAC list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: MAC list for rule %d set failed", rule_id))
        return false
    end
end

local function set_appfilter_rule_app_id_list(rule_id, app_id_list)
    log(string.format("AppFilter: Setting App ID list for rule %d, count=%d", rule_id, #app_id_list))
    
    local app_id_array_str = ""
    if #app_id_list > 0 then
        local app_id_strs = {}
        for _, app_id in ipairs(app_id_list) do
            local token = tostring(app_id)
            token = token:gsub("\\", "\\\\"):gsub("\"", "\\\"")
            table.insert(app_id_strs, string.format('"%s"', token))
        end 
        app_id_array_str = "[" .. table.concat(app_id_strs, ",") .. "]"
    else
        app_id_array_str = "[]"
    end
    
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"app_action":1,"app_id_list":%s}}', 
        rule_id, app_id_array_str)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: App ID list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: App ID list for rule %d set failed", rule_id))
        return false
    end
end

local function set_appfilter_rule_filter_quic(rule_id, filter_quic)
    local filter_quic_value = tonumber(filter_quic) or 0
    if filter_quic_value ~= 1 then
        filter_quic_value = 0
    end

    log(string.format("AppFilter: Setting filter_quic for rule %d, value=%d", rule_id, filter_quic_value))
    local json_str = string.format('{"api":"mod_app_filter_rule","data":{"rule_id":%d,"filter_quic":%d}}',
        rule_id, filter_quic_value)
    if write_to_dev_fwx(json_str) then
        log(string.format("AppFilter: filter_quic for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("AppFilter: filter_quic for rule %d set failed", rule_id))
        return false
    end
end

local function apply_macfilter_rule(rule_id, enable)
    log(string.format("MACFilter: apply_macfilter_rule called but enable field is no longer sent to kernel"))
    return true
end

local function create_macfilter_rule(rule_id, mode)
    local rule_mode = tonumber(mode) or MACFILTER_RULE_MODE_ALL_USERS
    if rule_mode ~= MACFILTER_RULE_MODE_SINGLE_USER then
        rule_mode = MACFILTER_RULE_MODE_ALL_USERS
    end
    log(string.format("MACFilter: Creating rule %d, mode=%d", rule_id, rule_mode))
    local json_str = string.format('{"api":"add_mac_filter_rule","data":{"rule_id":%d,"mode":%d}}', rule_id, rule_mode)
    if write_to_dev_fwx(json_str) then
        log(string.format("MACFilter: Rule %d created successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: Rule %d create failed", rule_id))
        return false
    end
end

local function delete_macfilter_rule(rule_id)
    log(string.format("MACFilter: Deleting rule %d", rule_id))
    local json_str = string.format('{"api":"del_mac_filter_rule","data":{"rule_id":%d}}', rule_id)
    if write_to_dev_fwx(json_str) then
        log(string.format("MACFilter: Rule %d deleted successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: Rule %d delete failed", rule_id))
        return false
    end
end

local function set_macfilter_rule_mac_list(rule_id, mac_list, mode)
    local rule_mode = tonumber(mode) or MACFILTER_RULE_MODE_ALL_USERS
    if rule_mode ~= MACFILTER_RULE_MODE_SINGLE_USER then
        rule_mode = MACFILTER_RULE_MODE_ALL_USERS
    end
    log(string.format("MACFilter: Setting MAC list for rule %d, mode=%d, count=%d", rule_id, rule_mode, #mac_list))
    
    local clear_json = string.format('{"api":"mod_mac_filter_rule","data":{"rule_id":%d,"mode":%d,"mac_action":0}}', rule_id, rule_mode)
    if not write_to_dev_fwx(clear_json) then
        log(string.format("MACFilter: Failed to clear MAC list for rule %d", rule_id))
        return false
    end
    
    if #mac_list == 0 then
        log(string.format("MACFilter: MAC list for rule %d cleared (empty list, no MACs to set)", rule_id))
        return true
    end
    
    local mac_strs = {}
    for _, mac in ipairs(mac_list) do
        table.insert(mac_strs, string.format('"%s"', mac))
    end
    local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
    
    local json_str = string.format('{"api":"mod_mac_filter_rule","data":{"rule_id":%d,"mode":%d,"mac_action":1,"mac_list":%s}}', 
        rule_id, rule_mode, mac_array_str)
    if write_to_dev_fwx(json_str) then
        log(string.format("MACFilter: MAC list for rule %d set successfully", rule_id))
        return true
    else
        log(string.format("MACFilter: MAC list for rule %d set failed", rule_id))
        return false
    end
end

local function uci_get_all_sections(config, section_type)
    local sections = {}
    local cmd = string.format("uci show %s.@%s 2>/dev/null | grep -E '^%s\\.@%s\\[\\-?\\d+\\]'", config, section_type, config, section_type)
    local handle = io.popen(cmd)
    if not handle then
        return sections
    end
    
    local seen_ids = {}
    for line in handle:lines() do
        local section_path = line:match("^([^=]+)=")
        if section_path then
            local section_index = section_path:match("%[([%d%-]+)%]")
            if section_index then
                local index = tonumber(section_index)
                if index and index >= 0 and not seen_ids[index] then
                    seen_ids[index] = true
                    table.insert(sections, index)
                end
            end
        end
    end
    handle:close()
    
    table.sort(sections)
    return sections
end

local function load_appfilter_rules()
    log("=== Loading AppFilter rules from UCI ===")
    
    local uci_cursor = uci.cursor()
    local rules = {}
    
    uci_cursor:foreach("appfilter", "rule", function(section)
        local rule = {
            id = tonumber(section.id) or 0,
            name = section.name or "",
            mode = tonumber(section.mode) or 1,
            enabled = tonumber(section.enabled) or 1,
            filter_quic = tonumber(section.filter_quic) or 0,
            user_mac = section.user_mac or "",
            time_rules = {},
            app_ids = {}
        }
        
        if section.app_id then
            local app_ids = type(section.app_id) == "table" and section.app_id or {section.app_id}
            for _, app_id_token in ipairs(app_ids) do
                if app_id_token and app_id_token ~= "" then
                    table.insert(rule.app_ids, tostring(app_id_token))
                end
            end
        end
        
        if section.time_rule then
            local time_rules = type(section.time_rule) == "table" and section.time_rule or {section.time_rule}
            for _, time_rule_str in ipairs(time_rules) do
                if time_rule_str and time_rule_str ~= "" then
                    local parts = {}
                    for part in time_rule_str:gmatch("[^,]+") do
                        table.insert(parts, part)
                    end
                    
                    if #parts >= 3 then
                        local weekdays = {}
                        local start_time = nil
                        local end_time = nil
                        
                        for i, part in ipairs(parts) do
                            if part:match(":") then
                                if not start_time then
                                    start_time = part
                                else
                                    end_time = part
                                end
                            else
                                local wd = tonumber(part)
                                if wd then
                                    table.insert(weekdays, wd)
                                end
                            end
                        end
                        
                        if start_time and end_time and #weekdays > 0 then
                            table.insert(rule.time_rules, {
                                weekdays = weekdays,
                                start_time = start_time,
                                end_time = end_time
                            })
                        end
                    end
                end
            end
        end
        
        table.insert(rules, rule)
    end)
    
    uci_cursor:unload("appfilter")
    
    log(string.format("Loaded %d AppFilter rules", #rules))
    return rules
end

local function load_macfilter_rules()
    local uci_cursor = uci.cursor()
    local rules = {}

    local function parse_weekdays_csv(weekdays_csv)
        local weekdays = {}
        if not weekdays_csv then
            return weekdays
        end
        for wd_str in tostring(weekdays_csv):gmatch("[^,]+") do
            local wd = tonumber(wd_str)
            if wd and wd >= 0 and wd <= 6 then
                table.insert(weekdays, wd)
            end
        end
        return weekdays
    end

    local function parse_macfilter_time_rule(rule, time_rule_str)
        if not time_rule_str or time_rule_str == "" then
            return
        end

        local weekday_part, mode_part, value_part = time_rule_str:match("^([^;]+);([^;]+);(.+)$")
        if weekday_part and mode_part and value_part then
            local parsed_rule_mode = tonumber(mode_part) or 0
            local parsed_time_mode = TIME_MODE_RANGE
            if parsed_rule_mode == 1 then
                parsed_time_mode = TIME_MODE_DURATION
            elseif parsed_rule_mode == 2 then
                parsed_time_mode = TIME_MODE_FLOW
            end

            local weekdays = parse_weekdays_csv(weekday_part)
            if #weekdays <= 0 then
                return
            end

            rule.time_mode = parsed_time_mode
            if parsed_time_mode == TIME_MODE_DURATION then
                local duration_minutes = tonumber(value_part) or 0
                if duration_minutes > 0 then
                    table.insert(rule.duration_rules, {
                        weekdays = weekdays,
                        duration_minutes = duration_minutes
                    })
                end
            elseif parsed_time_mode == TIME_MODE_FLOW then
                local flow_mb = tonumber(value_part) or 0
                if flow_mb > 0 then
                    table.insert(rule.flow_rules, {
                        weekdays = weekdays,
                        flow_mb = flow_mb
                    })
                end
            else
                local start_time, end_time = value_part:match("^([^%-]+)%-(.+)$")
                if start_time and end_time then
                    table.insert(rule.time_rules, {
                        weekdays = weekdays,
                        start_time = start_time,
                        end_time = end_time
                    })
                end
            end
            return
        end

        local parts = {}
        for part in time_rule_str:gmatch("[^,]+") do
            table.insert(parts, part)
        end
        if #parts <= 0 then
            return
        end

        local effective_time_mode = rule.time_mode
        if #parts >= 3 and parts[#parts - 1] == "duration" then
            effective_time_mode = TIME_MODE_DURATION
        elseif #parts >= 3 and parts[#parts - 1] == "flow" then
            effective_time_mode = TIME_MODE_FLOW
        end
        rule.time_mode = effective_time_mode

        if effective_time_mode == TIME_MODE_DURATION then
            local weekdays = {}
            local duration_minutes = tonumber(parts[#parts]) or 0
            local last_weekday_idx = #parts - 1
            if #parts >= 3 and parts[#parts - 1] == "duration" then
                last_weekday_idx = #parts - 2
            end

            for i = 1, last_weekday_idx do
                local wd = tonumber(parts[i])
                if wd and wd >= 0 and wd <= 6 then
                    table.insert(weekdays, wd)
                end
            end

            if duration_minutes > 0 and #weekdays > 0 then
                table.insert(rule.duration_rules, {
                    weekdays = weekdays,
                    duration_minutes = duration_minutes
                })
            end
            return
        end

        if effective_time_mode == TIME_MODE_FLOW then
            local weekdays = {}
            local flow_mb = tonumber(parts[#parts]) or 0
            local last_weekday_idx = #parts - 1
            if #parts >= 3 and parts[#parts - 1] == "flow" then
                last_weekday_idx = #parts - 2
            end

            for i = 1, last_weekday_idx do
                local wd = tonumber(parts[i])
                if wd and wd >= 0 and wd <= 6 then
                    table.insert(weekdays, wd)
                end
            end

            if flow_mb > 0 and #weekdays > 0 then
                table.insert(rule.flow_rules, {
                    weekdays = weekdays,
                    flow_mb = flow_mb
                })
            end
            return
        end

        if #parts >= 3 then
            local weekdays = {}
            local start_time = nil
            local end_time = nil

            for _, part in ipairs(parts) do
                if part:match(":") then
                    if not start_time then
                        start_time = part
                    else
                        end_time = part
                    end
                else
                    local wd = tonumber(part)
                    if wd and wd >= 0 and wd <= 6 then
                        table.insert(weekdays, wd)
                    end
                end
            end

            if start_time and end_time and #weekdays > 0 then
                table.insert(rule.time_rules, {
                    weekdays = weekdays,
                    start_time = start_time,
                    end_time = end_time
                })
            end
        end
    end

    local function parse_week_limit_rules(limit_str, max_value, value_key)
        local result = {}
        local parsed_map = {}
        local order = {1, 2, 3, 4, 5, 6, 0}
        if type(limit_str) ~= "string" then
            limit_str = ""
        end
        for pair in tostring(limit_str):gmatch("[^,]+") do
            local day_str, value_str = pair:match("^%s*(%d+)%s*:%s*(%d+)%s*$")
            local day = tonumber(day_str)
            local value = tonumber(value_str)
            if day and value and day >= 0 and day <= 6 then
                if value < 0 then
                    value = 0
                end
                if max_value and value > max_value then
                    value = max_value
                end
                parsed_map[day] = value
            end
        end
        for _, day in ipairs(order) do
            table.insert(result, {
                weekdays = {day},
                [value_key] = parsed_map[day] or 0
            })
        end
        return result
    end
    
    uci_cursor:foreach("macfilter", "rule", function(section)
        local rule = {
            id = tonumber(section.id) or 0,
            name = section.name or "",
            mode = tonumber(section.mode) or 1,
            time_mode = tonumber(section.time_mode) or TIME_MODE_RANGE,
            enabled = tonumber(section.enabled) or 1,
            user_mac = section.user_mac or "",
            time_list = {},
            time_limit = section.time_limit or "",
            flow_limit = section.flow_limit or "",
            time_rules = {},
            duration_rules = {},
            flow_rules = {}
        }

        local loaded_new_field = false
        if rule.time_mode == TIME_MODE_RANGE then
            if section.time_list then
                local time_list = type(section.time_list) == "table" and section.time_list or {section.time_list}
                for _, time_rule_str in ipairs(time_list) do
                    if time_rule_str and time_rule_str ~= "" then
                        table.insert(rule.time_list, time_rule_str)
                        parse_macfilter_time_rule(rule, time_rule_str)
                    end
                end
                if #rule.time_list > 0 then
                    loaded_new_field = true
                end
            end
        elseif rule.time_mode == TIME_MODE_DURATION then
            if rule.time_limit and rule.time_limit ~= "" then
                rule.duration_rules = parse_week_limit_rules(rule.time_limit, 1440, "duration_minutes")
                loaded_new_field = true
            end
        elseif rule.time_mode == TIME_MODE_FLOW then
            if rule.flow_limit and rule.flow_limit ~= "" then
                rule.flow_rules = parse_week_limit_rules(rule.flow_limit, 1048576, "flow_mb")
                loaded_new_field = true
            end
        end

        if (not loaded_new_field) and section.time_rule then
            local time_rules = type(section.time_rule) == "table" and section.time_rule or {section.time_rule}
            for _, time_rule_str in ipairs(time_rules) do
                parse_macfilter_time_rule(rule, time_rule_str)
            end
        end
        
        table.insert(rules, rule)
    end)
    
    uci_cursor:unload("macfilter")
    
    log(string.format("Loaded %d MACFilter rules", #rules))
    return rules
end

local function load_mac_blacklist()
    local uci_cursor = uci.cursor()
    local mac_list = {}
    local ok = false

    if type(uci_cursor.get_list) == "function" then
        local list_ret = uci_cursor:get_list("mac_blacklist", "base", "mac_list")
        if type(list_ret) == "table" then
            mac_list = list_ret
            ok = true
        elseif type(list_ret) == "string" then
            mac_list = {list_ret}
            ok = true
        end
    end

    if not ok then
        local raw = uci_cursor:get("mac_blacklist", "base", "mac_list")
        if type(raw) == "table" then
            mac_list = raw
        elseif type(raw) == "string" then
            mac_list = {raw}
        else
            mac_list = {}
        end
    end

    if type(uci_cursor.unload) == "function" then
        pcall(function()
            uci_cursor:unload("mac_blacklist")
        end)
    end

    local uniq = {}
    local normalized_list = {}
    for _, mac in ipairs(mac_list) do
        local normalized_mac = tostring(mac or ""):upper()
        if normalized_mac ~= "" and not uniq[normalized_mac] then
            uniq[normalized_mac] = true
            table.insert(normalized_list, normalized_mac)
        end
    end
    table.sort(normalized_list)
    log(string.format("Loaded %d MAC blacklist entries", #normalized_list))
    return normalized_list
end

local function weekday_match(weekdays, current_weekday)
    if not weekdays then
        return false
    end
    for _, weekday in ipairs(weekdays) do
        if weekday == current_weekday then
            return true
        end
    end
    return false
end

local function get_macfilter_user_stat()
    local cmd = "ubus call fwx common '{\"api\":\"get_user_stat\",\"data\":{}}' 2>/dev/null"
    local handle = io.popen(cmd)
    local output = ""
    log(string.format("MACFilter usage mode: exec ubus cmd: %s", cmd))
    if handle then
        output = handle:read("*a") or ""
        handle:close()
    end

    local output_len = string.len(output or "")
    if output_len <= 1024 then
        log(string.format("MACFilter usage mode: ubus raw result(len=%d): %s", output_len, output))
    else
        log(string.format("MACFilter usage mode: ubus raw result(len=%d, first_1024): %s", output_len, string.sub(output, 1, 1024)))
    end

    if output == "" or not output:match('"code"%s*:%s*2000') then
        log("MACFilter usage mode: ubus get_user_stat invalid response")
        return nil, nil, nil
    end

    local user_active_map = {}
    local user_flow_bytes_map = {}
    local user_mac_list = {}
    local user_mac_set = {}

    local parsed = parse_json_obj(output)
    if parsed and tonumber(parsed.code) == 2000 and type(parsed.data) == "table" then
        local stat_list = nil
        if type(parsed.data.l) == "table" then
            stat_list = parsed.data.l
        elseif type(parsed.data.list) == "table" then
            stat_list = parsed.data.list
        elseif type(parsed.data.data) == "table" then
            stat_list = parsed.data.data
        end

        if type(stat_list) == "table" then
            for _, item in ipairs(stat_list) do
                if type(item) == "table" then
                    local mac = item.m or item.mac
                    local active_time = item.at or item.today_active_time
                    local up_flow = item.uf or item.today_up_flow
                    local down_flow = item.df or item.today_down_flow
                    if mac and mac ~= "" then
                        user_active_map[mac] = math.floor((tonumber(active_time) or 0) / 60)
                        user_flow_bytes_map[mac] = (tonumber(up_flow) or 0) + (tonumber(down_flow) or 0)
                        if not user_mac_set[mac] then
                            user_mac_set[mac] = true
                            table.insert(user_mac_list, mac)
                        end
                    end
                end
            end
        end
    end

    if #user_mac_list == 0 then
        for mac, active_time, up_flow, down_flow in output:gmatch('"m"%s*:%s*"([^"]+)".-"at"%s*:%s*(%d+).-"uf"%s*:%s*(%d+).-"df"%s*:%s*(%d+)') do
            if mac and mac ~= "" then
                user_active_map[mac] = math.floor((tonumber(active_time) or 0) / 60)
                user_flow_bytes_map[mac] = (tonumber(up_flow) or 0) + (tonumber(down_flow) or 0)
                if not user_mac_set[mac] then
                    user_mac_set[mac] = true
                    table.insert(user_mac_list, mac)
                end
            end
        end
    end

    if #user_mac_list == 0 then
        for mac, seconds, up_flow, down_flow in output:gmatch('"mac"%s*:%s*"([^"]+)".-"today_active_time"%s*:%s*(%d+).-"today_up_flow"%s*:%s*(%d+).-"today_down_flow"%s*:%s*(%d+)') do
            if mac and mac ~= "" then
                user_active_map[mac] = math.floor((tonumber(seconds) or 0) / 60)
                user_flow_bytes_map[mac] = (tonumber(up_flow) or 0) + (tonumber(down_flow) or 0)
                if not user_mac_set[mac] then
                    user_mac_set[mac] = true
                    table.insert(user_mac_list, mac)
                end
            end
        end
    end

    log(string.format("MACFilter usage mode: parsed user stat count=%d", #user_mac_list))
    return user_active_map, user_flow_bytes_map, user_mac_list
end

local function append_detail_for_mac(detail_map, mac, detail)
    if not detail_map or not mac or mac == "" or not detail then
        return
    end
    if not detail_map[mac] then
        detail_map[mac] = {}
    end
    table.insert(detail_map[mac], detail)
end

local function parse_app_rule_category_stats(app_ids)
    local category_count_map = {}
    local category_ids = {}
    local app_count = 0
    local app_list = app_ids or {}

    local function add_category_count(category_id, count)
        if not category_id or category_id <= 0 or not count or count <= 0 then
            return
        end
        category_count_map[category_id] = (category_count_map[category_id] or 0) + count
    end

    local function add_range_category_count(start_id, end_id)
        local cur = tonumber(start_id) or 0
        local finish = tonumber(end_id) or 0
        if cur <= 0 or finish <= 0 then
            return 0
        end
        if cur > finish then
            cur, finish = finish, cur
        end

        local total = 0
        while cur <= finish do
            local category_id = math.floor(cur / 1000)
            if category_id <= 0 then
                cur = cur + 1
            else
                local category_end = category_id * 1000 + 999
                local seg_end = math.min(finish, category_end)
                local seg_count = seg_end - cur + 1
                add_category_count(category_id, seg_count)
                total = total + seg_count
                cur = seg_end + 1
            end
        end
        return total
    end

    for _, app_id in ipairs(app_list) do
        local token = tostring(app_id or "")
        local start_str, end_str = token:match("^%s*(%d+)%s*%-%s*(%d+)%s*$")
        if start_str and end_str then
            app_count = app_count + add_range_category_count(start_str, end_str)
        else
            local app_num = tonumber(token)
            if app_num and app_num > 0 then
                local category_id = math.floor(app_num / 1000)
                if category_id > 0 then
                    add_category_count(category_id, 1)
                    app_count = app_count + 1
                end
            end
        end
    end

    local category_stats = {}
    for category_id, count in pairs(category_count_map) do
        table.insert(category_ids, category_id)
        table.insert(category_stats, {
            id = category_id,
            count = count
        })
    end

    table.sort(category_ids)
    table.sort(category_stats, function(a, b)
        return (a.id or 0) < (b.id or 0)
    end)

    return category_ids, category_stats, app_count
end

local function build_appfilter_rule_detail(rule)
    local app_ids = rule.app_ids or {}
    local category_ids, category_stats, app_count = parse_app_rule_category_stats(app_ids)
    return {
        rule_id = tonumber(rule.id) or 0,
        rule_name = rule.name or "",
        mode = tonumber(rule.mode) or 1,
        user_mac = rule.user_mac or "",
        time_rules = rule.time_rules or {},
        category_ids = category_ids,
        category_stats = category_stats,
        category_count = #category_ids,
        app_count = app_count
    }
end

local function build_macfilter_rule_detail(rule, match_type)
    local detail = {
        rule_id = tonumber(rule.id) or 0,
        rule_name = rule.name or "",
        mode = tonumber(rule.mode) or 1,
        time_mode = tonumber(rule.time_mode) or TIME_MODE_RANGE,
        user_mac = rule.user_mac or "",
        match_type = match_type or "time_range"
    }
    if detail.time_mode == TIME_MODE_DURATION then
        detail.duration_rules = rule.duration_rules or {}
    elseif detail.time_mode == TIME_MODE_FLOW then
        detail.flow_rules = rule.flow_rules or {}
    else
        detail.time_rules = rule.time_rules or {}
    end
    return detail
end

local function get_all_user_macs_for_status()
    local cmd = "ubus call fwx common '{\"api\":\"get_all_users\",\"data\":{\"flag\":0,\"page\":1,\"page_size\":1024}}' 2>/dev/null"
    local handle = io.popen(cmd)
    local output = ""
    local user_mac_list = {}
    local user_mac_set = {}

    if handle then
        output = handle:read("*a") or ""
        handle:close()
    end

    if output == "" or not output:match('"code"%s*:%s*2000') then
        log("ParentalControlStatus: get_all_users failed, fallback to matched MAC set only")
        return user_mac_list, user_mac_set
    end

    local parsed = parse_json_obj(output)
    if parsed and tonumber(parsed.code) == 2000 and type(parsed.data) == "table" then
        local users = nil
        if type(parsed.data.data) == "table" then
            users = parsed.data.data
        elseif type(parsed.data.list) == "table" then
            users = parsed.data.list
        end

        if type(users) == "table" then
            for _, item in ipairs(users) do
                if type(item) == "table" then
                    local mac = item.mac
                    if mac and mac ~= "" and not user_mac_set[mac] then
                        user_mac_set[mac] = true
                        table.insert(user_mac_list, mac)
                    end
                end
            end
        end
    end

    if #user_mac_list == 0 then
        for mac in output:gmatch('"mac"%s*:%s*"([^"]+)"') do
            if mac and mac ~= "" and not user_mac_set[mac] then
                user_mac_set[mac] = true
                table.insert(user_mac_list, mac)
            end
        end
    end

    log(string.format("ParentalControlStatus: loaded %d MACs from get_all_users", #user_mac_list))
    return user_mac_list, user_mac_set
end

local function write_user_parental_control_status(appfilter_mac_set, appfilter_all_users_active, macfilter_block_set, appfilter_detail_map, appfilter_all_user_rule_details, macfilter_all_user_rule_details, macfilter_detail_map)
    local final_mac_set = {}
    local _, all_mac_set = get_all_user_macs_for_status()
    local output_mac_list = {}
    local app_set = appfilter_mac_set or {}
    local mac_block_set = macfilter_block_set or {}
    local app_detail_set = appfilter_detail_map or {}
    local app_all_user_detail_list = appfilter_all_user_rule_details or {}
    local mac_all_user_detail_list = macfilter_all_user_rule_details or {}
    local mac_detail_set = macfilter_detail_map or {}
    local detail_data = {
        appfilter_all_user_rules = app_all_user_detail_list,
        macfilter_all_user_rules = mac_all_user_detail_list,
        users = {}
    }

    for mac, _ in pairs(all_mac_set) do
        final_mac_set[mac] = true
    end
    for mac, _ in pairs(app_set) do
        final_mac_set[mac] = true
    end
    for mac, _ in pairs(mac_block_set) do
        final_mac_set[mac] = true
    end

    for mac, _ in pairs(final_mac_set) do
        table.insert(output_mac_list, mac)
    end
    table.sort(output_mac_list)

    os.execute("mkdir -p /tmp/fwx_cache")
    local tmp_file = USER_PARENTAL_CONTROL_STATUS_FILE .. ".tmp"
    local file = io.open(tmp_file, "w")
    if not file then
        log(string.format("ParentalControlStatus: failed to open temp file %s", tmp_file))
        return false
    end

    local unlimited_count = 0
    local app_limited_count = 0
    local mac_blocked_count = 0

    for _, mac in ipairs(output_mac_list) do
        local status = PC_STATUS_UNLIMITED
        local app_rules = {}
        local mac_rules = mac_detail_set[mac] or {}
        local mac_rule_hit = mac_block_set[mac] and true or false

        if app_detail_set[mac] then
            for _, detail in ipairs(app_detail_set[mac]) do
                table.insert(app_rules, detail)
            end
        end
        if #app_rules > 0 or appfilter_all_users_active or app_set[mac] then
            status = PC_STATUS_APP_LIMITED
        end
        if mac_rule_hit then
            status = PC_STATUS_MAC_BLOCKED
        end

        file:write(string.format("%s %s\n", mac, status))
        if status == PC_STATUS_MAC_BLOCKED then
            mac_blocked_count = mac_blocked_count + 1
        elseif status == PC_STATUS_APP_LIMITED then
            app_limited_count = app_limited_count + 1
        else
            unlimited_count = unlimited_count + 1
        end

        detail_data.users[mac] = {
            pc_status = status,
            appfilter_rules = app_rules,
            macfilter_rules = mac_rules
        }
    end

    file:close()
    os.rename(tmp_file, USER_PARENTAL_CONTROL_STATUS_FILE)

    if jsonc and jsonc.stringify then
        local detail_tmp_file = USER_PARENTAL_CONTROL_DETAIL_FILE .. ".tmp"
        local detail_file = io.open(detail_tmp_file, "w")
        if detail_file then
            detail_file:write(jsonc.stringify(detail_data))
            detail_file:close()
            os.rename(detail_tmp_file, USER_PARENTAL_CONTROL_DETAIL_FILE)
        else
            log(string.format("ParentalControlStatus: failed to open detail temp file %s", detail_tmp_file))
        end
    else
        log("ParentalControlStatus: luci.jsonc unavailable, skip detail json output")
    end

    log(string.format("ParentalControlStatus: written %d items to %s (unlimited=%d, app_limited=%d, mac_blocked=%d, all_user_app=%s)",
        #output_mac_list, USER_PARENTAL_CONTROL_STATUS_FILE, unlimited_count, app_limited_count, mac_blocked_count, tostring(appfilter_all_users_active)))
    return true
end

local function init_effective_mac_rules()
    local ok_regular = create_macfilter_rule(SINGLE_MAC_FILTER_RULE_ID, MACFILTER_RULE_MODE_SINGLE_USER)
    local ok_blacklist = create_macfilter_rule(BLACKLIST_MAC_FILTER_RULE_ID, MACFILTER_RULE_MODE_SINGLE_USER)

    if ok_regular then
        log(string.format("MACFilter effective rule initialized: rule_id=%d", SINGLE_MAC_FILTER_RULE_ID))
    else
        log(string.format("MACFilter effective rule init failed: rule_id=%d", SINGLE_MAC_FILTER_RULE_ID))
    end

    if ok_blacklist then
        log(string.format("MACFilter blacklist rule initialized: rule_id=%d", BLACKLIST_MAC_FILTER_RULE_ID))
    else
        log(string.format("MACFilter blacklist rule init failed: rule_id=%d", BLACKLIST_MAC_FILTER_RULE_ID))
    end

    return ok_regular and ok_blacklist
end

local function sync_effective_mac_rule(rule_id, rule_name, mac_list)
    local mac_count = #mac_list
    local rule_state = macfilter_rules_state[rule_id]
    local rule_active = rule_state and rule_state.active or false

    local mac_list_changed = true
    if rule_state and rule_state.mac_list then
        local old_mac_set = {}
        for _, old_mac in ipairs(rule_state.mac_list) do
            old_mac_set[old_mac] = true
        end

        if mac_count == #rule_state.mac_list then
            mac_list_changed = false
            for _, new_mac in ipairs(mac_list) do
                if not old_mac_set[new_mac] then
                    mac_list_changed = true
                    break
                end
            end
        end
    end

    local need_update = false
    if rule_active then
        need_update = mac_list_changed
    else
        need_update = (mac_count > 0) or mac_list_changed
    end

    if not need_update then
        log(string.format("%s: no changes needed (rule_id=%d, active=%s, mac_count=%d)",
            rule_name, rule_id, tostring(rule_active), mac_count))
        return true
    end

    log(string.format("%s: apply to kernel (rule_id=%d, active=%s, mac_count=%d, changed=%s)",
        rule_name, rule_id, tostring(rule_active), mac_count, tostring(mac_list_changed)))

    if not set_macfilter_rule_mac_list(rule_id, mac_list, MACFILTER_RULE_MODE_SINGLE_USER) then
        log(string.format("%s: apply failed (rule_id=%d)", rule_name, rule_id))
        return false
    end

    if not macfilter_rules_state[rule_id] then
        macfilter_rules_state[rule_id] = {}
    end
    macfilter_rules_state[rule_id].active = (mac_count > 0)
    macfilter_rules_state[rule_id].mode = MACFILTER_RULE_MODE_SINGLE_USER
    macfilter_rules_state[rule_id].mac_list = mac_list
    macfilter_rules_state[rule_id].name = rule_name
    log(string.format("%s: apply success (rule_id=%d, mac_count=%d)", rule_name, rule_id, mac_count))
    return true
end

local function process_appfilter_rules(current_info)
    log(string.format("=== Processing AppFilter rules (time: %02d:%02d, weekday: %d) ===", 
        current_info.hour, current_info.min, current_info.weekday))
    
    local rules = load_appfilter_rules()
    local appfilter_effective_mac_set = {}
    local appfilter_all_users_active = false
    local appfilter_detail_map = {}
    local appfilter_all_user_rule_details = {}
    local rule_map = {}
    for _, rule in ipairs(rules) do
        rule_map[tonumber(rule.id) or 0] = rule
    end
    
    for _, rule in ipairs(rules) do
        local time_match = is_time_in_range(rule.time_rules, current_info)
        local should_active = (rule.enabled == 1) and time_match
        local current_state = appfilter_rules_state[rule.id]
        local is_active = current_state and current_state.active or false
        
        log(string.format("AppFilter rule %d (%s): enabled=%d, time_match=%s, should_active=%s, is_active=%s", 
            rule.id, rule.name, rule.enabled, tostring(time_match), tostring(should_active), tostring(is_active)))
        
        if should_active then
            local mac_list = {}
            if rule.mode == 2 and rule.user_mac and rule.user_mac ~= "" then
                table.insert(mac_list, rule.user_mac)
            elseif rule.mode == 1 then
            end
            
            local app_id_list = rule.app_ids or {}
            
            local config_changed = false
            if not current_state then
                config_changed = true
            else
                if #mac_list ~= (current_state.mac_list and #current_state.mac_list or 0) then
                    config_changed = true
                else
                    local old_mac_set = {}
                    if current_state.mac_list then
                        for _, mac in ipairs(current_state.mac_list) do
                            old_mac_set[mac] = true
                        end
                    end
                    for _, mac in ipairs(mac_list) do
                        if not old_mac_set[mac] then
                            config_changed = true
                            break
                        end
                    end
                end
                
                if not config_changed then
                    if #app_id_list ~= (current_state.app_id_list and #current_state.app_id_list or 0) then
                        config_changed = true
                    else
                        local old_app_id_set = {}
                        if current_state.app_id_list then
                            for _, app_id in ipairs(current_state.app_id_list) do
                                old_app_id_set[app_id] = true
                            end
                        end
                        for _, app_id in ipairs(app_id_list) do
                            if not old_app_id_set[app_id] then
                                config_changed = true
                                break
                            end
                        end
                    end
                end

                if not config_changed then
                    if (tonumber(rule.filter_quic) or 0) ~= (tonumber(current_state.filter_quic) or 0) then
                        config_changed = true
                    end
                end
            end
            
            if not is_active or config_changed then
                if is_active then
                    log(string.format("AppFilter rule %d (%s): config changed, recreating", rule.id, rule.name))
                    delete_appfilter_rule(rule.id)
                else
                    log(string.format("AppFilter rule %d (%s): activating", rule.id, rule.name))
                end
                
                if create_appfilter_rule(rule.id) then
                    if not appfilter_rules_state[rule.id] then
                        appfilter_rules_state[rule.id] = {}
                    end
                    
                    if set_appfilter_rule_mac_list(rule.id, mac_list) then
                        appfilter_rules_state[rule.id].mac_list = mac_list
                    end
                    
                    if set_appfilter_rule_app_id_list(rule.id, app_id_list) then
                        appfilter_rules_state[rule.id].app_id_list = app_id_list
                    end

                    if set_appfilter_rule_filter_quic(rule.id, rule.filter_quic) then
                        appfilter_rules_state[rule.id].filter_quic = tonumber(rule.filter_quic) or 0
                    end
                    
                    appfilter_rules_state[rule.id].active = true
                    appfilter_rules_state[rule.id].name = rule.name
                    appfilter_rules_state[rule.id].mode = rule.mode
                    appfilter_rules_state[rule.id].enabled = rule.enabled
                    log(string.format("AppFilter rule %d: activated successfully", rule.id))
                end
            else
                log(string.format("AppFilter rule %d: no changes needed", rule.id))
            end
        else
            if is_active then
                log(string.format("AppFilter rule %d (%s): deactivating (enabled=%d, time_match=%s)", 
                    rule.id, rule.name, rule.enabled, tostring(time_match)))
                if delete_appfilter_rule(rule.id) then
                    appfilter_rules_state[rule.id].active = false
                    log(string.format("AppFilter rule %d: deactivated", rule.id))
                end
            end
        end
    end
    
    for rule_id, state in pairs(appfilter_rules_state) do
        local found = false
        for _, rule in ipairs(rules) do
            if rule.id == rule_id then
                found = true
                break
            end
        end
        if not found then
            if state.active then
                log(string.format("AppFilter rule %d: removed from UCI, deleting", rule_id))
                if delete_appfilter_rule(rule_id) then
                    appfilter_rules_state[rule_id] = nil
                end
            else
                appfilter_rules_state[rule_id] = nil
            end
        end
    end

    for rule_id, state in pairs(appfilter_rules_state) do
        if state and state.active then
            local rule_cfg = rule_map[tonumber(rule_id) or 0]
            if rule_cfg then
                local detail = build_appfilter_rule_detail(rule_cfg)
                if tonumber(state.mode) == 1 then
                    appfilter_all_users_active = true
                    table.insert(appfilter_all_user_rule_details, detail)
                elseif tonumber(state.mode) == 2 and state.mac_list then
                    for _, mac in ipairs(state.mac_list) do
                        if mac and mac ~= "" then
                            appfilter_effective_mac_set[mac] = true
                            append_detail_for_mac(appfilter_detail_map, mac, detail)
                        end
                    end
                end
            end
        end
    end

    return appfilter_effective_mac_set, appfilter_all_users_active, appfilter_detail_map, appfilter_all_user_rule_details
end

local function process_macfilter_rules(current_info)
    log(string.format("=== Processing MACFilter rules (time: %02d:%02d, weekday: %d) ===", 
        current_info.hour, current_info.min, current_info.weekday))
    
    local rules = load_macfilter_rules()
    
    local all_user_rules = {}
    local regular_mac_set = {}
    local blacklist_mac_set = {}
    local duration_rules = {}
    local flow_rules = {}
    local blacklist_macs = load_mac_blacklist()
    local macfilter_detail_map = {}
    local all_user_range_rule_details = {}
    
    for _, rule in ipairs(rules) do
        if rule.enabled == 1 then
            local time_mode = tonumber(rule.time_mode) or TIME_MODE_RANGE
            if time_mode == TIME_MODE_DURATION then
                table.insert(duration_rules, rule)
            elseif time_mode == TIME_MODE_FLOW then
                table.insert(flow_rules, rule)
            else
                local should_active = is_time_in_range(rule.time_rules, current_info)
                if should_active then
                    if rule.mode == 1 then
                        table.insert(all_user_rules, rule)
                        table.insert(all_user_range_rule_details, build_macfilter_rule_detail(rule, "time_range"))
                    elseif rule.mode == 2 and rule.user_mac and rule.user_mac ~= "" then
                        regular_mac_set[rule.user_mac] = true
                        append_detail_for_mac(macfilter_detail_map, rule.user_mac, build_macfilter_rule_detail(rule, "time_range"))
                    end
                end
            end
        end
    end
    
    log(string.format("MACFilter: Found %d time-range all-user rules, %d duration rules, %d flow rules (effective-mac-list mode)", 
        #all_user_rules, #duration_rules, #flow_rules))

    local user_active_map = nil
    local user_flow_bytes_map = nil
    local user_mac_list = nil
    local need_user_stat = (#all_user_rules > 0) or (#duration_rules > 0) or (#flow_rules > 0)
    if need_user_stat then
        user_active_map, user_flow_bytes_map, user_mac_list = get_macfilter_user_stat()
        if not user_active_map or not user_flow_bytes_map or not user_mac_list then
            log("MACFilter: failed to get user stat, all-user/duration/flow evaluation will be skipped this round")
            user_active_map = nil
            user_flow_bytes_map = nil
            user_mac_list = nil
        else
            log(string.format("MACFilter: got user stat, total users=%d", #user_mac_list))
        end
    end

    if #all_user_rules > 0 then
        if user_mac_list then
            local added_count = 0
            for _, mac in ipairs(user_mac_list) do
                if not regular_mac_set[mac] then
                    added_count = added_count + 1
                end
                regular_mac_set[mac] = true
            end
            log(string.format("MACFilter all-user range: %d active rules, add %d users into effective mac list", #all_user_rules, added_count))
        else
            log("MACFilter all-user range: skip because user stat unavailable")
        end
    end
    
    if #duration_rules > 0 then
        if not user_active_map or not user_mac_list then
            log("MACFilter duration mode: failed to get user active minutes, skipping duration match this round")
        else
            log(string.format("MACFilter duration mode: begin match, users=%d, rules=%d", #user_mac_list, #duration_rules))
            for _, rule in ipairs(duration_rules) do
                local target_macs = {}
                if rule.mode == 1 then
                    for _, mac in ipairs(user_mac_list) do
                        table.insert(target_macs, mac)
                    end
                elseif rule.mode == 2 and rule.user_mac and rule.user_mac ~= "" then
                    table.insert(target_macs, rule.user_mac)
                end

                log(string.format("MACFilter duration rule %d (%s): mode=%d, target_macs=%d, duration_items=%d",
                    rule.id, rule.name, rule.mode, #target_macs, #(rule.duration_rules or {})))

                for _, target_mac in ipairs(target_macs) do
                    local active_minutes = user_active_map[target_mac] or 0
                    local exceeded = false
                    local weekday_hit = false
                    local min_remaining = nil
                    local exceeded_limit_minutes = 0
                    local duration_rule_list = rule.duration_rules or {}
                    for _, duration_rule in ipairs(duration_rule_list) do
                        if weekday_match(duration_rule.weekdays, current_info.weekday) then
                            local limit_minutes = duration_rule.duration_minutes or 0
                            if limit_minutes <= 0 then
                                weekday_hit = true
                                log(string.format("MACFilter duration check: rule_id=%d, mac=%s, limit=0(unlimited), skip block",
                                    rule.id, target_mac))
                                break
                            end
                            local remaining_minutes = limit_minutes - active_minutes
                            local current_exceeded = active_minutes > limit_minutes
                            weekday_hit = true
                            if min_remaining == nil or remaining_minutes < min_remaining then
                                min_remaining = remaining_minutes
                            end
                            log(string.format("MACFilter duration check: rule_id=%d, mac=%s, used=%dmin, limit=%dmin, remain=%dmin, exceeded=%s",
                                rule.id, target_mac, active_minutes, limit_minutes, remaining_minutes, tostring(current_exceeded)))
                            if current_exceeded then
                                exceeded = true
                                exceeded_limit_minutes = limit_minutes
                                break
                            end
                        end
                    end
                    if exceeded then
                        regular_mac_set[target_mac] = true
                        local detail = build_macfilter_rule_detail(rule, "duration")
                        detail.used_minutes = active_minutes
                        detail.limit_minutes = exceeded_limit_minutes
                        append_detail_for_mac(macfilter_detail_map, target_mac, detail)
                        log(string.format("MACFilter duration result: rule_id=%d, mac=%s, final=block", rule.id, target_mac))
                    else
                        if weekday_hit then
                            log(string.format("MACFilter duration result: rule_id=%d, mac=%s, final=allow, remain=%dmin",
                                rule.id, target_mac, min_remaining or 0))
                        else
                            log(string.format("MACFilter duration result: rule_id=%d, mac=%s, final=allow, reason=no weekday match",
                                rule.id, target_mac))
                        end
                    end
                end
            end
        end
    end

    if #flow_rules > 0 then
        if not user_flow_bytes_map or not user_mac_list then
            log("MACFilter flow mode: failed to get user flow stats, skipping flow match this round")
        else
            log(string.format("MACFilter flow mode: begin match, users=%d, rules=%d", #user_mac_list, #flow_rules))
            for _, rule in ipairs(flow_rules) do
                local target_macs = {}
                if rule.mode == 1 then
                    for _, mac in ipairs(user_mac_list) do
                        table.insert(target_macs, mac)
                    end
                elseif rule.mode == 2 and rule.user_mac and rule.user_mac ~= "" then
                    table.insert(target_macs, rule.user_mac)
                end

                log(string.format("MACFilter flow rule %d (%s): mode=%d, target_macs=%d, flow_items=%d",
                    rule.id, rule.name, rule.mode, #target_macs, #(rule.flow_rules or {})))

                for _, target_mac in ipairs(target_macs) do
                    local used_flow_bytes = user_flow_bytes_map[target_mac] or 0
                    local used_flow_mb = used_flow_bytes / (1024 * 1024)
                    local exceeded = false
                    local weekday_hit = false
                    local min_remaining_mb = nil
                    local exceeded_limit_mb = 0
                    local flow_rule_list = rule.flow_rules or {}
                    for _, flow_rule in ipairs(flow_rule_list) do
                        if weekday_match(flow_rule.weekdays, current_info.weekday) then
                            local limit_mb = tonumber(flow_rule.flow_mb) or 0
                            if limit_mb <= 0 then
                                weekday_hit = true
                                log(string.format("MACFilter flow check: rule_id=%d, mac=%s, limit=0(unlimited), skip block",
                                    rule.id, target_mac))
                                break
                            end
                            local limit_bytes = limit_mb * 1024 * 1024
                            local remaining_mb = limit_mb - used_flow_mb
                            local current_exceeded = used_flow_bytes > limit_bytes
                            weekday_hit = true
                            if min_remaining_mb == nil or remaining_mb < min_remaining_mb then
                                min_remaining_mb = remaining_mb
                            end
                            log(string.format("MACFilter flow check: rule_id=%d, mac=%s, used=%.2fMB, limit=%dMB, remain=%.2fMB, exceeded=%s",
                                rule.id, target_mac, used_flow_mb, limit_mb, remaining_mb, tostring(current_exceeded)))
                            if current_exceeded then
                                exceeded = true
                                exceeded_limit_mb = limit_mb
                                break
                            end
                        end
                    end
                    if exceeded then
                        regular_mac_set[target_mac] = true
                        local detail = build_macfilter_rule_detail(rule, "flow")
                        detail.used_mb = tonumber(string.format("%.2f", used_flow_mb)) or used_flow_mb
                        detail.limit_mb = exceeded_limit_mb
                        append_detail_for_mac(macfilter_detail_map, target_mac, detail)
                        log(string.format("MACFilter flow result: rule_id=%d, mac=%s, final=block", rule.id, target_mac))
                    else
                        if weekday_hit then
                            log(string.format("MACFilter flow result: rule_id=%d, mac=%s, final=allow, remain=%.2fMB",
                                rule.id, target_mac, min_remaining_mb or 0))
                        else
                            log(string.format("MACFilter flow result: rule_id=%d, mac=%s, final=allow, reason=no weekday match",
                                rule.id, target_mac))
                        end
                    end
                end
            end
        end
    end

    if #blacklist_macs > 0 then
        for _, blacklist_mac in ipairs(blacklist_macs) do
            blacklist_mac_set[blacklist_mac] = true
            append_detail_for_mac(macfilter_detail_map, blacklist_mac, {
                rule_id = BLACKLIST_MAC_FILTER_RULE_ID,
                rule_name = BLACKLIST_RULE_NAME,
                mode = MACFILTER_RULE_MODE_SINGLE_USER,
                time_mode = TIME_MODE_RANGE,
                user_mac = blacklist_mac,
                match_type = "blacklist"
            })
        end
        log(string.format("MACFilter blacklist: total=%d", #blacklist_macs))
    end

    local regular_mac_list = {}
    for mac, _ in pairs(regular_mac_set) do
        table.insert(regular_mac_list, mac)
    end
    table.sort(regular_mac_list)

    local blacklist_mac_list = {}
    for mac, _ in pairs(blacklist_mac_set) do
        table.insert(blacklist_mac_list, mac)
    end
    table.sort(blacklist_mac_list)

    if #duration_rules > 0 or #flow_rules > 0 or #all_user_rules > 0 or #blacklist_macs > 0 then
        local regular_preview = table.concat(regular_mac_list, ",")
        if string.len(regular_preview) > 512 then
            regular_preview = string.sub(regular_preview, 1, 512) .. "..."
        end
        local blacklist_preview = table.concat(blacklist_mac_list, ",")
        if string.len(blacklist_preview) > 512 then
            blacklist_preview = string.sub(blacklist_preview, 1, 512) .. "..."
        end
        log(string.format("MACFilter effective mac summary: regular_count=%d, regular_macs=%s, blacklist_count=%d, blacklist_macs=%s",
            #regular_mac_list, regular_preview, #blacklist_mac_list, blacklist_preview))
    end

    sync_effective_mac_rule(SINGLE_MAC_FILTER_RULE_ID, "MAC Filter (Effective List)", regular_mac_list)
    sync_effective_mac_rule(BLACKLIST_MAC_FILTER_RULE_ID, "Internet Blacklist (Effective List)", blacklist_mac_list)
    
    for rule_id, state in pairs(macfilter_rules_state) do
        if rule_id ~= SINGLE_MAC_FILTER_RULE_ID and rule_id ~= BLACKLIST_MAC_FILTER_RULE_ID then
            local found = false
            for _, rule in ipairs(rules) do
                if rule.id == rule_id then
                    found = true
                    break
                end
            end
            if not found then
                log(string.format("MACFilter rule %d: removed from UCI, cleaning up state", rule_id))
                macfilter_rules_state[rule_id] = nil
            end
        end
    end

    local merged_block_set = {}
    for mac, _ in pairs(regular_mac_set) do
        merged_block_set[mac] = true
    end
    for mac, _ in pairs(blacklist_mac_set) do
        merged_block_set[mac] = true
    end

    return merged_block_set, macfilter_detail_map
end

local function get_uci_enable(config, section, option)
    local uci_cursor = uci.cursor()
    local value = tonumber(uci_cursor:get(config, section, option)) or 0
    uci_cursor:unload(config)
    return value
end

local function apply_appfilter_enable(enable)
    log(string.format("=== Applying AppFilter enable: %d ===", enable))
    local proc_file = "/proc/sys/fwx/appfilter_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("AppFilter enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function apply_macfilter_enable(enable)
    log(string.format("=== Applying MACFilter enable: %d ===", enable))
    local proc_file = "/proc/sys/fwx/macfilter_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("MACFilter enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function check_and_apply_appfilter_enable()
    local current_enable = get_uci_enable("fwx", "appfilter", "enable")
    if appfilter_enable_state == nil or appfilter_enable_state ~= current_enable then
        log(string.format("AppFilter enable changed: %s -> %d", 
            appfilter_enable_state == nil and "nil" or tostring(appfilter_enable_state), current_enable))
        if apply_appfilter_enable(current_enable) then
            appfilter_enable_state = current_enable
        end
    end
end

local function check_and_apply_macfilter_enable()
    local current_enable = get_uci_enable("fwx", "macfilter", "enable")
    if macfilter_enable_state == nil or macfilter_enable_state ~= current_enable then
        log(string.format("MACFilter enable changed: %s -> %d", 
            macfilter_enable_state == nil and "nil" or tostring(macfilter_enable_state), current_enable))
        if apply_macfilter_enable(current_enable) then
            macfilter_enable_state = current_enable
        end
    end
end

local function apply_record_enable(enable)
    log(string.format("=== Applying Record enable: %d ===", enable))
    local proc_file = "/proc/sys/fwx/record_enable"
    local file = io.open(proc_file, "w")
    if file then
        file:write(tostring(enable))
        file:close()
        log(string.format("Record enable set to %d successfully", enable))
        return true
    else
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end
end

local function check_and_apply_record_enable()
    local current_enable = get_uci_enable("fwx", "record", "enable")
    if record_enable_state == nil or record_enable_state ~= current_enable then
        log(string.format("Record enable changed: %s -> %d", 
            record_enable_state == nil and "nil" or tostring(record_enable_state), current_enable))
        if apply_record_enable(current_enable) then
            record_enable_state = current_enable
        end
    end
end

local function check_state_file(file_path)
    local file = io.open(file_path, "r")
    if not file then
        return false
    end
    
    local content = file:read("*line")
    file:close()
    
    return (content == "1")
end

local function reset_state_file(file_path)
    local file = io.open(file_path, "w")
    if file then
        file:write("0")
        file:close()
        return true
    end
    return false
end

local function check_reinit_flags()
    local appfilter_reinit = check_state_file(APPFILTER_STATE_FILE)
    local macfilter_reinit = check_state_file(MACFILTER_STATE_FILE)
    local appfilter_whitelist_reinit = check_state_file(APPFILTER_WHITELIST_STATE_FILE)
    local macfilter_whitelist_reinit = check_state_file(MACFILTER_WHITELIST_STATE_FILE)
    local record_whitelist_reinit = check_state_file(RECORD_WHITELIST_STATE_FILE)
    
    return appfilter_reinit, macfilter_reinit, appfilter_whitelist_reinit, macfilter_whitelist_reinit, record_whitelist_reinit
end

local function flush_appfilter_rules()
    log("=== Flushing AppFilter rules ===")
    local json_str = '{"api":"flush_app_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("AppFilter rules flushed successfully")
        return true
    else
        log("Failed to flush AppFilter rules")
        return false
    end
end

local function flush_macfilter_rules()
    log("=== Flushing MACFilter rules ===")
    local json_str = '{"api":"flush_mac_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MACFilter rules flushed successfully")
        return true
    else
        log("Failed to flush MACFilter rules")
        return false
    end
end

local function flush_appfilter_whitelist()
    log("=== Flushing AppFilter whitelist ===")
    local json_str = '{"api":"flush_app_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("AppFilter whitelist flushed successfully")
        return true
    else
        log("Failed to flush AppFilter whitelist")
        return false
    end
end

local function flush_macfilter_whitelist()
    log("=== Flushing MACFilter whitelist ===")
    local json_str = '{"api":"flush_mac_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MACFilter whitelist flushed successfully")
        return true
    else
        log("Failed to flush MACFilter whitelist")
        return false
    end
end

local function load_appfilter_whitelist()
    log("=== Loading AppFilter whitelist from UCI ===")
    
    local uci_cursor = uci.cursor()
    local mac_list = {}
    
    uci_cursor:foreach("appfilter_whitelist", "whitelist_mac", function(section)
        local mac = section.mac or ""
        if mac and mac ~= "" then
            table.insert(mac_list, mac)
        end
    end)
    
    uci_cursor:unload("appfilter_whitelist")
    
    log(string.format("AppFilter whitelist: loaded %d MAC addresses", #mac_list))
    return mac_list
end

local function load_macfilter_whitelist()
    log("=== Loading MACFilter whitelist from UCI ===")
    
    local uci_cursor = uci.cursor()
    local mac_list = {}
    
    uci_cursor:foreach("macfilter_whitelist", "whitelist_mac", function(section)
        local mac = section.mac or ""
        if mac and mac ~= "" then
            table.insert(mac_list, mac)
        end
    end)
    
    uci_cursor:unload("macfilter_whitelist")
    
    log(string.format("MACFilter whitelist: loaded %d MAC addresses", #mac_list))
    return mac_list
end

local function load_record_whitelist()
    log("=== Loading Record whitelist from UCI ===")

    local uci_cursor = uci.cursor()
    local mac_list = {}
    local mac_set = {}
    local function append_section_macs(section)
        local whitelist = section.whitelist
        if type(whitelist) == "table" then
            for _, mac in ipairs(whitelist) do
                if mac and mac ~= "" and not mac_set[mac] then
                    mac_set[mac] = true
                    table.insert(mac_list, mac)
                end
            end
        elseif type(whitelist) == "string" then
            if whitelist ~= "" and not mac_set[whitelist] then
                mac_set[whitelist] = true
                table.insert(mac_list, whitelist)
            end
        end
    end

    uci_cursor:foreach("fwx_record", "whitelist", function(section)
        append_section_macs(section)
    end)

    if #mac_list == 0 then
        uci_cursor:foreach("fwx_record", "record", function(section)
            append_section_macs(section)
        end)
    end

    uci_cursor:unload("fwx_record")

    log(string.format("Record whitelist: loaded %d MAC addresses", #mac_list))
    return mac_list
end

local function apply_appfilter_whitelist(mac_list)
    log(string.format("=== Applying AppFilter whitelist, count=%d ===", #mac_list))
    
    flush_appfilter_whitelist()
    
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
        
        local json_str = string.format('{"api":"add_app_filter_whitelist","data":{"mac_list":%s}}', mac_array_str)
        if write_to_dev_fwx(json_str) then
            log(string.format("AppFilter whitelist applied successfully: %d MACs", #mac_list))
            return true
        else
            log("Failed to apply AppFilter whitelist")
            return false
        end
    else
        log("AppFilter whitelist is empty, no MACs to add")
        return true
    end
end

local function apply_macfilter_whitelist(mac_list)
    log(string.format("=== Applying MACFilter whitelist, count=%d ===", #mac_list))
    
    flush_macfilter_whitelist()
    
    if #mac_list > 0 then
        local mac_strs = {}
        for _, mac in ipairs(mac_list) do
            table.insert(mac_strs, string.format('"%s"', mac))
        end
        local mac_array_str = "[" .. table.concat(mac_strs, ",") .. "]"
        
        local json_str = string.format('{"api":"add_mac_filter_whitelist","data":{"mac_list":%s}}', mac_array_str)
        if write_to_dev_fwx(json_str) then
            log(string.format("MACFilter whitelist applied successfully: %d MACs", #mac_list))
            return true
        else
            log("Failed to apply MACFilter whitelist")
            return false
        end
    else
        log("MACFilter whitelist is empty, no MACs to add")
        return true
    end
end

local function apply_record_whitelist(mac_list)
    log(string.format("=== Applying Record whitelist, count=%d ===", #mac_list))

    local proc_file = "/proc/sys/fwx/record_whitelist"
    local file = io.open(proc_file, "w")
    if not file then
        log(string.format("Failed to open %s for writing", proc_file))
        return false
    end

    local content = ""
    if #mac_list > 0 then
        content = table.concat(mac_list, ",")
    else
        content = "\n"
    end

    file:write(content)
    file:close()
    log(string.format("Record whitelist applied successfully: %d MACs", #mac_list))
    return true
end

local function interruptible_sleep(seconds)
    for i = 1, seconds do
        local result = os.execute("sleep 1")
        if result ~= 0 and result ~= true then
            return
        end
    end
end

local function flush_all_rules()
    log("=== Flushing all rules before initialization ===")
    
    local json_str = '{"api":"flush_mac_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MAC filter rules flushed")
    else
        log("Failed to flush MAC filter rules")
    end
    
    json_str = '{"api":"flush_app_filter_rule","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("App filter rules flushed")
    else
        log("Failed to flush App filter rules")
    end
    
    json_str = '{"api":"flush_mac_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("MAC filter whitelist flushed")
    else
        log("Failed to flush MAC filter whitelist")
    end
    
    json_str = '{"api":"flush_app_filter_whitelist","data":{}}'
    if write_to_dev_fwx(json_str) then
        log("App filter whitelist flushed")
    else
        log("Failed to flush App filter whitelist")
    end

    if apply_record_whitelist({}) then
        log("Record whitelist flushed")
    else
        log("Failed to flush Record whitelist")
    end
    
    log("All rules flushed successfully")
    return true
end

local function initialize_rules()
    flush_all_rules()
    check_and_apply_appfilter_enable()
    check_and_apply_macfilter_enable()
    check_and_apply_record_enable()  
    
    init_effective_mac_rules()
    
    local appfilter_rules = load_appfilter_rules()
    for _, rule in ipairs(appfilter_rules) do
        appfilter_rules_state[rule.id] = {
            active = false,
            name = rule.name,
            mode = rule.mode,
            filter_quic = tonumber(rule.filter_quic) or 0
        }
    end
    
    local macfilter_rules = load_macfilter_rules()
    for _, rule in ipairs(macfilter_rules) do
        macfilter_rules_state[rule.id] = {
            active = false,
            mode = rule.mode,
            name = rule.name,
            user_mac = rule.user_mac
        }
    end
    
    log(string.format("Initialized: %d AppFilter rules, %d MACFilter rules", 
        #appfilter_rules, #macfilter_rules))
    
    log("=== Loading whitelists ===")
    local appfilter_whitelist = load_appfilter_whitelist()
    apply_appfilter_whitelist(appfilter_whitelist)
    
    local macfilter_whitelist = load_macfilter_whitelist()
    apply_macfilter_whitelist(macfilter_whitelist)

    local record_whitelist = load_record_whitelist()
    apply_record_whitelist(record_whitelist)
    
    log("Whitelists initialized successfully")
end

local function main_loop()
    log("Rule manager started")
    
    initialize_rules()
    
    local running = true
    
    while running do
        local appfilter_reinit, macfilter_reinit, appfilter_whitelist_reinit, macfilter_whitelist_reinit, record_whitelist_reinit = check_reinit_flags()
        
        if appfilter_whitelist_reinit then
            log("=== AppFilter whitelist state file detected change, reloading ===")
            local appfilter_whitelist = load_appfilter_whitelist()
            apply_appfilter_whitelist(appfilter_whitelist)
            if reset_state_file(APPFILTER_WHITELIST_STATE_FILE) then
                log("AppFilter whitelist state file reset to 0")
            else
                log("Failed to reset AppFilter whitelist state file")
            end
        end
        
        if macfilter_whitelist_reinit then
            log("=== MACFilter whitelist state file detected change, reloading ===")
            local macfilter_whitelist = load_macfilter_whitelist()
            apply_macfilter_whitelist(macfilter_whitelist)
            if reset_state_file(MACFILTER_WHITELIST_STATE_FILE) then
                log("MACFilter whitelist state file reset to 0")
            else
                log("Failed to reset MACFilter whitelist state file")
            end
        end

        if record_whitelist_reinit then
            log("=== Record whitelist state file detected change, reloading ===")
            local record_whitelist = load_record_whitelist()
            apply_record_whitelist(record_whitelist)
            if reset_state_file(RECORD_WHITELIST_STATE_FILE) then
                log("Record whitelist state file reset to 0")
            else
                log("Failed to reset Record whitelist state file")
            end
        end
        
        if appfilter_reinit then
            log("=== AppFilter rules state file detected change, reinitializing ===")
            flush_appfilter_rules()
            
            check_and_apply_appfilter_enable()
            
            appfilter_rules_state = {}
            local appfilter_rules = load_appfilter_rules()
            for _, rule in ipairs(appfilter_rules) do
                appfilter_rules_state[rule.id] = {
                    active = false,
                    name = rule.name,
                    mode = rule.mode,
                    filter_quic = tonumber(rule.filter_quic) or 0
                }
            end
            log(string.format("AppFilter rules reinitialized: %d rules", #appfilter_rules))
            if reset_state_file(APPFILTER_STATE_FILE) then
                log("AppFilter state file reset to 0")
            else
                log("Failed to reset AppFilter state file")
            end
        end
        
        if macfilter_reinit then
            flush_macfilter_rules()
            
            check_and_apply_macfilter_enable()
            
            macfilter_rules_state = {}
            init_effective_mac_rules()
            local macfilter_rules = load_macfilter_rules()
            for _, rule in ipairs(macfilter_rules) do
                macfilter_rules_state[rule.id] = {
                    active = false,
                    mode = rule.mode,
                    name = rule.name,
                    user_mac = rule.user_mac
                }
            end
            log(string.format("MACFilter rules reinitialized: %d rules", #macfilter_rules))
            if reset_state_file(MACFILTER_STATE_FILE) then
                log("MACFilter state file reset to 0")
            else
                log("Failed to reset MACFilter state file")
            end
        end
        
        local current_info = get_current_time_info()
        local appfilter_effective_mac_set = {}
        local appfilter_all_users_active = false
        local appfilter_detail_map = {}
        local appfilter_all_user_rule_details = {}
        local macfilter_block_set = {}
        local macfilter_detail_map = {}
        local macfilter_all_user_rule_details = {}
        
        local ok, err = pcall(function()
            appfilter_effective_mac_set, appfilter_all_users_active, appfilter_detail_map, appfilter_all_user_rule_details =
                process_appfilter_rules(current_info)
            macfilter_block_set, macfilter_detail_map, macfilter_all_user_rule_details = process_macfilter_rules(current_info)
            macfilter_block_set = macfilter_block_set or {}
            macfilter_detail_map = macfilter_detail_map or {}
            macfilter_all_user_rule_details = macfilter_all_user_rule_details or {}
        end)
        
        if not ok then
            log("ERROR processing rules: " .. tostring(err))
        end

        local status_ok, status_err = pcall(function()
            write_user_parental_control_status(
                appfilter_effective_mac_set or {},
                appfilter_all_users_active or false,
                macfilter_block_set or {},
                appfilter_detail_map or {},
                appfilter_all_user_rule_details or {},
                macfilter_all_user_rule_details or {},
                macfilter_detail_map or {}
            )
        end)
        if not status_ok then
            log("ERROR writing parental control status: " .. tostring(status_err))
        end
        interruptible_sleep(CHECK_INTERVAL)
    end
end

if arg[0] and arg[0]:match("rule_manager") then
    main_loop()
end
