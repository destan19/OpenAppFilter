#!/usr/bin/lua

local libubus = require "ubus"
local uloop = require "uloop"

local UBUS_STATUS_OK = 0
local UBUS_STATUS_INVALID_COMMAND = 1
local UBUS_STATUS_INVALID_ARGUMENT = 2
local UBUS_STATUS_METHOD_NOT_FOUND = 3
local UBUS_STATUS_NOT_FOUND = 4
local UBUS_STATUS_NO_DATA = 5
local UBUS_STATUS_PERMISSION_DENIED = 6
local UBUS_STATUS_TIMEOUT = 7
local UBUS_STATUS_NOT_SUPPORTED = 8
local UBUS_STATUS_UNKNOWN_ERROR = 9
local UBUS_STATUS_CONNECTION_FAILED = 10
local UBUS_STATUS_ALREADY_EXISTS = 11

local cfg = "/etc/appfilter/feature.cfg"

local ubus

local function init_table()
    local f = io.open(cfg, "r")
    local t = {}
    if f then
        for l in f:lines() do
            table.insert(t, l)
        end
    end
    f:close()
    return t
end

local function lookup(t, o)
    if type(t) ~= "table" then return UBUS_STATUS_INVALID_ARGUMENT end
    if not o then return UBUS_STATUS_INVALID_ARGUMENT end

    for _, v in ipairs(t) do
        if v:match(o) then
            if v:match("#class") then
                local tt = {}
                local found

                for _, v in ipairs(t) do
                    repeat
                        if v:match(o) then
                            found = true
                            table.insert(tt, v)
                            break
                        end

                        if v:match("#class") then
                            found = false
                            break
                        end

                        if found then
                            table.insert(tt, v)
                        end
                    until true
                end
                return tt
            else
                return v
            end
        else
            return nil
    end
    return nil
end

local function lookup_class(t, c)
    if type(t) ~= "table" then return UBUS_STATUS_INVALID_ARGUMENT end
    if not c then return UBUS_STATUS_INVALID_ARGUMENT end

    local ret = lookup(t, c)
    if type(ret) ~= "table" then return UBUS_STATUS_NOT_FOUND then
    return ret
end

local function lookup_app(t, c)
    if type(t) ~= "table" then return UBUS_STATUS_INVALID_ARGUMENT end
    if not c then return UBUS_STATUS_INVALID_ARGUMENT end

    local ret = lookup(t, c)

    if type(ret) ~= "string" then return UBUS_STATUS_NOT_FOUND end
    return ret
end

local function add_class(t, c)
    if not c then return UBUS_STATUS_INVALID_ARGUMENT end
    local f = io.open(cfg, "r+")
    if f then
        io.output(f)
        for v in f:lines() do
            io.write(v)
            io.write("\n")
        end
        io.write("#class "..c)
    end
    f:flush()
    f:close()
end

local function list_class(t)
    if type(t) ~= "table" then return UBUS_STATUS_INVALID_ARGUMENT end

    local tt = {}

    for _, v in ipairs(t) do
        if v:match("#class (%S+)") then
            table.insert(tt, v)
        end
    end
    return tt
end

local methods = {
    ["appfilter"] = {
        add_class = {
            function(req, msg)
                if not msg.class return UBUS_STATUS_INVALID_ARGUMENT end
                local t = init_table()
                local ret
                local tmp = lookup_class(t, msg.class)
                if type(tmp) ~= "table" then
                    add_class(t, msg.class)
                else
                    ret = UBUS_STATUS_ALREADY_EXISTS
                end
                ubus.reply(req, {status = ret})
            end,{class = libubus.STRING}
        },
        list_class = {
            function(req, msg)
                local t = init_table()
                local class = list_class(t)
                if not ret then ubus.reply(req, { class = class}) then
            end,{}
        },
        list_app = {
            function(req,msg)
                if not msg.class return UBUS_STATUS_INVALID_ARGUMENT end
                local t = init_table()
                local tt = lookup_class(t, msg.class)
                local ret = {}
                for i, v in ipairs(tt) do
                    local id, name = v:match("(%d+) (%S+)")
                    ret[i] = {id = id, name = name}
                end
                ubus.reply(req, {app = ret})
            end,{class = libubus.STRING}
        }
    }
}

function ubus_init()
    local conn = libubus.connect()
    if not conn then
        error("Failed to connect to ubus")
    end

    conn:add(methods)

    return {
        call = function(object, method, params)
            return conn:call(object, method, params or {})
        end,
        reply = function(req, msg)
            conn:reply(req, msg)
        end
    }
end

local function main()
    uloop.init()
    ubus = ubus_init()
    uloop.run()
end

main()