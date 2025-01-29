local ds = require "luci.dispatcher"
local nxo = require "nixio"
local nfs = require "nixio.fs"
local ipc = require "luci.ip"
local sys = require "luci.sys"
local utl = require "luci.util"
local dsp = require "luci.dispatcher"
local uci = require "luci.model.uci"
local lng = require "luci.i18n"
local jsc = require "luci.jsonc"

local m, s
arg[1] = arg[1] or ""
m = Map("appfilter", translate("应用过滤规则"), translate("已选择的app将会被禁止联网"))

local v
v = m:section(SimpleSection)
v.template = "admin_network/app_filter"
return m
