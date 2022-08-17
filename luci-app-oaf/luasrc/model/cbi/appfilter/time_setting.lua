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
local http = luci.http
local SYS = require "luci.sys"
local m, s

m = Map("appfilter", translate(""), translate(""))

s = m:section(TypedSection, "time", translate("Time Setting"),translate("时间2为选填，开始和结束时间需要同时设置，结束时间要大于开始时间"))
s.anonymous = true


o=s:option(ListValue, "time_mode", translate("时间匹配模式："),translate("")) 
o.default=0
o:value(0,"时间范围内规则生效")
o:value(1,"时间范围外规则生效")

days = s:option(MultiValue, "days", "", translate(""))
days.widget = "checkbox"
days.size = 10
days:value("0", translate("Sun"));
days:value("1", translate("Mon"));
days:value("2", translate("Tue"));
days:value("3", translate("Wed"));
days:value("4", translate("Thur"));
days:value("5", translate("Fri"));
days:value("6", translate("Sat"));

hv = s:option(Value, "start_time", translate("Start Time1"),translate("格式xx:xx，下同"))
hv.optional = false
hv = s:option(Value, "end_time", translate("End Time1"))
hv.optional = false

hv = s:option(Value, "start_time2", translate("Start Time2"))
hv.optional = false
hv = s:option(Value, "end_time2", translate("End Time2"))
hv.optional = false



return m
