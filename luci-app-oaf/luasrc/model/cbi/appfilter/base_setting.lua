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

m = Map("appfilter", translate("App Filter"), translate(
    "请先关闭所有加速(acc)、广告过滤、多拨等可能冲突的模块"))

s = m:section(TypedSection, "global", translate("Basic Settings"))
s:option(Flag, "enable", translate("Enable App Filter"), translate(""))
s.anonymous = true

o=s:option(ListValue, "work_mode", translate("工作模式"),translate("请正确选择模式，一般经过了WAN口转发则为主路由，建议切换模式后重启设备")) 
o.default=0
o:value(0,"主路由模式")
o:value(1,"旁路由模式")

local rule_count = 0
local version = ""

s = m:section(TypedSection, "appfilter", translate("App Filter Rules"))
s.anonymous = true
s.addremove = false

local class_fd = io.popen("find /tmp/appfilter/ -type f -name '*.class'")
if class_fd then
    while true do
        local apps
        local class
        local path = class_fd:read("*l")
        if not path then
            break
        end

        class = path:match("([^/]+)%.class$")
        s:tab(class, translate(class))
        apps = s:taboption(class, MultiValue, class .. "apps", translate(""))
        apps.rmempty = true
        apps.widget = "checkbox"
        apps.size = 10

        local fd = io.open(path)
        if fd then
            local line
            while true do
                local cmd
                local cmd_fd
                line = fd:read("*l")
                if not line then
                    break
                end
                if string.len(line) < 5 then
                    break
                end
                if not string.find(line, "#") then
                    cmd = "echo " .. line .. "|awk '{print $1}'"
                    cmd_fd = io.popen(cmd)
                    id = cmd_fd:read("*l");
                    cmd_fd:close()

                    cmd = "echo " .. line .. "|awk '{print $2}'"
                    cmd_fd = io.popen(cmd)
                    name = cmd_fd:read("*l")

                    cmd_fd:close()
                    if not id then
                        break
                    end
                    if not name then
                        break
                    end
                    apps:value(id, name)
                end
            end
            fd:close()
        end
    end
    class_fd:close()
end

return m
