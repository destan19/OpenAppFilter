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

local function llog(message)
    local log_file = "/tmp/log/oaf_luci.log"  
    local fd = io.open(log_file, "a")  
    if fd then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")  
        fd:write(string.format("[%s] %s\n", timestamp, message))  
        fd:close() 
    end
end

m = Map("appfilter", translate(""),
    translate("The feature library is used to describe App features, App filtering effect and number-dependent feature library"))

local rule_count = 0
local version = ""
local format = ""
if nixio.fs.access("/tmp/feature.cfg") then
    rule_count = tonumber(SYS.exec("cat /tmp/feature.cfg | grep -v ^$ |grep -v ^# | wc -l"))
    version = SYS.exec("cat /tmp/feature.cfg |grep \"#version\" | awk '{print $2}'")
end
-- format=SYS.exec("uci get appfilter.feature.format")
-- if format == "" then
format="v3.0"
-- end

local display_str = "<style>" ..
                    ".label-style {}" ..
                    ".item-style { margin-top:15px;}" ..
                    "</style>" ..
                    "<div class='item-style'>" ..
                        "<span class='label-style'>"..translate("Current version")..":</span> " .. version .. 
                    "</div>" ..
                    "<div class='item-style'>" ..
                        "<span class='label-style'>"..translate("Feature format")..":</span> " ..format ..
                    "</div>" ..
                    "<div class='item-style'>" ..
                        "<span class='label-style'>"..translate("App number")..":</span> " ..rule_count ..
                    "</div>" ..
                    "<div class='item-style'>" ..
                        "<span class='label-style'>"..translate("Feature download")..":</span> <a href=\"http://www.openappfilter.com\" target=\"_blank\">www.openappfilter.com</a>" ..
                    "</div>"
s = m:section(TypedSection, "feature", translate("App Feature"), display_str)

fu = s:option(FileUpload, "")
fu.template = "cbi/oaf_upload"
s.anonymous = true

um = s:option(DummyValue, "rule_data")
um.template = "cbi/oaf_dvalue"

local dir, fd
dir = "/tmp/upload/"
nixio.fs.mkdir(dir)
http.setfilehandler(function(meta, chunk, eof)
    local feature_file = "/etc/appfilter/feature.cfg"
    local f_format="v3.0"
    if not fd then
        if not meta then
            return
        end
        if meta and chunk then
            fd = nixio.open(dir .. meta.file, "w")
        end
        if not fd then
            return
        end
    end
    if chunk and fd then
        fd:write(chunk)
    end
    if eof and fd then
        fd:close()
        -- Extract the tar.gz file
        local tar_cmd = "tar -zxvf /tmp/upload/" .. meta.file .. " -C /tmp/upload/ >/dev/null"
        local success = os.execute(tar_cmd)
        if success ~= 0 then
            um.value = translate("Failed to update feature file, format error")
            return
        else
            um.value = translate("Update the feature file successfully, please refresh the page")
        end

        local feature_dir="/tmp/upload/feature"
        local fd2 = io.open("/tmp/upload/feature.cfg")
        if not fd2 then
            um.value = translate("Failed to extract feature file, file not found")
            os.execute("rm /tmp/upload/* -fr")
            return
        end
        local version_line = fd2:read("*l")
        local format_line = fd2:read("*l")
        fd2:close()
        local ret = string.match(version_line, "#version")
        if ret ~= nil then
            if string.match(format_line, "#format") then
                f_format = SYS.exec("echo '"..format_line.."'|awk '{print $2}'")
            end
            if not string.match(f_format, format) then
                um.value = translate("Failed to update feature file, format error"..",feature format:"..f_format)
                os.execute("rm /tmp/upload/* -fr")
                return
            end
            local cmd = "cp /tmp/upload/feature.cfg " .. feature_file
            os.execute(cmd)
            os.execute("rm /www/luci-static/resources/app_icons/* -fr");
            cmd = "cp /tmp/upload/app_icons/* /www/luci-static/resources/app_icons/ -fr >/dev/null"
            os.execute(cmd)
            os.execute("chmod 666 " .. feature_file)
            luci.sys.exec("killall -SIGUSR1 oafd")
            um.value = translate("Update the feature file successfully, please refresh the page")
        else
            um.value = translate("Failed to update feature file, format error")
        end
        os.execute("rm /tmp/upload/* -fr")
    end

end)

if luci.http.formvalue("upload") then
    local f = luci.http.formvalue("ulfile")
    if #f <= 0 then
        -- um.value = translate("No specify upload file.")
    end
elseif luci.http.formvalue("download") then
    Download()
end

return m


