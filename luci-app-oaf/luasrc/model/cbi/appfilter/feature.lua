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

m = Map("appfilter", translate(""),
    translate("特征库用于描述app特征，app过滤效果和个数依赖特征库"))

local rule_count = 0
local version = ""
if nixio.fs.access("/tmp/feature.cfg") then
    rule_count = tonumber(SYS.exec("cat /tmp/feature.cfg | wc -l"))
    version = SYS.exec("cat /tmp/feature.cfg |grep \"#version\" | awk '{print $2}'")
end

local display_str = "<strong>当前版本:  </strong>" .. version .. "<br><strong>特征码个数:</strong>  " ..
                        rule_count ..
                        "<br><strong>  下载地址:</strong><a href=\"https://destan19.github.io\">https://destan19.github.io</a>"
s = m:section(TypedSection, "feature", translate("Update feature"), display_str)

fu = s:option(FileUpload, "")
fu.template = "cbi/oaf_upload"
s.anonymous = true

um = s:option(DummyValue, "rule_data")
um.template = "cbi/oaf_dvalue"

local dir, fd
dir = "/tmp/upload/"
nixio.fs.mkdir(dir)
http.setfilehandler(function(meta, chunk, eof)
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
        local fd2 = io.open("/tmp/upload/" .. meta.file)
        local line = fd2:read("*l");
        fd2:close()
        local ret = string.match(line, "#version")
        local feature_file = "/etc/appfilter/feature.cfg"
        if ret ~= nil then
            local cmd = "cp /tmp/upload/" .. meta.file .. " " .. feature_file;
            os.execute(cmd);
            os.execute("chmod 666 " .. feature_file);
            os.execute("rm /tmp/appfilter -fr");
            luci.sys.exec("/etc/init.d/appfilter restart &");
            um.value = translate("Update the feature file successfully, please refresh the page")
        else
            um.value = translate("Failed to update feature file, format error")
        end
        os.execute("rm /tmp/upload/* -fr");
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
