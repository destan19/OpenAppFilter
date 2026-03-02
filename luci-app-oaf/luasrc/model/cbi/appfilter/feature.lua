
local nfs = require "nixio.fs"
local sys = require "luci.sys"
local SYS = require "luci.sys"
local http = luci.http

local m, s

m = Map("appfilter", translate("App Feature Library"), translate("The App feature library is used to describe the packet protocol of applications, including port, domain, and Layer7 payload. It is the core of the DPI engine and affects the effectiveness of OAF. You can also add or modify App features according to the official website tutorial."))
s = m:section(SimpleSection)
s.template = "admin_network/feature"
s.anonymous = true

local dir, fd
dir = "/tmp/upload/"
nixio.fs.mkdir(dir)

local STATUS_FILE = "/tmp/feature_upgrade.status"
local MAX_SIZE = 20 * 1024 * 1024

local function write_status(code)
    local f = io.open(STATUS_FILE, "w+")
    if f then
        f:write(tostring(code))
        f:close()
    end
end

local function log(msg)
    local f = io.open("/tmp/log/luci.log", "a+")
    if f then
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. " [fwx_feature_upload] " .. tostring(msg) .. "\n")
        f:close()
    end
end

local function get_overlay_free_space()
    local df_output = SYS.exec("df -k /overlay 2>/dev/null | tail -1 | awk '{print $4}'")
    if df_output then
        df_output = string.gsub(df_output, "%s+", "")
        local free_kb = tonumber(df_output)
        if free_kb then
            return free_kb * 1024  -- 转换为字节
        end
    end
    return 0
end

local function get_dir_size(dir_path)
    local du_output = SYS.exec("du -sb " .. dir_path .. " 2>/dev/null | awk '{print $1}'")
    if du_output then
        du_output = string.gsub(du_output, "%s+", "")
        local size_bytes = tonumber(du_output)
        if size_bytes then
            return size_bytes
        end
    end
    return 0
end

http.setfilehandler(function(meta, chunk, eof)
    local feature_file = "/etc/appfilter/feature.cfg"
    local f_format = "v3.0"
    local format = "v3.0"
    if not fd then
        if not meta then
            return
        end
        if meta and chunk then
            log("start upload filename=" .. (meta.file or ""))
            fd = nixio.open(dir .. meta.file, "w")
            write_status(1)
        end
        if not fd then
            log("open file failed: " .. (dir .. (meta.file or "")))
            write_status(401)
            return
        end
    end
    if chunk and fd then
        fd:write(chunk)
    end
    if eof and fd then
        fd:close()
        log("upload finished, saved to " .. dir .. (meta.file or ""))
        local meta_size = 0
        do
            local file_path = dir .. (meta.file or "")
            local stat = nixio.fs.stat(file_path)
            if stat and stat.size then
                meta_size = stat.size
            end
        end
        log("meta_size: " .. tostring(meta_size) .. ", MAX_SIZE: " .. tostring(MAX_SIZE))
        if meta_size > MAX_SIZE then
            log("file too large: " .. tostring(meta_size))
            write_status(402)
            os.execute("rm /tmp/upload/* -fr")
            return
        end

        local tar_cmd = "tar -zxvf /tmp/upload/" .. meta.file .. " -C /tmp/upload/ >/dev/null"
        local success = os.execute(tar_cmd)
        if success ~= 0 then
            log("tar extract failed: " .. tar_cmd)
            write_status(401)
            return
        end

        local feature_dir = "/tmp/upload/feature"
        local fd2 = io.open("/tmp/upload/feature.cfg")
        if not fd2 then
            log("feature.cfg not found after extract")
            write_status(401)
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
                log("format mismatch: got " .. f_format .. ", expected " .. format)
                write_status(401)
                os.execute("rm /tmp/upload/* -fr")
                return
            end
            local cmd = "cp /tmp/upload/feature.cfg " .. feature_file
            os.execute(cmd)
            
            local app_icons_src = "/tmp/upload/app_icons"
            local app_icons_dst = "/www/luci-static/resources/app_icons"
            
            if nixio.fs.stat(app_icons_src) then
                local app_icons_size = get_dir_size(app_icons_src)
                local overlay_free = get_overlay_free_space()
                
                log("app_icons size: " .. tostring(app_icons_size) .. " bytes, overlay free: " .. tostring(overlay_free) .. " bytes")
                
                if overlay_free >= app_icons_size then
                    log("overlay space sufficient, copying app_icons to /www")
                    os.execute("rm -rf " .. app_icons_dst .. "/*")
                    cmd = "cp -r " .. app_icons_src .. "/* " .. app_icons_dst .. "/ >/dev/null 2>&1"
                    os.execute(cmd)
                    log("app_icons copied to /www/luci-static/resources/app_icons")
                else
                    log("overlay space insufficient (" .. tostring(overlay_free) .. " < " .. tostring(app_icons_size) .. "), skipping app_icons copy")
                end
            else
                log("app_icons directory not found in upload package, skipping")
            end
            os.execute("chmod 666 " .. feature_file)
            luci.sys.exec("killall -SIGUSR1 oafd")
            log("feature updated successfully")
            write_status(200)
        else
            log("missing #version marker")
            write_status(401)
        end
        os.execute("rm /tmp/upload/* -fr")
    end

end)

if luci.http.formvalue("upload") then
    local f = luci.http.formvalue("ulfile")
    if #f <= 0 then
    end
elseif luci.http.formvalue("download") then
end

return m

