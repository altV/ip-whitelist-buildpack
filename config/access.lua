local incoming_ip_str = ngx.var.http_x_forwarded_for
if not incoming_ip_str then
  ngx.log(ngx.ERR, "Problem with Heroku router: failed to get http_x_forwarded_for")
  return ngx.exit(500)
end

-- Plan is to
-- connect to redis
-- pass requests based on IP
-- pass requests based on host/url regexes
-- check if it's debug_allowed instance
-- block or log the request since it's not passed


-- connect to redis

local redis = require "vendor/nginx_lua/redis"
local red   = redis:new()

red:set_timeout(1000) -- 1 second



local r_password, r_host, r_port = string.match(os.getenv("IP_WHITELISTER_REDIS_DB_URL"), "://.+:(.+)@(.+):(.+)");

local ok, err = red:connect(r_host, r_port)
if not ok then
  ngx.log(ngx.ERR, "failed to connect to redis: ", err)
  return ngx.exit(500)
end

local ok, err = red:auth(r_password)
if not ok then
  ngx.log(ngx.ERR, "failed to connect to redis: ", err)
  return ngx.exit(500)
end


-- pass requests based on IP

local ip_calc = require "vendor/nginx_lua/ip_calc"

local ip_whitelist, err = red:smembers('ip_whitelist')
if not ip_whitelist then
    ngx.log(ngx.ERR, "failed to get redis set 'ip_whitelist': ", err)
    return ngx.exit(500)
end

local incoming_ip = ip_calc:ipv4_to_i(incoming_ip_str)
for k,ip_rule_str in pairs(ip_whitelist) do
  local whitelisted_ip                              = ip_calc:ipv4_to_i(ip_rule_str)
  local whitelisted_ip_net, whitelisted_ip_net_mask = ip_calc:ipv4_to_network_netmask(ip_rule_str)

  if whitelisted_ip and incoming_ip_str == ip_rule_str then
    -- ngx.log(ngx.ERR, "Whitelisted by this IP: ", ip_rule_str)
    return
  end

  if whitelisted_ip_net and ip_calc:ipv4_in_network(incoming_ip, whitelisted_ip_net, whitelisted_ip_net_mask) then
    -- ngx.log(ngx.ERR, "Whitelisted by this IP net: ", ip_rule_str)
    return
  end
end


-- pass requests based on host/url regexes

local host_url_whitelist, err = red:smembers('host_url_whitelist')
if not host_url_whitelist then
    ngx.log(ngx.ERR, "failed to get redis set 'host_url_whitelist': ", err)
    return ngx.exit(500)
end
for k,host_url_regex in pairs(host_url_whitelist) do
  local matched,err = ngx.re.match( (ngx.var.host .. ngx.var.request_uri), host_url_regex)
  if err then
    ngx.log(ngx.ERR, "Problem with host_url_regex ", host_url_regex, " : ", err)
  end
  if not err then
    if matched then
      -- ngx.log(ngx.ERR, "Whitelisted by this host_url_regex: ", host_url_regex)
      return
    end
  end
end


-- check if it's debug_allowed instance

local debug_passthrough = false
local debug_hosts, err = red:smembers('debug_hosts')
if not debug_passthrough then
    ngx.log(ngx.ERR, "failed to get redis set 'debug_hosts': ", err)
    return ngx.exit(500)
end
for k,debug_host in pairs(debug_hosts) do
  if debug_host == ngx.var.host then debug_host = true
end


-- block or log the request since it's not passed

local http_user_agent = ngx.var.http_user_agent or ""
ngx.log(ngx.ERR, "Denied UA '", http_user_agent, "' with this IP address: ", incoming_ip_str)
red:lpush("denied_log", os.date("%Y-%m-%dT%H:%M:%SZ").." ||| "..incoming_ip_str.." ||| "..ngx.var.host.." ||| "..ngx.var.request_uri.." ||| "..http_user_agent)
-- red:ltrim("denied_log", 0, 20000) -- not responsibility of buildpack, but companion application

if not (debug_passthrough or os.getenv("IP_WHITELISTER_DEBUG_PASSTHROUGH")) then
  ngx.header["Content-Type"] = "text/html; charset=UTF-8"
  ngx.status = 403
  ngx.say("<html><body>Sorry, your IP address is not in the whitelist.".."<br>Please contact support team (or lkovnatskiy@aligntech.com) or add yourself to the whitelist.</body></html>")
  ngx.exit(403)
end
