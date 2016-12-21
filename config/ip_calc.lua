local _M = {}

function _M.ipv4_to_i(self, ip_address_str)
  local octet4, octet3, octet2, octet1 = string.match(ip_address_str, '^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$');
  if octet4 and octet3 and octet2 and octet1 then
    return (2^24*octet4 + 2^16*octet3 + 2^8*octet2 + octet1);
  end
end

function _M.ipv4_to_network_netmask(self, ip_address_str)
  local octet4, octet3, octet2, octet1, netmask = string.match(ip_address_str, '^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)/(%d%d?)$');
  if octet4 and octet3 and octet2 and octet1 and netmask then
    return (2^24*octet4 + 2^16*octet3 + 2^8*octet2 + octet1), tonumber(netmask);
  end
end

function _M.ipv4_network(self, ip_address, netmask)
  return math.floor(ip_address / 2^(32-netmask));
end

function _M.ipv4_in_network(self, ip_address, network, netmask)
  return _M.ipv4_network(self, ip_address, netmask) == _M.ipv4_network(self, network, netmask);
end

return _M
