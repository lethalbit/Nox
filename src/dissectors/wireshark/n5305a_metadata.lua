metadata_proto = Proto("N5305A_Metadata", "N5305A Metadata")

info_key = ProtoField.string("n5305a.metadata.key", "Metadata Key", base.ASCII)
info_value = ProtoField.string("n5305a.metadata.value", "Metadata Value", base.ASCII)
info_raw = ProtoField.bytes("n5305a.metadata.raw", "Metadata Raw", base.SPACE)

metadata_proto.fields = { info_key, info_value, info_raw }

-- Ripped from http://lua-users.org/wiki/SplitJoin because lazy
function string:split(sSeparator, nMax, bRegexp)
   assert(sSeparator ~= '')
   assert(nMax == nil or nMax >= 1)

   local aRecord = {}

   if self:len() > 0 then
      local bPlain = not bRegexp
      nMax = nMax or -1

      local nField, nStart = 1, 1
      local nFirst,nLast = self:find(sSeparator, nStart, bPlain)
      while nFirst and nMax ~= 0 do
         aRecord[nField] = self:sub(nStart, nFirst-1)
         nField = nField+1
         nStart = nLast+1
         nFirst,nLast = self:find(sSeparator, nStart, bPlain)
         nMax = nMax-1
      end
      aRecord[nField] = self:sub(nStart)
   end

   return aRecord
end

function metadata_proto.dissector(buffer, pinfo, tree)
	len = buffer:len()
	if len == 0 then return end

	pinfo.cols.protocol = "N5305A Metadata"

	local subtree = tree:add(metadata_proto, buffer(), "N5305A Metadata")


	local entries = string.split(buffer(0):raw(), "\x00")

	for k, v in next, entries do
		pair = string.split(v, "=")
		if pair[1] ~= nil and  pair[2] ~= nil then
			local pair_tree = subtree:add(metadata_proto, buffer(), v)
			pair_tree:add(info_key, pair[1])
			pair_tree:add(info_value, pair[2])
		end
	end
   pinfo.cols.info = string.format("%i key-value pair(s)", #entries - 1)
	subtree:add(info_raw, buffer(0))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1027, metadata_proto)
