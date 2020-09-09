metadata_proto = Proto("N5305A", "N5305A Metadata")

info_key = ProtoField.string("n5305a.metadata_key", "Metadata Key", base.ASCII)
info_value = ProtoField.string("n5305a.metadata_value", "Metadata Value", base.ASCII)
info_raw = ProtoField.bytes("n5305a.metadata_raw", "Metadata Raw", base.SPACE)

metadata_proto.fields = { info_key, info_value, info_raw }

function metadata_proto.dissector(buffer, pinfo, tree)
	len = buffer:len()
	if len == 0 then return end

	pinfo.cols.protocol = "N5305A Metadata"

	local subtree = tree:add(metadata_proto, buffer(), "N5305A Metadata Data")

	eq_off = string.find(buffer(0):raw(), "=", 0)
	if eq_off ~= nil then
		subtree:add(info_key, buffer(0, eq_off - 1))
		subtree:add(info_value, buffer(eq_off))
	end
	subtree:add(info_raw, buffer(0))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1027, metadata_proto)
