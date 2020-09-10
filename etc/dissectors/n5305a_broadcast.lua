broadcast_proto = Proto("N5305A_Broadcast", "N5305A Broadcast")

boot_seq = ProtoField.uint32("n5305a.boot_seq", "Boot Sequence Number", base.HEX)
serial_number = ProtoField.string("n5305a.serial_number", "Serial Number", base.ASCII)
raw = ProtoField.bytes("n5305a.broadcast_raw", "Broadcast Raw", base.SPACE)

broadcast_proto.fields = { boot_seq, serial_number, raw }

function broadcast_proto.dissector(buffer, pinfo, tree)
	len = buffer:len()
	if len == 0 then return end

	pinfo.cols.protocol = "N5305A Broadcast"

	local subtree = tree:add(broadcast_proto, buffer(), "N5305A Broadcast")

	subtree:add(boot_seq, buffer(2,4))
	subtree:add(serial_number, buffer(6, 13))
	subtree:add(raw, buffer(0))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(7890, broadcast_proto)
