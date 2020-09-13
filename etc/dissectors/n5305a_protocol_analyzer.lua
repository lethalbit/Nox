protocol_analyzer = Proto("N5305A_ProtocolAnalyzer", "N5305A Protocol Analyzer Traffic")

flags = ProtoField.uint16("n5305a.protocol_analyzer.flags", "Flags", base.HEX)
flag_0 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag0", "Flag 0", base.NONE)
flag_1 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag1", "Flag 1", base.NONE)
flag_2 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag2", "Flag 2", base.NONE)
flag_3 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag3", "Flag 3", base.NONE)
flag_4 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag4", "Flag 4", base.NONE)
flag_5 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag5", "Flag 5", base.NONE)
flag_6 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag6", "Flag 6", base.NONE)
flag_7 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag7", "Flag 7", base.NONE)
flag_8 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag8", "Flag 8", base.NONE)
flag_9 = ProtoField.bool("n5305a.protocol_analyzer.flags.flag9", "Flag 9", base.NONE)
flag_a = ProtoField.bool("n5305a.protocol_analyzer.flags.flaga", "Flag A", base.NONE)
flag_b = ProtoField.bool("n5305a.protocol_analyzer.flags.flagb", "Flag B", base.NONE)
flag_c = ProtoField.bool("n5305a.protocol_analyzer.flags.flagc", "Flag C", base.NONE)
flag_d = ProtoField.bool("n5305a.protocol_analyzer.flags.flagd", "Flag D", base.NONE)
flag_e = ProtoField.bool("n5305a.protocol_analyzer.flags.flage", "Flag E", base.NONE)
flag_f = ProtoField.bool("n5305a.protocol_analyzer.flags.flagf", "Flag F", base.NONE)

pkt_direction = ProtoField.string("n5305a.protocol_analyzer.packet.direction", "Packet Direction", base.ASCII)
pkt_type = ProtoField.uint16("n5305a.protocol_analyzer.packet.type", "Type", base.HEX)

unk1 = ProtoField.uint16("n5305a.protocol_analyzer.unk1", "unk1", base.HEX)
cookie = ProtoField.uint16("n5305a.protocol_analyzer.cookie", "Cookie", base.HEX)
message = ProtoField.string("n5305a.protocol_analyzer.message", "Message", base.ASCII)
message_len = ProtoField.uint32("n5305a.protocol_analyzer.message_len", "Message Length", base.HEX)

pa_raw = ProtoField.bytes("n5305a.protocol_analyzer.raw", "Raw", base.SPACE)

pa_unkgen = ProtoField.bytes("n5305a.protocol_analyzer.unkgen", "Unk", base.SPACE)

protocol_analyzer.fields = {
	flags,
	flag_0,
	flag_1,
	flag_2,
	flag_3,
	flag_4,
	flag_5,
	flag_6,
	flag_7,
	flag_8,
	flag_9,
	flag_a,
	flag_b,
	flag_c,
	flag_d,
	flag_e,
	flag_f,

	pkt_type, pkt_direction, unk1, cookie, message, message_len, pa_raw, pa_unkgen }


local padded_packets = {  0x0058, 0x0068, 0x005c, 0x004c, 0x0050, 0x0054 }

local function contains(t, v)
    for i, value in ipairs(t) do
        if value == v then
            return true
        end
    end
    return false
end

function add_message(buffer, tree)
	if buffer:len() < 4 then return 0 end
	local str_len = buffer(0, 4)
	local len = str_len:uint(4)
	local msg_text = buffer(4, len):string(base.ASCII)
	if len == 0 then return 0 end

	local msg = tree:add(protocol_analyzer, buffer(), msg_text)
	msg:add(message_len, str_len)
	msg:add(message, buffer(4, len))

	return (len + bit32.band((4 - (len % 4)), 3)) + 4
end

function extract_flags(buffer, pinfo, substree)
	local message_flags = substree:add(flags, buffer(0, 2))
	local raw_flag = buffer(0, 2):uint(2)
	message_flags:add(flag_0, bit32.extract(raw_flag, 0))
	message_flags:add(flag_1, bit32.extract(raw_flag, 1))
	message_flags:add(flag_2, bit32.extract(raw_flag, 2))
	message_flags:add(flag_3, bit32.extract(raw_flag, 3))
	message_flags:add(flag_4, bit32.extract(raw_flag, 4))
	message_flags:add(flag_5, bit32.extract(raw_flag, 5))
	message_flags:add(flag_6, bit32.extract(raw_flag, 6))
	message_flags:add(flag_7, bit32.extract(raw_flag, 7))
	message_flags:add(flag_8, bit32.extract(raw_flag, 8))
	message_flags:add(flag_9, bit32.extract(raw_flag, 9))
	message_flags:add(flag_a, bit32.extract(raw_flag, 10))
	message_flags:add(flag_b, bit32.extract(raw_flag, 11))
	message_flags:add(flag_c, bit32.extract(raw_flag, 12))
	message_flags:add(flag_d, bit32.extract(raw_flag, 13))
	message_flags:add(flag_e, bit32.extract(raw_flag, 14))
	message_flags:add(flag_f, bit32.extract(raw_flag, 15))
end

function from(buffer, pkt_type_raw, substree)
	local entries = buffer:len() / 4
	for i = 0, entries - 1, 1 do
	    substree:add(pa_unkgen, buffer((i * 4), 4))
	end
end

function to(buffer, pkt_type_raw, substree)
	local len = buffer:len()
	local messages = substree:add(protocol_analyzer, buffer(), "Messages")
	padd_offset = 0

	if contains(padded_packets, pkt_type_raw) == true then
		padd_offset = 16
	end



	-- while padd_offset <= buffer:len() do
		print("\n\n\n\n\n")
		offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
		offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
				offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
		padd_offset = offset_inc + padd_offset
		print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
		-- if padd_offset>= buffer:len() then break end
	-- end

end

function protocol_analyzer.dissector(buffer, pinfo, tree)
	len = buffer:len()
	if len == 0 then return end

	pinfo.cols.protocol = "N5305A Protocol Analyzer"

	local substree = tree:add(protocol_analyzer, buffer(), "N5305A Protocol Analyzer")

	extract_flags(buffer, pinfo, substree)

	local pkt_type_raw = buffer(2, 2):uint(2)
	substree:add(pkt_type, buffer(2, 2))
	substree:add(unk1, buffer(4, 2))
	substree:add(cookie, buffer(6, 2))


	pkt_dir = ""
	if pinfo.src_port == 1029 then
		pkt_dir = "To Host"
		substree:add(pkt_direction, pkt_dir)
		from(buffer:range(8):tvb(), pkt_type_raw, substree)
	else
		pkt_dir = "To Analyzer"
		substree:add(pkt_direction, pkt_dir)
		to(buffer:range(8):tvb(), pkt_type_raw, substree)
	end


	pinfo.cols.info = string.format("%s - Cookie: 0x%04X Size: %i", pkt_dir, buffer(6, 2):uint(2), len)
	substree:add(pa_raw, buffer(0))

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1029, protocol_analyzer)
