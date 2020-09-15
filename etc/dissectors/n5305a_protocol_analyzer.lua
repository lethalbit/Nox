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
transaction_complete = ProtoField.bool("n5305a.protocol_analyzer.flags.transaction_complete", "Transaction Complete", base.NONE)

pkt_direction = ProtoField.string("n5305a.protocol_analyzer.packet.direction", "Packet Direction", base.ASCII)
pkt_len = ProtoField.uint16("n5305a.protocol_analyzer.packet.length", "Length", base.HEX)

unk1 = ProtoField.uint16("n5305a.protocol_analyzer.unk1", "unk1", base.HEX)
cookie = ProtoField.uint16("n5305a.protocol_analyzer.cookie", "Cookie", base.HEX)
raw_data = ProtoField.bytes("n5305a.protocol_analyzer.raw_data", "Raw Data", base.SPACE)
--message = ProtoField.string("n5305a.protocol_analyzer.message", "Message", base.ASCII)
--message_len = ProtoField.uint32("n5305a.protocol_analyzer.message_len", "Message Length", base.HEX)

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
	transaction_complete,

	pkt_len, pkt_direction, unk1, cookie, raw_data, pa_raw, pa_unkgen }
	-- message, message_len

-- local padded_packets = { 0x0058, 0x0068, 0x005c, 0x004c, 0x0050, 0x0054 }
local frame_remainder = 0

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

function extract_flags(buffer, pinfo, subtree)
	local message_flags = subtree:add(flags, buffer(0, 2))
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
	message_flags:add(transaction_complete, bit32.extract(raw_flag, 15))
	return raw_flag
end

function from(buffer, pkt_len_raw, substree)
	local entries = buffer:len() / 4
	for i = 0, entries - 1, 1 do
	    substree:add(pa_unkgen, buffer((i * 4), 4))
	end
end

function to(buffer, pkt_len_raw, subtree)
	local len = buffer:len()
	padd_offset = 0

	subtree:add(raw_data, buffer(0))
	-- if contains(padded_packets, pkt_len_raw) == true then
	-- 	padd_offset = 16
	-- 	subtree:add(padding, buffer(0, padd_offset))
	-- end

	-- local messages = subtree:add(protocol_analyzer, buffer(), "Messages")
	-- -- while padd_offset <= buffer:len() do
	-- 	print("\n\n\n\n\n")
	-- 	offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 	offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 			offset_inc = add_message(buffer:range(padd_offset):tvb(), messages)
	-- 	padd_offset = offset_inc + padd_offset
	-- 	print(string.format("Padding: %i, Offset: %i, Buffer Len: %i", padd_offset, offset_inc, len))
	-- 	-- if padd_offset>= buffer:len() then break end
	-- -- end

end

function protocol_analyzer.dissector(buffer, pinfo, tree)
	len = buffer:len()
	if len == 0 then return end

	pinfo.cols.protocol = "N5305A Protocol Analyzer"

	local subtree = tree:add(protocol_analyzer, buffer(), "N5305A Protocol Analyzer")

	pkt_dir = ""
	if pinfo.src_port == 1029 then
		pkt_dir = "To Host"
	else
		pkt_dir = "To Analyzer"
	end
	subtree:add(pkt_direction, pkt_dir)

	if pinfo.src_port == 1029 then
	else
		if frame_remainder ~= 0 then
			frame_remainder = frame_remainder - len
			subtree:add(raw_data, buffer(0))
			pinfo.cols.info = string.format("%s - Frame continuation, Size: %i", pkt_dir, len)
			return
		end
	end

	local flags = extract_flags(buffer, pinfo, subtree)

	local pkt_len_raw = buffer(2, 2):uint(2)
	subtree:add(pkt_len, buffer(2, 2))
	subtree:add(unk1, buffer(4, 2))
	subtree:add(cookie, buffer(6, 2))

	if pinfo.src_port == 1029 then
	else
		if bit32.extract(flags, 15) == 0 then
			frame_remainder = pkt_len_raw - (len - 4)
			print("frame remainder is ", frame_remainder)
		else
			frame_remainder = 0
		end
	end

	if pinfo.src_port == 1029 then
		from(buffer:range(8):tvb(), pkt_len_raw, subtree)
	else
		to(buffer:range(4):tvb(), pkt_len_raw, subtree)
	end

	pinfo.cols.info = string.format("%s - Cookie: 0x%04X Size: %i", pkt_dir, buffer(6, 2):uint(2), len)
	subtree:add(pa_raw, buffer(0))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1029, protocol_analyzer)
