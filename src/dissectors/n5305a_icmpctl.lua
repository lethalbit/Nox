
-- IP Scroll ICMP Message
local icmp_ctl_proto = Proto("N5305A_ICMP_Ctl", "N5305A ICMP Control")

local icmp_type = Field.new("icmp.type")
local icmp_seq  = Field.new("icmp.seq")
local ip_ttl    = Field.new("ip.ttl")

local ctl_signal = ProtoField.string("n5305a.icmp_ctl", "N5305A ICMP Control Signal", base.ASCII)

icmp_ctl_proto.fields = { ctl_signal }

function icmp_ctl_proto.dissector(buffer, pinfo, tree)
	local itype = {icmp_type()}
	local iseq  = {icmp_seq()}
	local ittl  = {ip_ttl()}

	if itype ~= nil and itype[1] ~= nil then
		if itype[1].value == 8 then
			local subtree = tree:add(icmp_ctl_proto, "N5305A ICMP Control")
			if iseq[1].value == 0 then
				if ittl[1].value == 1 then
					subtree:add(ctl_signal, "Display Module IP and Subnet")
					pinfo.cols.protocol = "N5305A ICMP Control"
					pinfo.cols.info = "Display Module IP and Subnet"
					return
				end
			end
		end
	end
end


register_postdissector(icmp_ctl_proto)
