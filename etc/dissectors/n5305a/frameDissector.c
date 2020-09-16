#include "dissectors.h"
#include "frameFields.h"

static int disectN5305AFraming(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const tree, void *const data)
{
	const uint32_t len = tvb_captured_length(buffer);
	(void)data;

	if (!len || len != tvb_reported_length(buffer))
		return 0;

	const char *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer Frame");
	proto_item *protocol;
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305AFrame,
		&protocol, "N5305A Protocol Analyzer Frame");
	proto_tree_add_item(subtree, hfPacketDirection, pinfo->srcport == 1029 ? dirHost : dirAnalyzer, 0, -1, ENC_ASCII);

	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags, ENC_BIG_ENDIAN);
	uint32_t packetLength;
	proto_tree_add_item_ret_uint(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN, &packetLength);
	proto_item_append_text(protocol, ", Len: %u", packetLength);
	if (packetLength != len - 4)
	{
		const uint32_t remainder = packetLength - (len - 4);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
		// TODO: properly handle the frame rebuild.
	}

	return len;
}

void registerProtocolN5305AFraming()
{
	protoN5305AFraming = proto_register_protocol(
		"N5305A Protocol Analyzer Framing",
		"N5305A_Framing",
		"n5305a.frame"
	);

	proto_register_field_array(protoN5305AFraming, fields, array_length(fields));
	proto_register_subtree_array(ett, array_length(ett));

	dirHost = create_tvb_from_string(dirHostStr);
	dirAnalyzer = create_tvb_from_string(dirAnalyzerStr);
}

void registerDissectorN5305AFraming()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(disectN5305AFraming, protoN5305AFraming);
	dissector_add_uint("tcp.port", 1029, handle);
}
