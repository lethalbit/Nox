#include "dissectors.h"
#include "transactionFields.h"

static const char *const dirHostStr = "To Host";
static const char *const dirAnalyzerStr = "To Analyzer";

uint16_t extractFlags(tvbuff_t *const buffer, proto_tree *const subtree)
{
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettTransactFlags, hfFlags, ENC_BIG_ENDIAN);
	return tvb_get_ntohs(buffer, 0);
}

static uint16_t disectAnalyzer(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const subtree, const uint16_t packetLength)
{
	uint32_t status;
	proto_item *const statusItem = proto_tree_add_item_ret_uint(subtree, hfStatus, buffer, 4, 4, ENC_BIG_ENDIAN, &status);
	if (!status)
		proto_item_set_text(statusItem, "Status: OK");
	return 4;
}

static uint16_t disectHost(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const subtree, const uint16_t packetLength)
{
	return 0;
}

static int disectN5305A(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const tree, const char *const dir)
{
	const uint32_t packetLength = tvb_captured_length(buffer);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer Transaction");
	proto_item *protocol;
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305ATransact,
		&protocol, "N5305A Protocol Analyzer Transaction");

	const uint16_t flags = extractFlags(buffer, subtree);
	(void)flags;
	uint32_t cookie;
	proto_tree_add_item_ret_uint(subtree, hfCookie, buffer, 2, 2, ENC_BIG_ENDIAN, &cookie);
	proto_item_append_text(protocol, ", Cookie: 0x%04X", cookie);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Cookie: 0x%04X, Size: %hu", dir, cookie, packetLength);

	tvbuff_t *const n5305aBuffer = tvb_new_subset_remaining(buffer, 4);
	uint16_t consumed = 0;
	if (pinfo->srcport == 1029)
		consumed = disectAnalyzer(n5305aBuffer, pinfo, subtree, packetLength);
	else
		consumed = disectHost(n5305aBuffer, pinfo, subtree, packetLength);

	if (consumed != packetLength)
		proto_tree_add_item(subtree, hfRawData, n5305aBuffer, consumed, -1, ENC_NA);
	return packetLength;
}

static int disectN5305ATransact(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const tree, void *const data)
{
	const uint32_t len = tvb_captured_length(buffer);
	(void)data;

	if (!len || len != tvb_reported_length(buffer))
		return 0;

	const uint16_t packetLength = tvb_get_ntohs(buffer, 2);
	tvbuff_t *const n5305aBuffer = tvb_new_subset_remaining(buffer, 4);

	const char *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;

	// TODO: Build our own reassembly engine as this uses TCP's and that prevents our COL_INFO displaying.
	if (packetLength != len - 4)
	{
		const uint32_t remainder = packetLength - (len - 4);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
		pinfo->fragmented = TRUE;
		pinfo->desegment_len = remainder;
		pinfo->desegment_offset = 0;
		return len;
	}

	return disectN5305A(n5305aBuffer, pinfo, tree, dirStr);
}

void registerProtocolN5305ATransaction()
{
	protoN5305ATransact = proto_register_protocol(
		"N5305A Protocol Analyzer Traffic",
		"N5305A_ProtocolAnalyzer",
		"n5305a.protocol_analyzer"
	);

	proto_register_field_array(protoN5305ATransact, fields, array_length(fields));
	proto_register_subtree_array(ett, array_length(ett));
}

void registerDissectorN5305ATransaction()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(disectN5305ATransact, protoN5305ATransact);
	//dissector_add_uint("tcp.port", 1029, handle);
}
