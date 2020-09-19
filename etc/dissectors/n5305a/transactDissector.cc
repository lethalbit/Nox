#include "dissectors.hh"
#include "transactionFields.hh"

dissector_handle_t transactionDissector;
static const char *const dirHostStr = "To Host";
static const char *const dirAnalyzerStr = "To Analyzer";

uint16_t extractFlags(tvbuff_t *const buffer, proto_tree *const subtree)
{
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettTransactFlags, hfFlags.data(), ENC_BIG_ENDIAN);
	return tvb_get_ntohs(buffer, 0);
}

static uint16_t dissectAnalyzer(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const subtree, const uint16_t packetLength)
{
	uint32_t status;
	proto_item *const statusItem = proto_tree_add_item_ret_uint(subtree, hfTransactStatus,
		buffer, 0, 4, ENC_BIG_ENDIAN, &status);
	if (!status)
		proto_item_set_text(statusItem, "Status: OK");
	return 4;
}

static uint16_t dissectHost(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const subtree, const uint16_t packetLength)
{
	return 0;
}

static int dissectTransact(tvbuff_t *const buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
{
	const uint32_t packetLength = tvb_captured_length(buffer);
	const char *const dir = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer Transaction");
	proto_item *protocol;
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305ATransact,
		&protocol, "N5305A Protocol Analyzer Transaction");

	const uint16_t flags = extractFlags(buffer, subtree);
	(void)flags;
	uint32_t cookie;
	proto_tree_add_item_ret_uint(subtree, hfTransactCookie, buffer, 2, 2, ENC_BIG_ENDIAN, &cookie);
	proto_item_append_text(protocol, ", Cookie: 0x%04X", cookie);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s - Cookie: 0x%04X, Size: %hu", dir, cookie, packetLength);

	tvbuff_t *const n5305aBuffer = tvb_new_subset_remaining(buffer, 4);
	uint16_t consumed = 0;
	if (pinfo->srcport == 1029)
		consumed = dissectAnalyzer(n5305aBuffer, pinfo, subtree, packetLength);
	else
		consumed = dissectHost(n5305aBuffer, pinfo, subtree, packetLength);

	if (consumed + 4U != packetLength)
		proto_tree_add_item(subtree, hfTransactData, n5305aBuffer, consumed, -1, ENC_NA);
	return packetLength;
}

void registerProtocolN5305ATransaction()
{
	protoN5305ATransact = proto_register_protocol(
		"N5305A Protocol Analyzer Traffic",
		"N5305A_ProtocolAnalyzer",
		"n5305a.protocol_analyzer"
	);

	proto_register_field_array(protoN5305ATransact, fields.data(), fields.size());
	proto_register_subtree_array(ett.data(), ett.size());
}

void registerDissectorN5305ATransaction()
	{ transactionDissector = create_dissector_handle(dissectTransact, protoN5305ATransact); }
