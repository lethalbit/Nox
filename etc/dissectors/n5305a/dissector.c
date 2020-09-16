#include <stdint.h>
#include "dissector.h"

uint16_t extractFlags(tvbuff_t *const buffer, proto_tree *const subtree)
{
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFlags, hfFlags, ENC_BIG_ENDIAN);
	return tvb_get_ntohs(buffer, 0);
}

int disectN5305A(tvbuff_t *const buffer, packet_info *const pinfo, proto_tree *const tree, void *const data)
{
	uint32_t packetLength;
	const uint32_t len = tvb_captured_length(buffer);
	(void)data;

	if (!len || len != tvb_reported_length(buffer))
		return 0;

	const char *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer");
	proto_tree *subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305A, NULL, "N5305A Protocol Analyzer");
	proto_tree_add_item(subtree, hfPacketDirection, pinfo->srcport == 1029 ? dirHost : dirAnalyzer, 0, -1, ENC_ASCII);

	const uint16_t flags = extractFlags(buffer, subtree);
	proto_tree_add_item_ret_uint(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN, &packetLength);

	proto_tree_add_item(subtree, hfRawData, buffer, 4, -1, ENC_NA);

	return len;
}
