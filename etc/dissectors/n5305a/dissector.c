#include <stdint.h>
#include "dissector.h"

uint16_t extractFlags(tvbuff_t *const buffer, proto_tree *const subtree)
{
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFlags, hfFlags, ENC_BIG_ENDIAN);
	return tvb_get_ntohs(buffer, 0);
}

uint16_t disectAnalyzer(tvbuff_t *const buffer, packet_info *const pinfo, proto_tree *const subtree,
	const uint16_t flags, const char *const dir, const uint16_t packetLength)
{
	uint32_t cookie, status;
	proto_tree_add_item(subtree, hfUnknown1, buffer, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(subtree, hfCookie, buffer, 2, 2, ENC_BIG_ENDIAN, &cookie);
	if (flags & 0x8000U)
	{
		proto_item *statusItem = proto_tree_add_item_ret_uint(subtree, hfStatus, buffer, 4, 4, ENC_BIG_ENDIAN, &status);
		if (!status)
			proto_item_set_text(statusItem, "Status: OK");
	}
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Cookie: 0x%04X, Size: %hu", dir, cookie, packetLength);
	return flags & 0x8000U ? 8 : 4;
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

	const uint32_t remainder = packetLength - (len - 4);
	if (remainder)
	{
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %i", dirStr, len);
		pinfo->fragmented = TRUE;
		pinfo->desegment_len = remainder;
		pinfo->desegment_offset = 0;
		return len;
	}

	tvbuff_t *n5305aBuffer = tvb_new_subset_remaining(buffer, 4);
	uint16_t consumed = 0;
	if (pinfo->srcport == 1029)
		consumed = disectAnalyzer(n5305aBuffer, pinfo, subtree, flags, dirStr, packetLength);
	consumed += 4;

	if (consumed != packetLength)
		proto_tree_add_item(subtree, hfRawData, buffer, consumed, -1, ENC_NA);
	return len;
}