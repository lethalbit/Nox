#include "dissectors.h"
#include "frameFields.h"

// List of frames in active reconstruction
GSList *segmentList = NULL;
// Table of all reconstructed frames
static reassembly_table frameReassemblyTable;

uint16_t calcFrameLength()
{
	uint16_t length = 0;
	GSList *item = segmentList;
	while (item)
	{
		const frameFragment_t *const fragment = (frameFragment_t *)item->data;
		length += fragment->length;
		item = item->next;
	}
	return length;
}

static int disectN5305AFraming(tvbuff_t *buffer, packet_info *const pinfo,
	proto_tree *const tree, void *const data _U_)
{
	const uint32_t len = tvb_captured_length(buffer);
	if (!len || len != tvb_reported_length(buffer))
		return 0;

	// If the packet is in the reassembly table, we saw it already.. use the cached info
	fragment_head *fragment = fragment_get(&frameReassemblyTable, pinfo, pinfo->num, NULL);
	if (fragment && fragment->reassembled_in != pinfo->num)
	{
		return len;
	}

	// Annotate frame with basic info
	const char *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer Frame");
	proto_item *protocol;
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305AFrame,
		&protocol, "N5305A Protocol Analyzer Frame");
	proto_tree_add_item(subtree, hfPacketDirection, pinfo->srcport == 1029 ? dirHost : dirAnalyzer, 0, -1, ENC_ASCII);

	// If we have an active reconstruction, check if this packet would complete the reassembly
	if (segmentList)
	{
		const frameFragment_t *const frame = (frameFragment_t *)segmentList->data;
		const uint16_t computedLength = calcFrameLength();
		if (computedLength + len < frame->totalLength)
		{
			frameFragment_t *fragment = g_new0(frameFragment_t, 1);
			fragment->length = len;
			fragment->pinfo = pinfo;
			segmentList = g_slist_append(segmentList, fragment);
			fragment_add(&frameReassemblyTable, buffer, 0, pinfo, frame->pinfo->num,
				NULL, computedLength, len, TRUE);
			// If the packet does not complete the reassembly, quick exit plz
			col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
			return len;
		}

		g_slist_free_full(segmentList, g_free);
		segmentList = NULL;
		fragment = fragment_add(&frameReassemblyTable, buffer, 0, pinfo, frame->pinfo->num,
			NULL, computedLength, len, FALSE);
		buffer = process_reassembled_data(buffer, 0, pinfo, "N5305A Frame Data", fragment,
			&n5305aFrameItems, NULL, tree);
	}

	// If we get here, the packet is fresh for dessecting and offering up to the transaction dissector
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags, ENC_BIG_ENDIAN);
	uint32_t packetLength;
	proto_tree_add_item_ret_uint(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN, &packetLength);
	proto_item_append_text(protocol, ", Len: %u", packetLength);
	if (packetLength != len - 4)
	{
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
		frameFragment_t *fragment = g_new0(frameFragment_t, 1);
		fragment->length = len - 4;
		fragment->pinfo = pinfo;
		fragment->totalLength = packetLength;
		segmentList = g_slist_append(segmentList, fragment);
		fragment_add(&frameReassemblyTable, buffer, 0, pinfo, pinfo->num, NULL, 0, len, TRUE);
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
		return len;
	}

	proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
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
	reassembly_table_register(&frameReassemblyTable, &addresses_ports_reassembly_table_functions);

	dirHost = create_tvb_from_string(dirHostStr);
	dirAnalyzer = create_tvb_from_string(dirAnalyzerStr);
}

void registerDissectorN5305AFraming()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(disectN5305AFraming, protoN5305AFraming);
	dissector_add_uint("tcp.port", 1029, handle);
}
