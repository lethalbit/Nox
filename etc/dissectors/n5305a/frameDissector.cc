#include <cstdio>
#include <optional>
#include <utility>
#include "dissectors.h"
#include "frameFields.hh"
#include <epan/proto_data.h>

// List of frames in active reconstruction
std::optional<frameFragment_t> frameFragment{};
// Table of all reconstructed frames
reassembly_table frameReassemblyTable{};

std::pair<proto_tree *, proto_item *>beginN5305AFrameSubtree(tvbuff_t *buffer, packet_info *const pinfo,
	proto_tree *const tree)
{
	proto_item *protocol{};
	// Annotate frame with basic info
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer Frame");
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305AFrame,
		&protocol, "N5305A Protocol Analyzer Frame");
	proto_tree_add_item(subtree, hfPacketDirection, pinfo->srcport == 1029 ? dirHost : dirAnalyzer, 0, -1, ENC_ASCII);
	return std::make_pair(subtree, protocol);
}

static int dissectN5305AFraming(tvbuff_t *buffer, packet_info *const pinfo,
	proto_tree *const tree, void *const data _U_)
{
	uint32_t len = tvb_captured_length(buffer);
	if (!len || len != tvb_reported_length(buffer))
		return 0;

	// If the packet has already been visited, try to use the cached info
	auto *fragment
	{
		[](packet_info *pinfo) noexcept -> fragment_head *
		{
			if (!pinfo->fd->visited)
				return nullptr;
			auto *const frameNumber{p_get_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0)};
			if (frameNumber)
				return fragment_get_reassembled_id(&frameReassemblyTable, pinfo, *static_cast<uint32_t *>(frameNumber));
			return nullptr;
		}(pinfo)
	};

	const char *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;
	if (fragment)
	{
		if (fragment->reassembled_in != pinfo->num)
		{
			const auto &[subtree, protocol] = beginN5305AFrameSubtree(buffer, pinfo, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
			col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
			proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
			return len;
		}
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Frame, Size %hu", dirStr, len);
		buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
			&n5305aFrameItems, NULL, tree);
	}
	// If we have an active reconstruction, check if this packet would complete the reassembly
	else if (frameFragment)
	{
		auto &frame = *frameFragment;
		const auto offset{frame.length};
		// If the packet does not complete the reassembly, quick exit plz
		if (offset + len < frame.totalLength)
		{
			const auto &[subtree, protocol] = beginN5305AFrameSubtree(buffer, pinfo, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
			frame.length += len;
			fragment_add(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber,
				NULL, offset, len, TRUE);
			p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
			col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
			proto_tree_add_item(subtree, hfFrameData, buffer, 0, -1, ENC_NA);
			return len;
		}

		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Frame, Size %hu", dirStr, len);
		fragment = fragment_add_check(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber,
			NULL, offset, len, FALSE);
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
		if (fragment)
			buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
				&n5305aFrameItems, NULL, tree);
		else
			puts("Error: fragment_add_check() return nullptr for frame reassembly");
		frameFragment.reset();
		if (!fragment || !buffer)
			return len;
	}

	len = tvb_captured_length(buffer);
	const auto &[subtree, protocol] = beginN5305AFrameSubtree(buffer, pinfo, tree);
	// If we get here, the packet is fresh for dessecting and offering up to the transaction dissector
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags, ENC_BIG_ENDIAN);
	uint32_t packetLength;
	proto_tree_add_item_ret_uint(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN, &packetLength);
	proto_item_append_text(protocol, ", Len: %u", packetLength);
	if (!pinfo->fd->visited && packetLength != len - 4)
	{
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
		frameFragment_t frame;
		frame.totalLength = packetLength + 4;
		frame.length = len;
		frame.frameNumber = pinfo->num;
		frame.framePointer = g_new0(uint32_t, 1);
		*frame.framePointer = pinfo->num;
		frameFragment = frame;
		fragment_add(&frameReassemblyTable, buffer, 0, pinfo, pinfo->num, nullptr, 0, len, TRUE);
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
		proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
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
	handle = create_dissector_handle(dissectN5305AFraming, protoN5305AFraming);
	dissector_add_uint("tcp.port", 1029, handle);
}
