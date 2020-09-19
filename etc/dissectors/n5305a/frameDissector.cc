#include <cstdio>
#include <optional>
#include <utility>
#include "dissectors.hh"
#include "frameFields.hh"
#include <epan/proto_data.h>

// Frame in active reconstruction
std::optional<frameFragment_t> frameFragment{};
// Table of all reconstructed frames
reassembly_table frameReassemblyTable{};

// Transaction in active reconstruction
std::optional<transactFragment_t> transactFragment{};
// Table of all reconstructed transactions
reassembly_table transactReassemblyTable{};

std::pair<proto_tree *, proto_item *> beginTransactSubtree(tvbuff_t *buffer, proto_tree *const tree)
{
	proto_item *protocol{};
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305ATransact,
		&protocol, "N5305A Protocol Analyzer Transaction");
	return std::make_pair(subtree, protocol);
}

int dissectFrame(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, const uint16_t frameFlags)
{
	const uint32_t len = tvb_captured_length(buffer);

	// If the packet has already been visited, try to use the cached info
	auto *fragment
	{
		[](packet_info *pinfo) noexcept -> fragment_head *
		{
			if (!pinfo->fd->visited)
				return nullptr;
			auto *const cookie{p_get_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 1)};
			if (!cookie)
				return nullptr;
			return fragment_get_reassembled_id(&transactReassemblyTable, pinfo, *static_cast<uint16_t *>(cookie));
		}(pinfo)
	};

	if (fragment)
	{
		const auto cookie{*static_cast<uint16_t *>(p_get_proto_data(wmem_file_scope(),
			pinfo, protoN5305AFraming, 1))};
		if (fragment->reassembled_in != pinfo->num)
		{
			const auto &[subtree, protocol] = beginTransactSubtree(buffer, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented Transaction #%hu]", cookie);

			int32_t buffer_offset{0};
			// Make the first frame reassembled look nice with the header
			if (fragment->next->frame == pinfo->num) {
				/* This should be the first frame in the reassembly? */
				buffer_offset = 4;
				proto_tree_add_item(subtree, hfTransactCookie, buffer, 2, 2, ENC_BIG_ENDIAN);
			}

			proto_tree_add_item(subtree, hfTransactData, buffer, buffer_offset, -1, ENC_NA);
			process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Transaction", fragment,
				&n5305aTransactItems, nullptr, tree);
			return len;
		}
		buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Transaction", fragment,
			&n5305aTransactItems, NULL, tree);
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Transaction #%hu]", cookie);
	}
	// If we have an active reconstruction, check if this packet would complete the reassembly
	else if (transactFragment)
	{
		auto &transact = *transactFragment;
		const auto offset{transact.length};
		const auto cookie{transact.transactCookie};
		// If the packet does not complete the reassembly, quick exit plz
		if (!(frameFlags & 0x8000))
		{
			const auto &[subtree, protocol] = beginTransactSubtree(buffer, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented Transaction #%hu]", cookie);
			transact.length += len;
			fragment_add(&transactReassemblyTable, buffer, 0, pinfo, cookie, nullptr, offset, len, TRUE);
			p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 1, transact.cookiePointer);
			col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A transaction]");
			proto_tree_add_item(subtree, hfTransactData, buffer, 0, -1, ENC_NA);
			return len;
		}
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Transaction #%hu]", cookie);
		fragment = fragment_add_check(&transactReassemblyTable, buffer, 0, pinfo, cookie,
			nullptr, offset, len, FALSE);
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 1, transact.cookiePointer);
		if (fragment)
			buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Transaction", fragment,
				&n5305aTransactItems, nullptr, tree);
		else
			puts("Error: fragment_add_check() return nullptr for transaction reassembly");
		transactFragment.reset();
		if (!fragment || !buffer)
			return len;
	}

	if (!pinfo->fd->visited && !(frameFlags & 0x8000U))
	{
		const auto &[subtree, protocol] = beginTransactSubtree(buffer, tree);
		const uint16_t cookie = tvb_get_ntohs(buffer, 2);
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented Transaction #%hu]", cookie);
		transactFragment_t transact{cookie, pinfo->num};
		transactFragment = transact;
		fragment_add(&transactReassemblyTable, buffer, 0, pinfo, cookie, nullptr, 0, len, TRUE);
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 1, transact.cookiePointer);
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A transaction]");
		proto_tree_add_item(subtree, hfTransactData, buffer, 0, -1, ENC_NA);
		return len;
	}
	return call_dissector(transactionDissector, buffer, pinfo, tree);
}

std::pair<proto_tree *, proto_item *> beginFrameSubtree(tvbuff_t *buffer, packet_info *const pinfo,
	proto_tree *const tree)
{
	proto_item *protocol{};
	// Annotate frame with basic info
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "N5305A Protocol Analyzer Frame");
	auto *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305AFrame,
		&protocol, "N5305A Protocol Analyzer Frame");
	auto *const frame_direction = proto_tree_add_item(subtree, hfPacketDirection, pinfo->srcport == 1029 ? dirHost : dirAnalyzer, 0, -1, ENC_ASCII);
	proto_item_set_generated(frame_direction);
	return std::make_pair(subtree, protocol);
}

int dissectFraming(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
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
			if (!frameNumber)
				return nullptr;
			return fragment_get_reassembled_id(&frameReassemblyTable, pinfo, *static_cast<uint32_t *>(frameNumber));
		}(pinfo)
	};

	auto *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;
	if (fragment)
	{
		const auto frameNumber{*static_cast<uint32_t *>(p_get_proto_data(wmem_file_scope(),
			pinfo, protoN5305AFraming, 0))};
		if (fragment->reassembled_in != pinfo->num)
		{
			const auto &[subtree, protocol] = beginFrameSubtree(buffer, pinfo, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented Frame #%u] %s, Size %u", frameNumber, dirStr, len);

			int32_t buffer_offset{0};
			// Make the first frame reassembled look nice with the header
			if (fragment->next->frame == pinfo->num) {
				buffer_offset = 4;
				proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags.data(), ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN);
			}

			proto_tree_add_item(subtree, hfFrameData, buffer, buffer_offset, -1, ENC_NA);
			process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
				&n5305aFrameItems, NULL, tree);
			return len;
		}
		buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
			&n5305aFrameItems, NULL, tree);
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Frame #%u (%u)]", frameNumber, tvb_captured_length(buffer));
	}
	// If we have an active reconstruction, check if this packet would complete the reassembly
	else if (frameFragment)
	{
		auto &frame = *frameFragment;
		const auto offset{frame.length};
		// If the packet does not complete the reassembly, quick exit plz
		if (offset + len < frame.totalLength)
		{
			const auto &[subtree, protocol] = beginFrameSubtree(buffer, pinfo, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
			frame.length += len;
			fragment_add(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber, nullptr, offset, len, TRUE);
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
	const auto &[subtree, protocol] = beginFrameSubtree(buffer, pinfo, tree);
	// If we get here, the packet is fresh for dessecting and offering up to the transaction dissector
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags.data(), ENC_BIG_ENDIAN);
	uint32_t packetLength;
	proto_tree_add_item_ret_uint(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN, &packetLength);
	proto_item_append_text(protocol, ", Len: %u", packetLength);
	if (!pinfo->fd->visited && packetLength != len - 4)
	{
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
		frameFragment_t frame{packetLength, len, pinfo->num};
		frameFragment = frame;
		fragment_add(&frameReassemblyTable, buffer, 0, pinfo, pinfo->num, nullptr, 0, len, TRUE);
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
		proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
		return len;
	}

	if (!fragment)
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Frame #%u (%u)]", pinfo->num, len);
	proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
	auto *const frameBuffer{tvb_new_subset_remaining(buffer, 4)};
	return dissectFrame(frameBuffer, pinfo, tree, tvb_get_ntohs(buffer, 0));
}

inline tvbuff_t *create_tvb_from_string(const char *const str)
{
	const size_t len = strlen(str) + 1;
	return tvb_new_real_data((const uint8_t *)str, len, len);
}

void registerProtocolN5305AFraming()
{
	protoN5305AFraming = proto_register_protocol(
		"N5305A Protocol Analyzer Framing",
		"N5305A_Framing",
		"n5305a.frame"
	);

	proto_register_field_array(protoN5305AFraming, fields.data(), fields.size());
	proto_register_subtree_array(ett.data(), ett.size());
	reassembly_table_register(&frameReassemblyTable, &addresses_ports_reassembly_table_functions);
	reassembly_table_register(&transactReassemblyTable, &addresses_ports_reassembly_table_functions);

	dirHost = create_tvb_from_string(dirHostStr);
	dirAnalyzer = create_tvb_from_string(dirAnalyzerStr);
}

void registerDissectorN5305AFraming()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(dissectFraming, protoN5305AFraming);
	dissector_add_uint("tcp.port", 1029, handle);
}
