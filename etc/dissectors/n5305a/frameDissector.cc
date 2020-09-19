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

/* Initialize a wireshark protocol subtree from the given tvb and populate the generic metadata */
std::pair<proto_tree *, proto_item *> beginTransactSubtree(tvbuff_t *buffer, proto_tree *const tree)
{
	proto_item *protocol{};
	proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305ATransact,
		&protocol, "N5305A Protocol Analyzer Transaction");
	return std::make_pair(subtree, protocol);
}

/* Take the completed frame from frame reassembly and attempt to reassemble the underlying transactional data */
/* This is basically the same as dissectFraming however the packets have been replaced with reassembled frames */
/* And the frames are replaced with transactions */
int dissectFrame(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, const uint16_t frameFlags)
{
	const uint32_t len = tvb_captured_length(buffer);

	// If the packet has already been visited, try to use the cached info
	auto *fragment
	{
		[](packet_info *pinfo) noexcept -> fragment_head *
		{
			if (!PINFO_FD_VISITED(pinfo))
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

	if (!PINFO_FD_VISITED(pinfo) && !(frameFlags & 0x8000U))
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
	/* Chain the transaction dissector onto fully reassembled transactions */
	/* TODO: use find_dissecotr() by name rather than this cheeky handle */
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
	PROTO_ITEM_SET_GENERATED(frame_direction);
	return std::make_pair(subtree, protocol);
}

int dissectFraming(tvbuff_t *buffer, packet_info *const pinfo, proto_tree *const tree, void *const)
{
	/* Skip zero length or mismatched length packets */
	uint32_t len = tvb_captured_length(buffer);
	if (!len || len != tvb_reported_length(buffer))
		return 0;

	/* Return the fragment header for a reassembled frame if this frame has been reassembled, otherwise it's null */
	auto *fragment
	{
		[](packet_info *pinfo) noexcept -> fragment_head *
		{
			if (!PINFO_FD_VISITED(pinfo))
				return nullptr;
			/* If we've been visited, look up the frame number from the pinfo protocol specific data in slot 0 */
			auto *const frameNumber{p_get_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0)};
			if (!frameNumber)
				return nullptr;
			/* This frame has been reassembled get it from the reassembly table */
			return fragment_get_reassembled_id(&frameReassemblyTable, pinfo, *static_cast<uint32_t *>(frameNumber));
		}(pinfo)
	};

	/* Set the direction string based on if we are coming from for going to the source port */
	auto *const dirStr = pinfo->srcport == 1029 ? dirHostStr : dirAnalyzerStr;

	/* If the frame has been reassembled */
	if (fragment)
	{
		/* Extract the frame number */
		const auto frameNumber{*static_cast<uint32_t *>(p_get_proto_data(wmem_file_scope(),
			pinfo, protoN5305AFraming, 0))};

		/* If this packet is not the final reassembled frame */
		if (fragment->reassembled_in != pinfo->num)
		{
			/* Add protocol metadata to tree and info column */
			const auto &[subtree, protocol] = beginFrameSubtree(buffer, pinfo, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented Frame #%u] %s, Size %u", frameNumber, dirStr, len);

			int32_t buffer_offset{0};
			/* If we are the first packet in the frame to be reassembled add the flags and length to it, and set the buffer offset appropriately */
			if (fragment->next->frame == pinfo->num) {
				buffer_offset = 4;
				proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags.data(), ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN);
			}

			/* Add the raw buffer data after the TCP header offset appropriately */
			proto_tree_add_item(subtree, hfFrameData, buffer, buffer_offset, -1, ENC_NA);
			/* Output the frame assembly hyperlink in tree due to this not being the final frame in the assembly sequence */
			process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
				&n5305aFrameItems, NULL, tree);
			/* Let the TCP dissector know we've chewed on all the data */
			return len;
		}

		/* Because we are the final frame in the assembly sequence this call does two things, */
		/* 1: Inserts the appropriate tree reassembly metadata */
		/* 2: Using the given buffer, it finds the fully assembled tvb and returns it */
		buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
			&n5305aFrameItems, NULL, tree);
		/* Set info column text appropriately */
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Frame #%u (%u)]", frameNumber, tvb_captured_length(buffer));
	}
	/* If we are in the middle of reassembly and we have a valid frame */
	/* If we are in the first pass of the reassembly, all frames from the wireshark TCP dissector will be provided in order */
	else if (frameFragment)
	{
		/* Extract the frame reference */
		auto &frame = *frameFragment;
		/* frame.length is the amount of data seen thus far, not the total length of the frame */
		/* thus is the same an offset into the total frame */
		const auto offset{frame.length};
		/* If this packet does not complete the frame reassembly */
		if (offset + len < frame.totalLength)
		{
			/* Initialize and display intermediate frame metadata */
			const auto &[subtree, protocol] = beginFrameSubtree(buffer, pinfo, tree);
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
			/* Accumulate total length */
			frame.length += len;
			/* Append buffer to frame reassembly table */
			/* The TRUE indicates that there are additional packets to follow before reassembly is completed */
			fragment_add(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber, nullptr, offset, len, TRUE);
			/* Add frame pointer into protocol specific data's slot 0 the frame pointer */
			p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
			/* Add raw frame data to tree */
			proto_tree_add_item(subtree, hfFrameData, buffer, 0, -1, ENC_NA);
			/* Signal to the TCP dissector that we've completed processing this packet */
			return len;
		}

		/* Append column info with the total length of the reassembled frame  */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Frame, Size %hu", dirStr, frame.totalLength);
		/* fragment_add doesn't not deal with completed reassembly, therefore we need to use the check version */
		/* The FALSE indicates that the call will add the fully reassembled frame to the reassembled section of the reassembly table */
		fragment = fragment_add_check(&frameReassemblyTable, buffer, 0, pinfo, frame.frameNumber,
			NULL, offset, len, FALSE);
		/* Add frame pointer into protocol specific data's slot 0 the frame pointer */
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
		/* If we have a valid resembled frame */
		if (fragment) {
			/* 1: Inserts the appropriate tree reassembly metadata */
			/* 2: Using the given buffer, it creates the fully assembled tvb and returns it */
			buffer = process_reassembled_data(buffer, 0, pinfo, "Reassembled N5305A Frame", fragment,
				&n5305aFrameItems, NULL, tree);
		} else {
			/* For some reason the fragment check return properly print an error */
			puts("Error: fragment_add_check() return nullptr for frame reassembly");
		}
		/* reset frame reassembly state */
		frameFragment.reset();
		/* If we are in a invalid state return this packet */
		if (!fragment || !buffer) {
			puts("Error: dissectFraming(): fragment or buffer is invalid, dazed and confused");
			return len;
		}
	}

	/* The possible states we can be in for the following block of code are as follows: */
	/* 1: We are in the second pass and have a fully reassembled frame OR */
	/* 2: We are in the second pass and the frame did not require and reassembly OR */
	/* 3: We are in the first pass and we have just completed reassembly OR */
	/* 4: We are in the first pass and have no clue if the packet needs reassembly or not */

	/* If we have done reassembly, we need to update the buffer length */
	len = tvb_captured_length(buffer);
	/* Generate and attach protocol metadata */
	const auto &[subtree, protocol] = beginFrameSubtree(buffer, pinfo, tree);
	/* Added the flags and length from the framing protocol that were in the very first fragment for this total frame */
	proto_tree_add_bitmask(subtree, buffer, 0, hfFlagsType, ettFrameFlags, hfFlags.data(), ENC_BIG_ENDIAN);
	uint32_t packetLength;
	proto_tree_add_item_ret_uint(subtree, hfPacketLength, buffer, 2, 2, ENC_BIG_ENDIAN, &packetLength);
	proto_item_append_text(protocol, ", Len: %u", packetLength);
	/* If this is not the second pass, check the lengths to see if we're in a fragmented packet */
	if (!PINFO_FD_VISITED(pinfo) && packetLength != len - 4)
	{
		/* This is the first packet in a fragmented frame chain */

		/* Add column metadata */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - Fragmented frame, Size %hu", dirStr, len);
		/* Create a new frame fragment context with the frame number for this packet */
		frameFragment_t frame{packetLength, len, pinfo->num};
		frameFragment = frame;
		/* Append buffer to frame reassembly table */
		/* The TRUE indicates that there are additional packets to follow before reassembly is completed */
		fragment_add(&frameReassemblyTable, buffer, 0, pinfo, pinfo->num, nullptr, 0, len, TRUE);
		/* Add frame pointer into protocol specific data's slot 0 the frame pointer */
		p_add_proto_data(wmem_file_scope(), pinfo, protoN5305AFraming, 0, frame.framePointer);
		/* Set column information and add tree metadata */
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[partial N5305A frame]");
		proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
		return len;
	}

	/* If we get here, the packet is fresh for dessecting and offering up to the transaction dissector */
	/* If we are in the first pass and have not begun a reassembled frame or in the second pass and did not get a reassembled frame */
	if (!fragment) {
		/* Set the info column string to decorate the frame uniquely */
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Frame #%u (%u)]", pinfo->num, len);
	}
	/* Add the frame data to the tree */
	proto_tree_add_item(subtree, hfFrameData, buffer, 4, -1, ENC_NA);
	/* Construct a tvb from the reassembled frame data offset by the frame header */
	auto *const frameBuffer{tvb_new_subset_remaining(buffer, 4)};
	/* Dissect the completed frame and return the value */
	return dissectFrame(frameBuffer, pinfo, tree, tvb_get_ntohs(buffer, 0));
}

/* This is a helper method that constructs a tvb from a raw c string */
/* This is used as a workaround for adding raw strings to the protocol dissection tree */
inline tvbuff_t *create_tvb_from_string(const char *const str)
{
	const size_t len = strlen(str) + 1;
	return tvb_new_real_data((const uint8_t *)str, len, len);
}

/* Register the protocol dissector and appropriate metadata handles */
void registerProtocolN5305AFraming()
{
	protoN5305AFraming = proto_register_protocol(
		"N5305A Protocol Analyzer Framing",
		"N5305A_Framing",
		"n5305a.frame"
	);

	proto_register_field_array(protoN5305AFraming, fields.data(), fields.size());
	/* Generate subtree indices */
	proto_register_subtree_array(ett.data(), ett.size());
	/* Register the appropriate reassembly tables for the frames and transactions */
	/* addresses_ports_reassembly_table_functions is the hashing and lookup functions for the reassembly table */
	/* This indicates that we care about the address, port, and data, there exists another which only stores the */
	/* address and data. */
	reassembly_table_register(&frameReassemblyTable, &addresses_ports_reassembly_table_functions);
	reassembly_table_register(&transactReassemblyTable, &addresses_ports_reassembly_table_functions);

	/* create tvbs from the direction strings to use as items in the protocol dissector tree */
	dirHost = create_tvb_from_string(dirHostStr);
	dirAnalyzer = create_tvb_from_string(dirAnalyzerStr);
}

/* Registers the entire dissector */
void registerDissectorN5305AFraming()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(dissectFraming, protoN5305AFraming);
	dissector_add_uint("tcp.port", 1029, handle);
}
