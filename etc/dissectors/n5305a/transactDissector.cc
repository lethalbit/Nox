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


inline uint32_t readEmptyMessages(tvbuff_t *const buffer, proto_tree *const messages)
{
	const uint32_t bufferLength{tvb_captured_length(buffer)};
	uint32_t offset{0};
	while (offset < bufferLength)
	{
		const uint32_t length = tvb_get_ntohl(buffer, offset);
		if (length)
			break;
		proto_tree_add_item(messages, hfEmptyMessage, buffer, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	return offset;
}

inline std::pair<uint32_t, const char *>
	readMessage(tvbuff_t *const buffer, proto_tree *const messages, const uint32_t offset)
{
	proto_item *item{};
	const auto length{tvb_get_ntohl(buffer, offset)};
	auto *const message{proto_tree_add_subtree(messages, buffer, 0, length + 4, ettMessage, &item, "Message")};
	proto_tree_add_item(message, hfMessageLength, buffer, offset, 4, ENC_BIG_ENDIAN);
	const char *data{};
	proto_tree_add_item_ret_string(message, hfMessageData, buffer, offset + 4, length, ENC_ASCII,
		wmem_file_scope(), reinterpret_cast<const uint8_t **>(&data));
	const auto realignment{4 + ((4 - (length % 4)) % 4)};
	return {length + realignment, data};
}

inline uint32_t readMessages(tvbuff_t *const buffer, proto_tree *const messages, uint32_t offset)
{
	const auto &[length, message] = readMessage(buffer, messages, offset);
	offset += length;
	if (length == 8 && memcmp(message, "ln", 2) == 0)
	{
		for (uint32_t i{0}; i < 2; ++i)
		{
			const auto &[length, _] = readMessage(buffer, messages, offset);
			offset += length;
		}
	}
	else if (length != 8)
	{
		const auto &[length, _] = readMessage(buffer, messages, offset);
		offset += length;
	}
	return offset;
}

static uint16_t dissectAnalyzer(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const subtree, const uint16_t packetLength, const uint16_t cookie, const uint16_t flags)
{
	if (cookie == 1 && !(flags & 0x8000U)) {
		const auto &[length, message] = readMessage(buffer, subtree, 0);
		return length;
	} else {
		uint32_t status{};
		proto_item *const statusItem = proto_tree_add_item_ret_uint(subtree, hfTransactStatus,
			buffer, 0, 4, ENC_BIG_ENDIAN, &status);
		if (!status)
			proto_item_set_text(statusItem, "Status: OK");
		return 4;
	}
}

static uint16_t dissectHost(tvbuff_t *const buffer, packet_info *const pinfo,
	proto_tree *const subtree, const uint16_t packetLength, const uint16_t cookie, const uint16_t flags)
{
	if (cookie || flags) {
		proto_item *item{};
		auto *const messages{proto_tree_add_subtree(subtree, buffer, 0, -1, ettMessages, &item, "Messages")};
		auto offset{readEmptyMessages(buffer, messages)};
		offset = readMessages(buffer, messages, offset);
		proto_item_set_len(item, offset);
		return offset;
	}
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
	uint32_t cookie;
	proto_tree_add_item_ret_uint(subtree, hfTransactCookie, buffer, 2, 2, ENC_BIG_ENDIAN, &cookie);
	proto_item_append_text(protocol, ", Cookie: 0x%04X", cookie);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s - Cookie: 0x%04X, Size: %hu", dir, cookie, packetLength);

	tvbuff_t *const n5305aBuffer = tvb_new_subset_remaining(buffer, 4);

	const uint16_t consumed = (pinfo->srcport == 1029) ?
		dissectAnalyzer(n5305aBuffer, pinfo, subtree, packetLength, cookie, flags) :
		dissectHost(n5305aBuffer, pinfo, subtree, packetLength, cookie, flags);

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
