// SPDX-License-Identifier: GPL-3.0-or-later
/* transaction_dissector.cc - Nox N5305A Transaction Wireshark Plugin */
#include <dissectors.hh>
#include <transaction_dissector.hh>

#include <functional>
#include <unordered_map>
#include <string>
#include <string_view>

using namespace std::literals::string_view_literals;

dissector_handle_t transactionDissector;
static const char *const dirHostStr = "To Host";
static const char *const dirAnalyzerStr = "To Analyzer";

using Nox::Wireshark::Common::create_tvb_from_string;
using Nox::Wireshark::Common::create_tvb_from_numeric;

namespace Nox::Wireshark::N5305A::TransactionDissector {

	struct dissctor_args_t final {
		tvbuff_t *const buffer;
		packet_info *const pinfo;
		proto_tree *const subtree;
		size_t len;
		uint32_t offset;
	};

	using rpc_dissector_func_t = std::function<const ssize_t(dissctor_args_t)>;


	const auto rpc_func_handler_generic = [](dissctor_args_t args) -> const ssize_t {
		auto &[buffer, pinfo, subtree, len, offset] = args;
		proto_tree_add_item(subtree, hfTransactData, buffer, offset, -1, ENC_NA);

		auto dlen = len - offset;
		auto dlen_buff = create_tvb_from_numeric(&dlen);
		auto *const data_len = proto_tree_add_item(subtree, hfTransactDataLen, dlen_buff, 0, -1, ENC_NA);
		PROTO_ITEM_SET_GENERATED(data_len);
		return 0;
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_analyzer_control{
		{ "AnalyzerStateChange"sv,                rpc_func_handler_generic },
		{ "MultiframeCorrelationCounterChange"sv, rpc_func_handler_generic },
		{ "setAnalyzerProp"sv,                    rpc_func_handler_generic },
		{ "SWPackageCheckObserver"sv,             rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_analyzer_data{
		{ "CancelAnalysis"sv,       rpc_func_handler_generic },
		{ "CancelRecordResponse"sv, rpc_func_handler_generic },
		{ "FileSaveInfo"sv,         rpc_func_handler_generic },
		{ "GetSourceInfo"sv,        rpc_func_handler_generic },
		{ "Record10BitResponse"sv,  rpc_func_handler_generic },
		{ "RecordData"sv,           rpc_func_handler_generic },
		{ "RecordResponse"sv,       rpc_func_handler_generic },
		{ "RecordVectorResponse"sv, rpc_func_handler_generic },
		{ "SourceInfo"sv,           rpc_func_handler_generic },
		{ "TransactionMap"sv,       rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_segment_manager{
		{ "getNumberOfSteps"sv, rpc_func_handler_generic },
		{ "NumberOfSteps"sv,    rpc_func_handler_generic },
		{ "resetBegin"sv,       rpc_func_handler_generic },
		{ "ResetComplete"sv,    rpc_func_handler_generic },
		{ "resetEnd"sv,         rpc_func_handler_generic },
		{ "resetStep"sv,        rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_pa_sequencer{
		{ "setOccuranceCounters"sv, rpc_func_handler_generic },
		{ "setPatterns"sv,          rpc_func_handler_generic },
		{ "setResource"sv,          rpc_func_handler_generic },
		{ "setSequencerMemory"sv,   rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_heartbeat{
		{ "Heartbeat"sv, rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_spt_control{
		{ "CallGet"sv,         rpc_func_handler_generic },
		{ "CallSet"sv,         rpc_func_handler_generic },
		{ "CallSetObserver"sv, rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_statistics_factory{
		{ "getAvailableStatisticsGroups"sv, rpc_func_handler_generic },
		{ "StatisticsGroups"sv,             rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_statistics_control{
		{ "armStartMeasurements"sv,             rpc_func_handler_generic },
		{ "armStopMeasurements"sv,              rpc_func_handler_generic },
		{ "setContinuousMeasurementInterval"sv, rpc_func_handler_generic },
		{ "setSamplingInterval"sv,              rpc_func_handler_generic },
		{ "StatisticsStateUpdate"sv,            rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_event_manager{
		{ "setActions"sv, rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_device_control{
		{ "armResetTimestamps"sv, rpc_func_handler_generic },
		{ "performSoftReset"sv,   rpc_func_handler_generic },
		{ "shutdown"sv,           rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_event_generator{
		{ "signalEvent"sv, rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_pa_pci_statistics{
		{ "Statistics"sv, rpc_func_handler_generic },
	};

	static const std::unordered_map<std::string_view, rpc_dissector_func_t> rpc_unclassified{
		{ "rm"sv, rpc_func_handler_generic },
	};

	using rpc_table_t = const std::unordered_map<std::string_view, rpc_dissector_func_t>;

	static const std::unordered_map<std::string_view, rpc_table_t&> rpc_dispatch_tables{
		{ "IDevAnalyzerControl1029"sv,   rpc_analyzer_control   },
		{ "IDevAnalyzerData1029"sv,      rpc_analyzer_data      },
		{ "IDevSegmentManager1029"sv,    rpc_segment_manager    },
		{ "IDevPaSequencer1029"sv,       rpc_pa_sequencer       },
		{ "IDevHeartbeat1029"sv,         rpc_heartbeat          },
		{ "IDevSptControl1029"sv,        rpc_spt_control        },
		{ "IDevStatisticsFactory1029"sv, rpc_statistics_factory },
		{ "IDevStatisticsControl1029"sv, rpc_statistics_control },
		{ "IDevEventManager1029"sv,      rpc_event_manager      },
		{ "IDevDeviceControl1029"sv,     rpc_device_control     },
		{ "IDevEventGenerator1029"sv,    rpc_event_generator    },
		{ "PaPciStatistics1029"sv,       rpc_pa_pci_statistics  },

		/* These are for things like the rm message and things */
		{ "unclassified"sv,              rpc_unclassified       },
	};


	rpc_table_t& get_rpc_table(const std::string_view& table_name) {
		const auto& table = rpc_dispatch_tables.find(table_name);
		return (table != rpc_dispatch_tables.end()) ? table->second : rpc_unclassified;
	}

	const ssize_t invoke_dispatch(const rpc_table_t& rpc_table, const std::string_view& method_name, dissctor_args_t& dissector_data) {
		const auto& method_dissector = rpc_table.find(method_name);
		return (method_dissector != rpc_table.end()) ? (method_dissector->second)(dissector_data) : rpc_func_handler_generic(dissector_data);
	}

	const ssize_t dissect_rpc_call(const std::string_view& interface, const std::string_view& method, dissctor_args_t& data) {
		return invoke_dispatch(get_rpc_table(interface), method, data);
	}

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

	inline std::pair<uint32_t, const void *>
		readMessage(tvbuff_t *const buffer, proto_tree *const messages, const uint32_t offset)
	{
		proto_item *item{};
		const auto length{tvb_get_ntohl(buffer, offset)};
		auto *const message{proto_tree_add_subtree(messages, buffer, 0, length + 4, ettMessage, &item, "Message")};
		proto_tree_add_item(message, hfMessageLength, buffer, offset, 4, ENC_BIG_ENDIAN);
		const uint8_t *data{};
		proto_tree_add_item_ret_string(message, hfMessageData, buffer, offset + 4, length,
			ENC_ASCII, wmem_file_scope(), &data);
		const auto realignment{4 + ((4 - (length % 4)) % 4)};
		return {length + realignment, data};
	}

	inline uint32_t readMessages(tvbuff_t *const buffer, proto_tree *const messages, uint32_t offset)
	{
		const auto &[firstLength, message] = readMessage(buffer, messages, offset);
		offset += firstLength;
		if (firstLength == 8 && memcmp(message, "ln", 2) == 0)
		{
			for (uint32_t i{0}; i < 2; ++i)
			{
				const auto &[length, _] = readMessage(buffer, messages, offset);
				offset += length;
			}
		}
		else if (firstLength != 8)
		{
			const auto &[length, _] = readMessage(buffer, messages, offset);
			offset += length;
		}
		return offset;
	}

	/* Dissect messages from the Analyzer */
	/* TODO: The response depends on what the last RPC call was, we need a way to track that to allow for proper response dissection */
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

	/* Initialize a wireshark protocol subtree from the given tvb and populate the generic metadata */
	std::pair<proto_tree *, proto_item *> beginTransactSubtree(tvbuff_t *buffer, proto_tree *const tree)
	{
		proto_item *protocol{};
		proto_tree *const subtree = proto_tree_add_subtree(tree, buffer, 0, -1, ettN5305ATransact,
			&protocol, "N5305A Protocol Analyzer Transaction");
		return {subtree, protocol};
	}

	uint16_t dissectCookie(tvbuff_t *const buffer, proto_tree *const subtree)
	{
		uint32_t cookie;
		proto_tree_add_item_ret_uint(subtree, hfTransactCookie, buffer, 2, 2, ENC_BIG_ENDIAN, &cookie);
		return cookie;
	}

	void dissectRawData(tvbuff_t *const buffer, proto_tree *subtree, const int32_t offset)
	{
		proto_tree_add_item(subtree, hfTransactData, buffer, offset, -1, ENC_NA);
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
		const uint16_t cookie = dissectCookie(buffer, subtree);
		proto_item_append_text(protocol, ", Cookie: 0x%04X", cookie);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s - Cookie: 0x%04X, Size: %hu", dir, cookie, packetLength);

		tvbuff_t *const n5305aBuffer = tvb_new_subset_remaining(buffer, 4);

		const uint16_t consumed = (pinfo->srcport == 1029) ?
			dissectAnalyzer(n5305aBuffer, pinfo, subtree, packetLength, cookie, flags) :
			dissectHost(n5305aBuffer, pinfo, subtree, packetLength, cookie, flags);

		if (consumed + 4U != packetLength)
			dissectRawData(n5305aBuffer, subtree, consumed);
		return packetLength;
	}

	void register_protoinfo()
	{
		transaction_protocol = proto_register_protocol(
			"N5305A Protocol Analyzer Traffic",
			"N5305A_ProtocolAnalyzer",
			"n5305a.protocol_analyzer"
		);

		proto_register_field_array(transaction_protocol, fields.data(), fields.size());
		proto_register_subtree_array(ett.data(), ett.size());
	}

	void register_handoff() {
		transactionDissector = register_dissector("n5305a.protocol_analyzer.transaction", dissectTransact, transaction_protocol);
	}
}
