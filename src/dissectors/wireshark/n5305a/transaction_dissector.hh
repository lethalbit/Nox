// SPDX-License-Identifier: GPL-3.0-or-later
/* transaction_dissector.hh - Nox N5305A Transaction Wireshark Plugin */
#pragma once
#if !defined(N5305A_TRANSACTION_REASSEMBLY_HH)
#define N5305A_TRANSACTION_REASSEMBLY_HH

#include <common.hh>

#include <array>

#include <cstdint>
#include <epan/packet.h>

namespace Nox::Wireshark::N5305A::TransactionDissector {
	static int32_t transaction_protocol{-1};

	void register_protoinfo();
	void register_handoff();

	std::pair<proto_tree *, proto_item *> beginTransactSubtree(tvbuff_t *buffer, proto_tree *const tree);
	uint16_t dissectCookie(tvbuff_t *const buffer, proto_tree *const subtree);
	void dissectRawData(tvbuff_t *const buffer, proto_tree *subtree, const int32_t offset);

	static int32_t ettN5305ATransact = -1;
	static int32_t ettTransactFlags = -1;
	static int32_t ettLPString = -1;
	static int32_t ettRPC = -1;
	static int32_t ettRPCCall = -1;


	static int32_t hfFlagsType = -1;
	static std::array<int32_t, 16> flags{
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		-1, -1, -1, -1
	};

	static std::array<BITMASK_CONST int32_t*, 17> hfFlags{
		&flags[0],  &flags[1],  &flags[2],  &flags[3],
		&flags[4],  &flags[5],  &flags[6],  &flags[7],
		&flags[8],  &flags[9],  &flags[10], &flags[11],
		&flags[12], &flags[13], &flags[14], &flags[15],
		nullptr
	};

	static int32_t hfTransactCookie = -1;
	static int32_t hfTransactStatus = -1;
	static int32_t hfRPCPadding = -1;
	static int32_t hfLPSLength = -1;
	static int32_t hfLPSData = -1;
	static int32_t hfLPSPadding = -1;
	static int32_t hfTransactData = -1;
	static int32_t hfTransactDataLen = -1;

	static std::array<int32_t *, 5> ett{
		&ettN5305ATransact,
		&ettTransactFlags,
		&ettLPString,
		&ettRPC,
		&ettRPCCall
	};

	static std::array<hf_register_info, 26> fields{{
		{
			&hfFlagsType,
			{
				"Flags", "n5305a.protocol_analyzer.flags",
				FT_UINT16, BASE_HEX, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&flags[0],
			{
				"Flag 0", "n5305a.protocol_analyzer.flags.flag0",
				FT_BOOLEAN, 16, nullptr, 0x0001, nullptr, HFILL
			}
		},
		{
			&flags[1],
			{
				"Flag 1", "n5305a.protocol_analyzer.flags.flag1",
				FT_BOOLEAN, 16, nullptr, 0x0002, nullptr, HFILL
			}
		},
		{
			&flags[2],
			{
				"Flag 2", "n5305a.protocol_analyzer.flags.flag2",
				FT_BOOLEAN, 16, nullptr, 0x0004, nullptr, HFILL
			}
		},
		{
			&flags[3],
			{
				"Flag 3", "n5305a.protocol_analyzer.flags.flag3",
				FT_BOOLEAN, 16, nullptr, 0x0008, nullptr, HFILL
			}
		},
		{
			&flags[4],
			{
				"Flag 4", "n5305a.protocol_analyzer.flags.flag4",
				FT_BOOLEAN, 16, nullptr, 0x0010, nullptr, HFILL
			}
		},
		{
			&flags[5],
			{
				"Flag 5", "n5305a.protocol_analyzer.flags.flag5",
				FT_BOOLEAN, 16, nullptr, 0x0020, nullptr, HFILL
			}
		},
		{
			&flags[6],
			{
				"Flag 6", "n5305a.protocol_analyzer.flags.flag6",
				FT_BOOLEAN, 16, nullptr, 0x0040, nullptr, HFILL
			}
		},
		{
			&flags[7],
			{
				"Flag 7", "n5305a.protocol_analyzer.flags.flag7",
				FT_BOOLEAN, 16, nullptr, 0x0080, nullptr, HFILL
			}
		},
		{
			&flags[8],
			{
				"Flag 8", "n5305a.protocol_analyzer.flags.flag8",
				FT_BOOLEAN, 16, nullptr, 0x0100, nullptr, HFILL
			}
		},
		{
			&flags[9],
			{
				"Flag 9", "n5305a.protocol_analyzer.flags.flag9",
				FT_BOOLEAN, 16, nullptr, 0x0200, nullptr, HFILL
			}
		},
		{
			&flags[10],
			{
				"Flag A", "n5305a.protocol_analyzer.flags.flaga",
				FT_BOOLEAN, 16, nullptr, 0x0400, nullptr, HFILL
			}
		},
		{
			&flags[11],
			{
				"Flag B", "n5305a.protocol_analyzer.flags.flagb",
				FT_BOOLEAN, 16, nullptr, 0x0800, nullptr, HFILL
			}
		},
		{
			&flags[12],
			{
				"Flag C", "n5305a.protocol_analyzer.flags.flagc",
				FT_BOOLEAN, 16, nullptr, 0x1000, nullptr, HFILL
			}
		},
		{
			&flags[13],
			{
				"Flag D", "n5305a.protocol_analyzer.flags.flagd",
				FT_BOOLEAN, 16, nullptr, 0x2000, nullptr, HFILL
			}
		},
		{
			&flags[14],
			{
				"Flag E", "n5305a.protocol_analyzer.flags.flage",
				FT_BOOLEAN, 16, nullptr, 0x4000, nullptr, HFILL
			}
		},
		{
			&flags[15],
			{
				"Transaction Complete", "n5305a.protocol_analyzer.flags.transaction_complete",
				FT_BOOLEAN, 16, nullptr, 0x8000, nullptr, HFILL
			}
		},
		{
			&hfTransactCookie,
			{
				"Cookie", "n5305a.protocol_analyzer.cookie",
				FT_UINT16, BASE_HEX, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfTransactStatus,
			{
				"Status", "n5305a.protocol_analyzer.status",
				FT_UINT32, BASE_HEX_DEC, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfRPCPadding,
			{
				"RPC Padding", "n5305a.protocol_analyzer.rpc.padding",
				FT_BYTES, BASE_NONE, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfLPSLength,
			{
				"String Length", "n5305a.protocol_analyzer.lps.string_length",
				FT_UINT32, BASE_DEC_HEX, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfLPSData,
			{
				"String Data", "n5305a.protocol_analyzer.lps.string_data",
				FT_STRING, STR_ASCII, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfLPSPadding,
			{
				"String Padding", "n5305a.protocol_analyzer.lps.string_padding",
				FT_BYTES, BASE_NONE, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfTransactData,
			{
				"Transaction Data", "n5305a.protocol_analyzer.transact_data",
				FT_BYTES, BASE_NONE, nullptr, 0, nullptr, HFILL
			}
		},
		{
			&hfTransactDataLen,
			{
				"Transaction Data Length", "n5305a.protocol_analyzer.transact_len",
				FT_UINT32, BASE_DEC, nullptr, 0, nullptr, HFILL
			}
		}
	}};
}
#endif /* N5305A_TRANSACTION_REASSEMBLY_HH */

