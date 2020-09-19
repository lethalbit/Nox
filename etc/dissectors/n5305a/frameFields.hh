#ifndef N5305A_FRAME_FIELDS__H
#define N5305A_FRAME_FIELDS__H

#include <array>
#include <substrate/utility>

#include <cstdint>
#include <epan/packet.h>
extern "C"
{
#include <epan/reassemble.h>
}

static const char *const dirHostStr = "To Host";
static tvbuff_t *dirHost = nullptr;
static const char *const dirAnalyzerStr = "To Analyzer";
static tvbuff_t *dirAnalyzer = nullptr;

static int32_t protoN5305AFraming = -1;
static int32_t ettN5305AFrame = -1;
static int32_t ettFrameFlags = -1;

static int32_t hfFlagsType = -1;

static std::array<int32_t, 16> flags{
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	-1, -1, -1, -1,
	-1, -1, -1, -1
};

static std::array<int32_t*, 17> hfFlags{
	&flags[0],  &flags[1],  &flags[2],  &flags[3],
	&flags[4],  &flags[5],  &flags[6],  &flags[7],
	&flags[8],  &flags[9],  &flags[10], &flags[11],
	&flags[12], &flags[13], &flags[14], &flags[15],
	nullptr
};

static int32_t hfPacketDirection = -1;
static int32_t hfPacketLength = -1;
static int32_t hfFrameData = -1;

static int32_t ettFrameFragment = -1;
static int32_t ettFrameFragments = -1;
static int32_t hfFrameFragment = -1;
static int32_t hfFrameFragments = -1;
static int32_t hfFrameFragmentOverlap = -1;
static int32_t hfFrameFragmentOverlapConflict = -1;
static int32_t hfFrameMultipleTails = -1;
static int32_t hfFrameTooLongFragment = -1;
static int32_t hfFrameFragmentError = -1;
static int32_t hfFrameFragmentCount = -1;
static int32_t hfFrameReassembledIn = -1;
static int32_t hfFrameReassembledLength = -1;
static int32_t hfFrameReassembledData = -1;

static std::array<int32_t*, 4> ett{
	&ettN5305AFrame,
	&ettFrameFlags,
	&ettFrameFragment,
	&ettFrameFragments
};

static auto fields{substrate::make_array<hf_register_info>({
	{
		&hfFlagsType,
		{
			"Flags", "n5305a.frame.flags",
			FT_UINT16, BASE_HEX, nullptr, 0, "N5305A frame flags", HFILL
		}
	},
	{
		&flags[0],
		{
			"Flag 0", "n5305a.frame.flags.flag0",
			FT_BOOLEAN, 16, nullptr, 0x0001, "N5305A frame flag 0", HFILL
		}
	},
	{
		&flags[1],
		{
			"Flag 1", "n5305a.frame.flags.flag1",
			FT_BOOLEAN, 16, nullptr, 0x0002, "N5305A frame flag 1", HFILL
		}
	},
	{
		&flags[2],
		{
			"Flag 2", "n5305a.frame.flags.flag2",
			FT_BOOLEAN, 16, nullptr, 0x0004, "N5305A frame flag 2", HFILL
		}
	},
	{
		&flags[3],
		{
			"Flag 3", "n5305a.frame.flags.flag3",
			FT_BOOLEAN, 16, nullptr, 0x0008, "N5305A frame flag 3", HFILL
		}
	},
	{
		&flags[4],
		{
			"Flag 4", "n5305a.frame.flags.flag4",
			FT_BOOLEAN, 16, nullptr, 0x0010, "N5305A frame flag 4", HFILL
		}
	},
	{
		&flags[5],
		{
			"Flag 5", "n5305a.frame.flags.flag5",
			FT_BOOLEAN, 16, nullptr, 0x0020, "N5305A frame flag 5", HFILL
		}
	},
	{
		&flags[6],
		{
			"Flag 6", "n5305a.frame.flags.flag6",
			FT_BOOLEAN, 16, nullptr, 0x0040, "N5305A frame flag 6", HFILL
		}
	},
	{
		&flags[7],
		{
			"Flag 7", "n5305a.frame.flags.flag7",
			FT_BOOLEAN, 16, nullptr, 0x0080, "N5305A frame flag 7", HFILL
		}
	},
	{
		&flags[8],
		{
			"Flag 8", "n5305a.frame.flags.flag8",
			FT_BOOLEAN, 16, nullptr, 0x0100, "N5305A frame flag 8", HFILL
		}
	},
	{
		&flags[9],
		{
			"Flag 9", "n5305a.frame.flags.flag9",
			FT_BOOLEAN, 16, nullptr, 0x0200, "N5305A frame flag 9", HFILL
		}
	},
	{
		&flags[10],
		{
			"Flag A", "n5305a.frame.flags.flaga",
			FT_BOOLEAN, 16, nullptr, 0x0400, "N5305A frame flag A", HFILL
		}
	},
	{
		&flags[11],
		{
			"Flag B", "n5305a.frame.flags.flagb",
			FT_BOOLEAN, 16, nullptr, 0x0800, "N5305A frame flag B", HFILL
		}
	},
	{
		&flags[12],
		{
			"Flag C", "n5305a.frame.flags.flagc",
			FT_BOOLEAN, 16, nullptr, 0x1000, "N5305A frame flag C", HFILL
		}
	},
	{
		&flags[13],
		{
			"Flag D", "n5305a.frame.flags.flagd",
			FT_BOOLEAN, 16, nullptr, 0x2000, "N5305A frame flag D", HFILL
		}
	},
	{
		&flags[14],
		{
			"Flag E", "n5305a.frame.flags.flage",
			FT_BOOLEAN, 16, nullptr, 0x4000, "N5305A frame flag E", HFILL
		}
	},
	{
		&flags[15],
		{
			"Transaction Complete", "n5305a.frame.flags.transaction_complete",
			FT_BOOLEAN, 16, nullptr, 0x8000, "Transaction completed flag", HFILL
		}
	},
	{
		&hfPacketDirection,
		{
			"Packet Direction", "n5305a.frame.direction",
			FT_STRING, STR_ASCII, nullptr, 0, "N5305A frame direction", HFILL
		}
	},
	{
		&hfPacketLength,
		{
			"Length", "n5305a.frame.length",
			FT_UINT16, BASE_HEX_DEC, nullptr, 0, "N5305A frame length", HFILL
		}
	},
	{
		&hfFrameData,
		{
			"Frame Data", "n5305a.frame.frame_data",
			FT_BYTES, BASE_NONE, nullptr, 0, "N5305A frame data", HFILL
		}
	},

	{
		&hfFrameFragment,
		{
			"N5305A Frame Fragment", "n5305a.frame.frag",
			FT_FRAMENUM, BASE_NONE, nullptr, 0, "N5305A frame fragment", HFILL
		}
	},
	{
		&hfFrameFragments,
		{
			"Reassembled N5305A Frame Fragments", "n5305a.frame.fragments",
			FT_NONE, BASE_NONE, nullptr, 0, "N5305A frame fragments", HFILL
		}
	},
	{
		&hfFrameFragmentOverlap,
		{
			"Segment overlap", "n5305a.frame.frag.overlap",
			FT_BOOLEAN, BASE_NONE, nullptr, 0, "N5305A frame fragments overlap", HFILL
		}
	},
	{
		&hfFrameFragmentOverlapConflict,
		{
			"Conflicting data in segment overlap", "n5305a.frame.frag.overlap.conflict",
			FT_BOOLEAN, BASE_NONE, nullptr, 0, "N5305A frame fragment overlap conflict", HFILL
		}
	},
	{
		&hfFrameMultipleTails,
		{
			"Multiple tail segments found", "n5305a.frame.frag.multiple_tails",
			FT_BOOLEAN, BASE_NONE, nullptr, 0, "N5305A frame fragment multiple tails", HFILL
		}
	},
	{
		&hfFrameTooLongFragment,
		{
			"Segment too long", "n5305a.frame.frag.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, nullptr, 0, "N5305A frame fragment is too long", HFILL
		}
	},
	{
		&hfFrameFragmentError,
		{
			"Reassembling error", "n5305a.frame.frag.error",
			FT_FRAMENUM, BASE_NONE, nullptr, 0, "N5305A Frame fragment error", HFILL
		}
	},
	{
		&hfFrameFragmentCount,
		{
			"N5305A Frame Fragment Count", "n5305a.frame.fragment_count",
			FT_UINT32, BASE_DEC, nullptr, 0, "N5305A frame fragment count", HFILL
		}
	},

	{
		&hfFrameReassembledIn,
		{
			"Reassembled frame in segment", "n5305a.frame.reassembled_in",
			FT_FRAMENUM, BASE_NONE, nullptr, 0, "N5305A frame reassembled in", HFILL
		}
	},
	{
		&hfFrameReassembledLength,
		{
			"Reassembled frame length", "n5305a.frame.reassembled.length",
			FT_UINT32, BASE_HEX_DEC, nullptr, 0, "N5305A reassembled frame length", HFILL
		}
	},
	{
		&hfFrameReassembledData,
		{
			"Reassembled frame data", "n5305a.frame.reassembled.data",
			FT_BYTES, BASE_NONE, nullptr, 0, "N5305A reassembled frame data", HFILL
		}
	}
})};

static const fragment_items n5305aFrameItems =
{
	&ettFrameFragment,
	&ettFrameFragments,

	&hfFrameFragments,
	&hfFrameFragment,
	&hfFrameFragmentOverlap,
	&hfFrameFragmentOverlapConflict,
	&hfFrameMultipleTails,
	&hfFrameTooLongFragment,
	&hfFrameFragmentError,
	&hfFrameFragmentCount,

	&hfFrameReassembledIn,
	&hfFrameReassembledLength,
	&hfFrameReassembledData,

	"Frame fragments"
};

static inline tvbuff_t *create_tvb_from_string(const char *const str)
{
	const size_t len = strlen(str) + 1;
	return tvb_new_real_data((const uint8_t *)str, len, len);
}

struct frameFragment_t
{
	uint32_t totalLength;
	uint32_t length;
	uint32_t frameNumber;
	uint32_t *framePointer;

	frameFragment_t(const uint32_t packetLength, const uint32_t len, const uint32_t frameNum) noexcept :
		totalLength{packetLength + 4U}, length{len}, frameNumber{frameNum},
		framePointer
		{
			[](const uint32_t frameNum)
			{
				auto *const result = g_new0(uint32_t, 1);
				*result = frameNum;
				return result;
			}(frameNum)
		} { }
};

struct transactFragment_t
{
	uint16_t transactCookie;
	uint16_t *cookiePointer;

	transactFragment_t(const uint16_t cookie) noexcept :
		transactCookie{cookie}, cookiePointer
		{
			[](const uint16_t transactCookie)
			{
				auto *const result = g_new0(uint16_t, 1);
				*result = transactCookie;
				return result;
			}(transactCookie)
		} { }
};

#endif /*N5305A_FRAME_FIELDS__H*/
