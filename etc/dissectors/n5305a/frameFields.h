#ifndef N5305A_FRAME_FIELDS__H
#define N5305A_FRAME_FIELDS__H

#include <stdint.h>
#include <epan/packet.h>

static const char *const dirHostStr = "To Host";
static tvbuff_t *dirHost = NULL;
static const char *const dirAnalyzerStr = "To Analyzer";
static tvbuff_t *dirAnalyzer = NULL;

static int protoN5305AFraming = -1;
static int32_t ettN5305AFrame = -1;
static int32_t ettFrameFlags = -1;

static int hfFlagsType = -1;
static int flags[16] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static const int *hfFlags[17] =
{
	&flags[0], &flags[1], &flags[2], &flags[3], &flags[4], &flags[5], &flags[6], &flags[7],
	&flags[8], &flags[9], &flags[10], &flags[11], &flags[12], &flags[13], &flags[14], &flags[15],
	NULL
};
static int hfPacketDirection = -1;
static int hfPacketLength = -1;

static int32_t *ett[] =
{
	&ettN5305AFrame,
	&ettFrameFlags
};

static hf_register_info fields[] =
{
	{
		&hfFlagsType,
		{
			"Flags", "n5305a.frame.flags",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		}
	},
	{
		&flags[0],
		{
			"Flag 0", "n5305a.frame.flags.flag0",
			FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL
		}
	},
	{
		&flags[1],
		{
			"Flag 1", "n5305a.frame.flags.flag1",
			FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL
		}
	},
	{
		&flags[2],
		{
			"Flag 2", "n5305a.frame.flags.flag2",
			FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL
		}
	},
	{
		&flags[3],
		{
			"Flag 3", "n5305a.frame.flags.flag3",
			FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL
		}
	},
	{
		&flags[4],
		{
			"Flag 4", "n5305a.frame.flags.flag4",
			FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL
		}
	},
	{
		&flags[5],
		{
			"Flag 5", "n5305a.frame.flags.flag5",
			FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL
		}
	},
	{
		&flags[6],
		{
			"Flag 6", "n5305a.frame.flags.flag6",
			FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL
		}
	},
	{
		&flags[7],
		{
			"Flag 7", "n5305a.frame.flags.flag7",
			FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL
		}
	},
	{
		&flags[8],
		{
			"Flag 8", "n5305a.frame.flags.flag8",
			FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL
		}
	},
	{
		&flags[9],
		{
			"Flag 9", "n5305a.frame.flags.flag9",
			FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL
		}
	},
	{
		&flags[10],
		{
			"Flag A", "n5305a.frame.flags.flaga",
			FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL
		}
	},
	{
		&flags[11],
		{
			"Flag B", "n5305a.frame.flags.flagb",
			FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL
		}
	},
	{
		&flags[12],
		{
			"Flag C", "n5305a.frame.flags.flagc",
			FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL
		}
	},
	{
		&flags[13],
		{
			"Flag D", "n5305a.frame.flags.flagd",
			FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL
		}
	},
	{
		&flags[14],
		{
			"Flag E", "n5305a.frame.flags.flage",
			FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL
		}
	},
	{
		&flags[15],
		{
			"Transaction Complete", "n5305a.frame.flags.transaction_complete",
			FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL
		}
	},
	{
		&hfPacketDirection,
		{
			"Packet Direction", "n5305a.frame.direction",
			FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL
		}
	},
	{
		&hfPacketLength,
		{
			"Length", "n5305a.frame.length",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL
		}
	}
};

static inline tvbuff_t *create_tvb_from_string(const char *const str)
{
	const size_t len = strlen(str) + 1;
	return tvb_new_real_data((const uint8_t *)str, len, len);
}

#endif /*N5305A_FRAME_FIELDS__H*/
