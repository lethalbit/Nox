#ifndef N5305A_DISSESCTOR__H
#define N5305A_DISSESCTOR__H

#include <stdint.h>
#include <epan/packet.h>

static int protoN5305ATransact = -1;
static int32_t ettN5305ATransact = -1;
static int32_t ettTransactFlags = -1;

static int hfFlagsType = -1;
static int flags[16] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static const int *hfFlags[17] =
{
	&flags[0], &flags[1], &flags[2], &flags[3], &flags[4], &flags[5], &flags[6], &flags[7],
	&flags[8], &flags[9], &flags[10], &flags[11], &flags[12], &flags[13], &flags[14], &flags[15],
	NULL
};
static int hfCookie = -1;
static int hfStatus = -1;
static int hfRawData = -1;

gint *ett[] =
{
	&ettN5305ATransact,
	&ettTransactFlags
};

static hf_register_info fields[] =
{
	{
		&hfFlagsType,
		{
			"Flags", "n5305a.protocol_analyzer.flags",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		}
	},
	{
		&flags[0],
		{
			"Flag 0", "n5305a.protocol_analyzer.flags.flag0",
			FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL
		}
	},
	{
		&flags[1],
		{
			"Flag 1", "n5305a.protocol_analyzer.flags.flag1",
			FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL
		}
	},
	{
		&flags[2],
		{
			"Flag 2", "n5305a.protocol_analyzer.flags.flag2",
			FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL
		}
	},
	{
		&flags[3],
		{
			"Flag 3", "n5305a.protocol_analyzer.flags.flag3",
			FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL
		}
	},
	{
		&flags[4],
		{
			"Flag 4", "n5305a.protocol_analyzer.flags.flag4",
			FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL
		}
	},
	{
		&flags[5],
		{
			"Flag 5", "n5305a.protocol_analyzer.flags.flag5",
			FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL
		}
	},
	{
		&flags[6],
		{
			"Flag 6", "n5305a.protocol_analyzer.flags.flag6",
			FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL
		}
	},
	{
		&flags[7],
		{
			"Flag 7", "n5305a.protocol_analyzer.flags.flag7",
			FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL
		}
	},
	{
		&flags[8],
		{
			"Flag 8", "n5305a.protocol_analyzer.flags.flag8",
			FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL
		}
	},
	{
		&flags[9],
		{
			"Flag 9", "n5305a.protocol_analyzer.flags.flag9",
			FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL
		}
	},
	{
		&flags[10],
		{
			"Flag A", "n5305a.protocol_analyzer.flags.flaga",
			FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL
		}
	},
	{
		&flags[11],
		{
			"Flag B", "n5305a.protocol_analyzer.flags.flagb",
			FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL
		}
	},
	{
		&flags[12],
		{
			"Flag C", "n5305a.protocol_analyzer.flags.flagc",
			FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL
		}
	},
	{
		&flags[13],
		{
			"Flag D", "n5305a.protocol_analyzer.flags.flagd",
			FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL
		}
	},
	{
		&flags[14],
		{
			"Flag E", "n5305a.protocol_analyzer.flags.flage",
			FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL
		}
	},
	{
		&flags[15],
		{
			"Transaction Complete", "n5305a.protocol_analyzer.flags.transaction_complete",
			FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL
		}
	},
	{
		&hfCookie,
		{
			"Cookie", "n5305a.protocol_analyzer.cookie",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		}
	},
	{
		&hfStatus,
		{
			"Status", "n5305a.protocol_analyzer.status",
			FT_UINT32, BASE_HEX_DEC, NULL, 0, NULL, HFILL
		}
	},
	{
		&hfRawData,
		{
			"Raw Data", "n5305a.protocol_analyzer.raw_data",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
		}
	}
};

#endif /*N5305A_DISSESCTOR__H*/
