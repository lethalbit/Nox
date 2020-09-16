#include <ws_version.h>
#include "frameDissector.h"
#include "dissector.h"

WS_DLL_PUBLIC_DEF const char *const plugin_version = "0.0.2";
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
WS_DLL_PUBLIC void plugin_register(void);

static int protoN5305A = -1;
gint ettN5305A = -1;
gint ettFlags = -1;

int hfFlagsType = -1;
static int flags[16] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
const int *hfFlags[17] =
{
	&flags[0], &flags[1], &flags[2], &flags[3], &flags[4], &flags[5], &flags[6], &flags[7],
	&flags[8], &flags[9], &flags[10], &flags[11], &flags[12], &flags[13], &flags[14], &flags[15],
	NULL
};
int hfPacketDirection = -1;
int hfPacketLength = -1;
int hfUnknown1 = -1;
int hfCookie = -1;
int hfStatus = -1;
int hfRawData = -1;

gint *ett[] =
{
	&ettN5305A,
	&ettFlags
};

//true_false_string

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
		&hfPacketDirection,
		{
			"Packet Direction", "n5305a.protocol_analyzer.packet.direction",
			FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL
		}
	},
	{
		&hfPacketLength,
		{
			"Length", "n5305a.protocol_analyzer.packet.length",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL
		}
	},
	{
		&hfUnknown1,
		{
			"Unknown", "n5305a.protocol_analyzer.unk1",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
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

void registerProtocolN5305A()
{
	protoN5305A = proto_register_protocol(
		"N5305A Protocol Analyzer Traffic",
		"N5305A_ProtocolAnalyzer",
		"n5305a.protocol_analyzer"
	);

	proto_register_field_array(protoN5305A, fields, array_length(fields));
	proto_register_subtree_array(ett, array_length(ett));
}

void registerDissectorN5305A()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(disectN5305A, protoN5305A);
	dissector_add_uint("tcp.port", 1029, handle);
}

void plugin_register(void)
{
	static proto_plugin framePlugin;

	framePlugin.register_protoinfo = registerProtocolN5305AFraming;
	framePlugin.register_handoff = registerDissectorN5305AFraming;
	proto_register_plugin(&framePlugin);
}
