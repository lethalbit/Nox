#include <ws_version.h>
#include "dissector.h"

WS_DLL_PUBLIC_DEF const char *const plugin_version = "0.0.1";
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
WS_DLL_PUBLIC void plugin_register(void);

static const char *const dirHostStr = "To Host";
static const char *const dirAnalyzerStr = "To Analyzer";

static int protoN5305A = -1;
gint ettN5305A = -1;

int flagsType = -1;
int packetDirection = -1;
int packetLength = -1;

gint *ett[] = { &ettN5305A };

//true_false_string

static hf_register_info fields[] =
{
	{
		&flagsType,
		{
			"Flags", "n5305a.protocol_analyzer.flags",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		}
	},
	{
		&packetDirection,
		{
			"Packet Direction", "n5305a.protocol_analyzer.packet.direction",
			FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL
		}
	},
	{
		&packetLength,
		{
			"Length", "n5305a.protocol_analyzer.packet.length",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL
		}
	}
};

tvbuff_t *dirHost;
tvbuff_t *dirAnalyzer;

static inline tvbuff_t *create_tvb_from_string(const char *const str)
{
	const size_t len = strlen(str) + 1;
	return tvb_new_real_data((const guint8 *)str, len, len);
}

void registerProtocolN5305A()
{
	protoN5305A = proto_register_protocol(
		"N5305A Protocol Analyzer Traffic",
		"N5305A_ProtocolAnalyzer",
		"n5305a.protocol_analyzer"
	);

	proto_register_field_array(protoN5305A, fields, array_length(fields));
	proto_register_subtree_array(ett, array_length(ett));

	dirHost = create_tvb_from_string(dirHostStr);
	dirAnalyzer = create_tvb_from_string(dirAnalyzerStr);
}

void registerDissectorN5305A()
{
	static dissector_handle_t handle;
	handle = create_dissector_handle(disectN5305A, protoN5305A);
	dissector_add_uint("tcp.port", 1029, handle);
}

void plugin_register(void)
{
	static proto_plugin plugin;

	plugin.register_protoinfo = registerProtocolN5305A;
	plugin.register_handoff = registerDissectorN5305A;
	proto_register_plugin(&plugin);
}
