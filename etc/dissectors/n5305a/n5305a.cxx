#include <epan/packet.h>
#include <ws_version.h>
#include "dissectors.h"

extern "C"
{
	extern const char *const plugin_version WS_DLL_PUBLIC_DEF;
	extern const int plugin_want_major WS_DLL_PUBLIC_DEF;
	extern const int plugin_want_minor WS_DLL_PUBLIC_DEF;
	WS_DLL_PUBLIC void plugin_register();
}

const char *const plugin_version = "0.0.2";
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

void plugin_register()
{
	static proto_plugin framePlugin;
	//static proto_plugin transactionPlugin;

	framePlugin.register_protoinfo = registerProtocolN5305AFraming;
	framePlugin.register_handoff = registerDissectorN5305AFraming;
	proto_register_plugin(&framePlugin);

	/*transactionPlugin.register_protoinfo = registerProtocolN5305ATransaction;
	transactionPlugin.register_handoff = registerDissectorN5305ATransaction;
	proto_register_plugin(&transactionPlugin);*/
}
