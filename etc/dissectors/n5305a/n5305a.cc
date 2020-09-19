#include <epan/packet.h>
#include "dissectors.hh"

extern "C"
{
	extern const char plugin_version[] WS_DLL_PUBLIC_DEF;
	extern const int plugin_want_major WS_DLL_PUBLIC_DEF;
	extern const int plugin_want_minor WS_DLL_PUBLIC_DEF;
	WS_DLL_PUBLIC void plugin_register();
}

const char plugin_version[] = "0.0.2";
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

/* register the native wireshark plugin */
void plugin_register()
{
	/* define the internal plugins for the frame and transaction dissectors */
	static proto_plugin framePlugin;
	static proto_plugin transactionPlugin;

	/* Set the appropriate entry points for the frame dissectors  */
	framePlugin.register_protoinfo = registerProtocolN5305AFraming;
	framePlugin.register_handoff = registerDissectorN5305AFraming;
	/* Register the plugin with wireshark */
	proto_register_plugin(&framePlugin);

	/* Same as above but for the transaction dissector */
	transactionPlugin.register_protoinfo = registerProtocolN5305ATransaction;
	transactionPlugin.register_handoff = registerDissectorN5305ATransaction;
	proto_register_plugin(&transactionPlugin);
}
