// SPDX-License-Identifier: GPL-3.0-or-later
/* n5305a.cc - Nox N5305A  Wireshark Plugin */
#include <epan/packet.h>

#include <dissectors.hh>

#include <transaction_dissector.hh>
#include <frame_reassembly.hh>


extern "C"
{
	WS_DLL_PUBLIC_DEF extern const char plugin_version[];
	WS_DLL_PUBLIC_DEF extern const int plugin_want_major;
	WS_DLL_PUBLIC_DEF extern const int plugin_want_minor;
	WS_DLL_PUBLIC void plugin_register();
}

const char plugin_version[] = "0.0.2";
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

namespace n5305a_fr = Nox::Wireshark::N5305A::FrameReassembly;
namespace n5305a_tx = Nox::Wireshark::N5305A::TransactionDissector;

/* register the native wireshark plugin */
void plugin_register()
{
	/* define the internal plugins for the frame and transaction dissectors */
	static proto_plugin frame_reassembly;
	static proto_plugin transaction_dissector;

	/* Same as above but for the transaction dissector */
	transaction_dissector.register_protoinfo = n5305a_tx::register_protoinfo;
	transaction_dissector.register_handoff = n5305a_tx::register_handoff;
	proto_register_plugin(&transaction_dissector);

	/* Set the appropriate entry points for the frame dissectors  */
	frame_reassembly.register_protoinfo = n5305a_fr::register_protoinfo;
	frame_reassembly.register_handoff = n5305a_fr::register_handoff;
	/* Register the plugin with wireshark */
	proto_register_plugin(&frame_reassembly);

}
