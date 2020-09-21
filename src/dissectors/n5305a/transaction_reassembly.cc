// SPDX-License-Identifier: GPL-3.0-or-later
/* transaction_reassembly.cc - Nox N5305A Transaction Reassembly Wireshark Plugin */
#include <cstdio>
#include <optional>
#include <utility>

#include <dissectors.hh>
#include <transaction_reassembly.hh>

namespace N5305A::TransactionReassembly {
	std::optional<transaction_fragment_t> transaction_fragment{};
	reassembly_table tx_reassembly_table{};















	void register_protoinfo() {
		// protocol = proto_register_protocol(
		// 	"N5305A Transaction Reassembly",
		// 	"N5305A_TxReasm",
		// 	"n5305a.transaction.reassembly"
		// );

		// proto_register_field_array(protocol, fields.data(), fields.size());
		// proto_register_subtree_array(ett.data(), ett.size());

		// reassembly_table_register(&tx_reassembly_table, &addresses_ports_reassembly_table_functions);
	}

	void register_handoff() {

	}
}
