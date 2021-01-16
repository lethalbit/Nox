// SPDX-License-Identifier: GPL-3.0-or-later
/* transaction_reassembly.hh - Nox N5305A Transaction Reassembly Wireshark Plugin */
#pragma once
#if !defined(N5305A_TRANSACTION_REASSEMBLY_HH)
#define N5305A_TRANSACTION_REASSEMBLY_HH

#include <common.hh>

#include <array>

#include <cstdint>
#include <epan/packet.h>
extern "C"
{
#include <epan/reassemble.h>
}

namespace N5305A::TransactionReassembly {
	static int32_t protocol{-1};

	void register_protoinfo();
	void register_handoff();


	struct transaction_fragment_t final {
	public:
		uint16_t cookie;
		uint32_t length;
		uint32_t frame;
		uint16_t* cookie_ptr;

		transaction_fragment_t(const uint16_t cookie, const uint32_t len, const uint32_t frame) noexcept :
			cookie{cookie}, length{length}, frame{frame}, cookie_ptr{
				[](const uint16_t cookie) {
					auto *const res = g_new0(uint16_t, 1);
					*res = cookie;
					return res;
				}(cookie)
			} { /* NOP */ }
	};
}
#endif /* N5305A_TRANSACTION_REASSEMBLY_HH */
