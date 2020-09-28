// SPDX-License-Identifier: GPL-3.0-or-later
/* common.hh - Nox N5305A Wireshark Plugin Common definitions */
#pragma once
#if !defined(N5305A_COMMON_HH)
#define N5305A_COMMON_HH

#if WIRESHARK_VERSION_MAJOR >= 3 && WIRESHARK_VERSION_MINOR > 2
#define BITMASK_CONST
#else
#define BITMASK_CONST const
#endif

#include <cstdint>
#include <type_traits>

#include <epan/packet.h>

namespace Nox::Wireshark::Common {
	/* This is a helper method that constructs a tvb from a raw c string */
	/* This is used as a workaround for adding raw strings to the protocol dissection tree */
	inline tvbuff_t *create_tvb_from_string(const char *const str)
	{
		const size_t len = strlen(str) + 1;
		return tvb_new_real_data((const uint8_t *)str, len, len);
	}

	template<typename T>
	inline std::enable_if_t<std::is_integral_v<T>, tvbuff_t*>
	create_tvb_from_numeric(T *number) {
		return tvb_new_real_data(reinterpret_cast<uint8_t *>(number), sizeof(number), sizeof(number));
	}

}

#endif /* N5305A_COMMON_HH */
