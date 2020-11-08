// SPDX-License-Identifier: LGPL-3.0-or-later
/* internal/fs.hh - C++ Filesystem library wrapper */
#pragma once
#if !defined(LIBNOX_INTERNAL_FS_HH)
#define LIBNOX_INTERNAL_FS_HH

#include <config.hh>

#if defined(LIBNOX_CPPFS_EXPERIMENTAL)
	#include <experimental/filesystem>
namespace libnox::internal {
	namespace fs = std::experimental::filesystem;
}
#else
	#include <filesystem>
namespace libnox::internal {
	namespace fs = std::filesystem;
}
#endif

#endif /* LIBNOX_INTERNAL_FS_HH */
