// SPDX-License-Identifier: LGPL-3.0-or-later
/* internal/defs.hh - Internal definitions for libnox for symbol export control */
#pragma once
#if !defined(LIBNOX_INTERNAL_DEFS_HH)
#define LIBNOX_INTERNAL_DEFS_HH

#if defined(_MSC_VER) && !defined(_WINDOWS)
#define _WINDOWS 1
#endif

#if !defined(__has_cpp_attribute)
#	define __has_cpp_attribute(x) 0
#endif

#if __has_cpp_attribute(maybe_unused) || __cplusplus >= 201703L
#	define LIBNOX_NOWARN_UNUSED(x) [[maybe_unused]] x
#elif defined(__GNUC__)
#	define LIBNOX_NOWARN_UNUSED(x) x __attribute__((unused))
#else
#	define LIBNOX_NOWARN_UNUSED(x) x
#endif

#if __has_cpp_attribute(nodiscard) || __cplusplus >= 201402L
#	define LIBNOX_NO_DISCARD(...) [[nodiscard]] __VA_ARGS__
#elif defined(__GNUC__)
#	define LIBNOX_NO_DISCARD(...) __VA_ARGS__ __attribute__((warn_unused_result))
#else
#	define LIBNOX_NO_DISCARD(...) __VA_ARGS__
#endif

#if __cplusplus >= 201103L
#	define ALIGN(X) alignas(x)
#elif defined(__GNUC__)
#	define LIBNOX_ALIGN(X) __attribute__ ((aligned (X)))
#else
#	define LIBNOX_ALIGN(X)
#endif

#ifdef _WINDOWS
#	ifdef LIBNOX_BUILD_INTERNAL
#		define LIBNOX_CLS_API __declspec(dllexport)
#	else
#		define LIBNOX_CLS_API __declspec(dllimport)
#	endif
#	define LIBNOX_API extern LIBNOX_CLS_API
#	define LIBNOX_CLS_MAYBE_API
#else
#	define LIBNOX_CLS_API __attribute__ ((visibility("default")))
#	define LIBNOX_CLS_MAYBE_API LIBNOX_CLS_API
#	define LIBNOX_API extern LIBNOX_CLS_API
#endif

#if __cplusplus >= 201402L
#	define LIBNOX_DEPRECATE_R(reson) [[deprecated(reson)]]
#	define LIBNOX_DEPRECATE() [[deprecated]]
#else
#	ifdef _WINDOWS
#		define LIBNOX_DEPRECATE_R(reson) __declspec(deprecated(reson))
#		define LIBNOX_DEPRECATE() __declspec(deprecated)
#	else
#		define LIBNOX_DEPRECATE_R(reson) [[gnu::deprecated(reason)]]
#		define LIBNOX_DEPRECATE() __attribute__ ((deprecated))
#	endif
#endif

#endif /* LIBNOX_INTERNAL_DEFS_HH */
