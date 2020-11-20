// SPDX-License-Identifier: LGPL-3.0-or-later
/* core/module.hh - Nox plugin / native module interface */
#pragma once
#if !defined(LIBNOX_CORE_MODULE_HH)
#define LIBNOX_CORE_MODULE_HH

#include <string_view>
#include <memory>

using namespace std::literals::string_view_literals;

#define NOX_MODULE_INIT()                          \
	extern "C" [[gnu::visibility("default")]]      \
	std::unique_ptr<NoxModule> nox_module_init() { \
		return std::make_unique<NoxModule>();      \
	}

struct [[gnu::visibility("default")]] NoxModule final {
	std::string_view _name;
	std::string_view _version;
	std::string_view _description;
	std::string_view _author;
	std::string_view _license;
public:
	NoxModule() noexcept;
	~NoxModule() noexcept;

	const std::string_view name() const noexcept { return _name; }
	const std::string_view version() const noexcept { return _version; }
	const std::string_view description() const noexcept { return _description; }
	const std::string_view author() const noexcept { return _author; }
	const std::string_view license() const noexcept { return _license; }
};


#endif /* LIBNOX_CORE_MODULE_HH */
