// SPDX-License-Identifier: GPL-3.0-or-later
/* example.cc - Example Nox dissector module */

#include <core/module.hh>


NoxModule::NoxModule() noexcept :
	_name{"Example Module"sv},
	_version{"0.0.1"sv},
	_description{"An example Nox dissector module"sv},
	_author{"Jane Doe"sv},
	_license{"GPL-3.0-or-later"sv}
{ }

NoxModule::~NoxModule() { }


NOX_MODULE_INIT()
