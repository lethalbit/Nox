// SPDX-License-Identifier: GPL-3.0-or-later
/* nox-gui.cc - Nox GUI main entrypoint */

#include <config.hh>

#include <ui/main_window.hh>

#include <substrate/console>

#include <QApplication>

namespace noxcfg = Nox::compiletime;

int main(int argc, char** argv) {
	substrate::console = {stdout, stderr};
	substrate::console.showDebug(false);

	substrate::console.writeln(
		"nox-gui v"sv, noxcfg::version
		," "sv,        noxcfg::git_hash
		," ("sv,       noxcfg::compiler
		," "sv,        noxcfg::compiler_version
		," "sv,        noxcfg::target_system
		,"-"sv,        noxcfg::target_arch
		,")"sv
	);


	QApplication noxgui{argc, argv};

	Nox::gui::ui::MainWindow nox{};
	nox.show();

	return noxgui.exec();
}
