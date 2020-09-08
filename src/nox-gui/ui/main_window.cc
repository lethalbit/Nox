// SPDX-License-Identifier: GPL-3.0-or-later
/* ui/main_window.cc - Nox GUI main window */

#include <ui/main_window.hh>

namespace Nox::gui::ui {
	MainWindow::MainWindow(QWindow* parent) noexcept : ui(new Ui::MainWindow) {
		ui->setupUi(this);
	}
}
