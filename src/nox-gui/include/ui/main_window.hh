// SPDX-License-Identifier: GPL-3.0-or-later
/* ui/main_window.hh - Nox GUI main window */
#pragma once
#if !defined(NOX_GUI_UI_MAIN_WINDOW_HH)
#define NOX_GUI_UI_MAIN_WINDOW_HH

#include <config.hh>

#include <memory>

#include <QMainWindow>
#include <ui_main_window.h>

namespace Nox::gui::ui {
	class MainWindow final : public QMainWindow {
		Q_OBJECT
	private:
		std::unique_ptr<Ui_MainWindow> ui;
	public:
		explicit MainWindow(QWindow* parent = nullptr) noexcept;
	};
}
#endif /* NOX_GUI_UI_MAIN_WINDOW_HH */
