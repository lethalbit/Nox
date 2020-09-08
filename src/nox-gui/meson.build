qt5 = import('qt5')

noxgui_deps = [
	dependency('qt5', modules: ['Core', 'Gui', 'Widgets'], required: true),
]

noxgui_srcs = files([
	'nox-gui.cc',

	# Global Windows
	'ui/main_window.cc',

	# Diagnostics Windows

	# Capture Windows

	# Settings Windows

])

noxgui_moc = files([
	# Global Windows
	'include/ui/main_window.hh',

	# Diagnostics Windows

	# Capture Windows

	# Settings Windows
])

noxgui_ui = files([
	# Global Windows
	'ui/main_window.ui',

	# Diagnostics Windows

	# Capture Windows

	# Settings Windows
])

noxgui_inc = include_directories('./include')

noxgui_srcs += qt5.preprocess(
	ui_files: noxgui_ui,
	moc_headers: noxgui_moc,
	dependencies: noxgui_deps
)


noxgui = executable(
	'nox-gui',
    noxgui_srcs,
    link_with: libnox,
    include_directories: [ nox_inc, libnox_inc, noxgui_inc ],
    dependencies: [ nox_deps, noxgui_deps ],
	install: true,
)
