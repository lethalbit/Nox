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

noxgui_qrc = files([

])

noxgui_inc = include_directories('./include')

noxgui_srcs += qt5.preprocess(
	ui_files: noxgui_ui,
	moc_headers: noxgui_moc,
	qresources: noxgui_qrc,
	dependencies: noxgui_deps
)

noxgui_srcs += qt5.compile_translations(
	ts_files: files([
		'i18n/en_US.ts'
	]),
	build_by_default : true,
	# install: true,
)


noxgui = executable(
	'nox-gui',
    noxgui_srcs,
    link_with: libnox,
    include_directories: [ nox_inc, libnox_inc, noxgui_inc ],
    dependencies: [ nox_deps, noxgui_deps ],
	install: true,
)
