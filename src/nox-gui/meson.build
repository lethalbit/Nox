qt5 = import('qt5')

noxgui_deps = [
	dependency('qt5', modules: ['Core', 'Gui', 'Widgets'], required: true),
	dependency('libgvc', required: false),
	libnokogiri_dep,
]


noxgui_ui = files([])
noxgui_moc = files([])
noxgui_qrc = files([])


noxgui_srcs = files([
	'nox-gui.cc',
])

subdir('include')

subdir('models')
subdir('i18n')
subdir('qrc')
subdir('ui')

noxgui_srcs += qt5.preprocess(
	ui_files: noxgui_ui,
	moc_headers: noxgui_moc,
	qresources: noxgui_qrc,
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
