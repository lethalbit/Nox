libnox_deps = [
	dependency('zlib', version: '>=1.1.130', required: true),
]

libnox_srcs = files([

])

libnox_inc = include_directories('./include')

libnox = library(
	'libnox',
	libnox_srcs,
	include_directories: [ nox_inc, libnox_inc ],
	dependencies: [ nox_deps, libnox_deps ],
	install: (not meson.is_subproject()),
)

subdir('include')

pkgconfig = import('pkgconfig')

if not meson.is_subproject()
	pkgconfig.generate(
		subdirs: 'libnox',
		name: 'libnox',
		filebase: 'libnox',
		libraries: [ libnox ],
		version: meson.project_version(),
		description: 'An interface library to interact with the Agilent N2X chassis and modules'
	)
endif

libnox_dep = declare_dependency(
	dependencies: [ nox_deps, libnox_deps ],
	include_directories: [ nox_inc, libnox_inc ],
	link_with: libnox,
	version: meson.project_version()
)
