libnox_deps = [
	dependency('zlib', version: '>=1.1.130', required: true),
]

libnox_srcs = files([

])

subdir('include')
subdir('core')

subdir('dissector')

subdir('analyzer')
subdir('exerciser')
subdir('interface')
subdir('protocol')

libnox = library(
	'libnox',
	libnox_srcs,
	include_directories: [ nox_inc, libnox_inc ],
	dependencies: [ nox_deps, libnox_deps ],
	install: (not meson.is_subproject()),
)

if not meson.is_subproject()
	pkgconfig = import('pkgconfig')
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
