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
	install: true,
)
