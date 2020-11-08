libnox_headers_internal = files([
	'defs.hh',
	'fs.hh'
])

if not meson.is_subproject()
	install_headers(
		libnox_headers_internal,
		subdir: 'libnox/internal'
	)
endif
