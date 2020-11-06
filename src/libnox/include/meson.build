
libnox_headers_internal = files([
	'internal/defs.hh',
	'internal/fs.hh'
])


if not meson.is_subproject()
	install_headers(
		libnox_headers_internal,
		subdir: 'libnox/internal'
	)

	install_headers(
		'@0@/etc/config.hh'.format(meson.build_root()),
		subdir: 'libnox'
	)
endif
