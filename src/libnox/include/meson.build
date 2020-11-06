libnox_headers = files([

])

subdir('internal')

if not meson.is_subproject()
	install_headers(
		libnox_headers,
		subdir: 'libnox'
	)

	install_headers(
		'@0@/etc/config.hh'.format(meson.build_root()),
		subdir: 'libnox'
	)
endif
