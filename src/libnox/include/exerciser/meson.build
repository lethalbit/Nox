libnox_headers_exerciser = files([

])

subdir('Agilent')

if not meson.is_subproject()
	install_headers(
		libnox_headers_exerciser,
		subdir: 'libnox/exerciser'
	)
endif
