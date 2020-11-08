libnox_headers_interface = files([

])

subdir('Agilent')

if not meson.is_subproject()
	install_headers(
		libnox_headers_interface,
		subdir: 'libnox/interface'
	)
endif
