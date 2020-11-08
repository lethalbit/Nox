libnox_headers_analyzer = files([

])

subdir('Agilent')

if not meson.is_subproject()
	install_headers(
		libnox_headers_analyzer,
		subdir: 'libnox/analyzer'
	)
endif
