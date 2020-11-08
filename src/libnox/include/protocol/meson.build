libnox_headers_protocol = files([

])

subdir('PCIe')

if not meson.is_subproject()
	install_headers(
		libnox_headers_protocol,
		subdir: 'libnox/protocol'
	)
endif
