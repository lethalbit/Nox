libnox_headers_protocol_pcie = files([

])

subdir('gen1')
subdir('gen2')
subdir('gen3')
subdir('gen4')

if not meson.is_subproject()
	install_headers(
		libnox_headers_protocol_pcie,
		subdir: 'libnox/protocol/PCIe'
	)
endif
