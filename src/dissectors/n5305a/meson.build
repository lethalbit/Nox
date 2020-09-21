n5305a_srcs = [
	'n5305a.cc',
	'frame_reassembly.cc',
	'transaction_reassembly.cc',
	'transact_dissector.cc'
]

ws_version = wireshark.version()
ws_version = ws_version.split('.')

n5305a_dissector = shared_library(
	'n5305a',
	n5305a_srcs,
	name_prefix: '',
	cpp_args: [
		'-DWS_BUILD_DLL',
		'-DHAVE_PLUGINS',
		'-DWIRESHARK_VERSION_MAJOR=@0@'.format(ws_version[0]),
		'-DWIRESHARK_VERSION_MINOR=@0@'.format(ws_version[1])
	],
	dependencies: [ wireshark, substrate_dep ],
	gnu_symbol_visibility: 'inlineshidden',
	install: true,
	install_dir: wireshark.get_pkgconfig_variable('plugindir')
)
