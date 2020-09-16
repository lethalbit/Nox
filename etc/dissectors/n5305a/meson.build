n5305a_srcs = [
	'n5305a.c', 'frameDissector.c', 'transactDissector.c'
]

shared_library(
	'n5305a',
	n5305a_srcs,
	c_args: ['-DWS_BUILD_DLL', '-DHAVE_PLUGINS'],
	dependencies: [wireshark]
)
