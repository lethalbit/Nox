noxcli_deps = [
	dependency('ncurses', required: true),
]

line_editor = get_option('line_editor')
if line_editor == 'readline'
	noxcli_deps += dependency('readline', required: true)
elif line_editor == 'editline'
	noxcli_deps += dependency('libedit', required: true)
endif

noxcli_srcs = files([
	'nox-cli.cc'
])

subdir('include')

noxcli = executable(
	'nox-cli',
    noxcli_srcs,
    link_with: libnox,
    include_directories: [ nox_inc, libnox_inc, noxcli_inc ],
    dependencies: [ nox_deps, noxcli_deps ],
	install: true,
)
