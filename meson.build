project(
	'Nox',
	'cpp',
	default_options: [
		'cpp_std=c++17',
		'warning_level=3',
		'b_lto=true',
		'b_sanitize=address,undefined'
	],
	meson_version: '>= 0.54.0',
	license: 'GPL-3.0-or-later',
	version: '0.0.1'
)

cxx = meson.get_compiler('cpp')

extra_args = [
	'-Wvla',
	'-Wimplicit-fallthrough'
]

add_project_arguments(
	cxx.get_supported_arguments(extra_args),
	language: 'cpp'
)

nox_deps = [
	dependency('threads', required: true),
]

if (cxx.get_id() == 'gcc' and cxx.version().version_compare('<9.0.0')) or (cxx.get_id() == 'clang' and cxx.version().version_compare('<9.0.0'))
	if cxx.has_header('experimental/filesystem') == false
		error('Unable to find C++17 experimental/filesystem header')
	endif
	nox_deps += [ cxx.find_library('libstdc++fs', required: true) ]
	add_global_arguments('-DLIBNOX_CPPFS_EXPERIMENTAL',	language: 'cpp')
endif

substrate_dep = dependency('substrate', required: false, version: '>=0.0.1')
libnokogiri_dep = dependency('libnokogiri', required: false, version: '>=0.0.1')

if not substrate_dep.found()
	message('Did not find local substrate install, bundling')
	substrate = subproject('substrate', default_options: [
		'default_library=static',
		'build_tests=false',
	])
	substrate_dep = substrate.get_variable('substrate_dep')
endif

if not libnokogiri_dep.found()
	message('Did not find local libnokogiri install, bundling')
	libnokogiri = subproject('libnokogiri', default_options: [
		'default_library=static',
		'enable_tests=false',
		'build_examples=false',
	])
	libnokogiri_dep = libnokogiri.get_variable('libnokogiri_dep')
endif

nox_deps += [
	substrate_dep,
	libnokogiri_dep,
]

subdir('etc')
subdir('src')
