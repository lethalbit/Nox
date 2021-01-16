# SPDX-License-Identifier: GPL-3.0-or-later
include(WiresharkPlugin)

set_module_info(n5305a 0 0 2 0)

add_definitions(-DWIRESHARK_VERSION_MAJOR=${PROJECT_MAJOR_VERSION} -DWIRESHARK_VERSION_MINOR=${PROJECT_MINOR_VERSION})

set(PLUGIN_FILES
	n5305a.cc
	frame_reassembly.cc
	transaction_dissector.cc
	transaction_reassembly.cc
	${DISSECTOR_SRCS}
)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS} "
)

register_plugin_files(plugin.c
	n5305a
	${DISSECTOR_SRCS}
)

add_plugin_library(n5305a epan)
target_link_libraries(n5305a epan)
install_plugin(n5305a epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.hh")
CHECKAPI(
	NAME
		n5305a
	SWITCHES
		-g abort -g termoutput
	SOURCES
		${DISSECTOR_SRCS}
		${DISSECTOR_HEADERS}
)
