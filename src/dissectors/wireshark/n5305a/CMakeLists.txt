# SPDX-License-Identifier: GPL-3.0-or-later
include(WiresharkPlugin)

set_module_info(n5305a 0 0 2 0)

set(DISSECTOR_SRCS
	frame_reassembly.cc
	n5305a.cc
	transaction_dissector.cc
	transaction_reassembly.cc
)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "**/*.hh")

set_source_files_properties(
	${DISSECTOR_SRCS}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS} "
)

add_plugin_library(n5305a epan)
target_link_libraries(n5305a epan)
install_plugin(n5305a epan)

CHECKAPI(
	NAME
		n5305a
	SWITCHES
		-g abort -g termoutput
	SOURCES
		${DISSECTOR_SRCS}
		${DISSECTOR_HEADERS}
)
