
cmake_minimum_required(VERSION 3.15)

project(afb-ocpp-ext
	VERSION 0.1
	DESCRIPTION "Provide OCPP-1.6+2.0.1 websocket RPC"
	HOMEPAGE_URL "https://github.com/redpesk-automotive/afb-ocpp-ext"
	LANGUAGES C
)

include(FindPkgConfig)
include(GNUInstallDirs)

pkg_check_modules(deps REQUIRED librp-utils libafb>=5)

# Define target
add_library(afb-ocpp-ext SHARED src/ocpp.c)

target_include_directories(afb-ocpp-ext PRIVATE ${deps_INCLUDE_DIRS})
target_compile_options(afb-ocpp-ext PRIVATE ${deps_CFLAGS})
target_link_options(afb-ocpp-ext PRIVATE ${deps_LDFLAGS})
target_link_directories(afb-ocpp-ext PRIVATE ${deps_LIBRARY_DIRS})
target_link_libraries(afb-ocpp-ext PRIVATE ${deps_LIBRARIES})

install(TARGETS afb-ocpp-ext LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/afb-ext)


