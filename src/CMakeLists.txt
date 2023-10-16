

# Add target to project dependency list
PROJECT_TARGET_ADD(ocpp)

	# compile any C file starting with a lower case
	file(GLOB CSOURCES [a-z]*.c)

	# Define project Targets
	add_library(${TARGET_NAME} SHARED ${CSOURCES})


    # Add dependency without pkgconfig
    target_link_libraries(${TARGET_NAME} rp-utils)

    target_compile_options(${TARGET_NAME}
        PUBLIC  -Wno-unused-variable
    )

	# Binder exposes a unique public entry point
	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
		PREFIX "libafb-"
		LABELS "LIBRARY"
        SUFFIX "-ext.so"
		# LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/conf.d/cmake/afb-ext-link.flags"
		IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libafb-${TARGET_NAME}-ext.so
		OUTPUT_NAME ${TARGET_NAME}
	)

