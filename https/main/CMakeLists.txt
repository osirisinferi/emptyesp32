file(GLOB SOURCES *.cpp *.c ../libraries/acmeclient/*.cpp)

idf_component_register(SRCS "${SOURCES}"
  INCLUDE_DIRS "." ${BUILD_DIR}
  REQUIRES acmeclient arduinojson app_update esp_littlefs wpa_supplicant mdns nvs_flash)

add_custom_command(OUTPUT ${BUILD_DIR}/build.h
	COMMAND ${COMPONENT_DIR}/generate_build_date ${BUILD_DIR}/build.h
	DEPENDS ${SOURCES}
	VERBATIM)

add_custom_target(buildh DEPENDS ${BUILD_DIR}/build.h)
add_dependencies(${COMPONENT_LIB} buildh)

# COMMAND ${COMPONENT_DIR}/generate_build_date ${BUILD_DIR}/build.h
# COMMAND echo '#define __BUILD__ "' `date '+%Y/%m/%d %T'` '"' >${BUILD_DIR}/build.h
