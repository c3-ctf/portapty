project(portapty)

# Needed for _Thread_local
set(CMAKE_C_STANDARD 11)

#set(CMAKE_C_COMPILER musl-gcc)
#set(CMAKE_CXX_COMPILER musl-gcc)
set(CMAKE_LINKER /usr/bin/musl-ldd)
#



set(ENABLE_TESTING OFF)
set(USE_STATIC_MBEDTLS_LIBRARY ON)
set(CMAKE_C_FLAGS "-static")
include_directories(${CMAKE_SOURCE_DIR})
add_definitions(-DMBEDTLS_CONFIG_FILE='"mbedtls.cfg.h"')
#if (ON) #CMAKE_BUILD_TYPE STREQUAL "Release"
  # This means we get a faster upgrade (and breaks `strings`, which is nice :P)
  # ultra-brute kills it for some reason, so no thanks

  add_custom_command(TARGET portapty POST_BUILD COMMAND upx --best ${portapty_path} || exit 0)
  add_definitions(-DPORTAPTY_QUIET=1)
#  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
#endif()


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -s -static -ffunction-sections -fdata-sections -Wl,--gc-sections")
add_subdirectory(mbedtls)

# We need this for some mad reason
include_directories("/usr/include/x86_64-linux-musl")
if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
  include_directories("/usr/include/")
endif()


add_executable(portapty main.c net.c upgrade.c comms.c crypto.c server.c client.c)
target_include_directories(portapty PUBLIC "/usr/include/x86_64-linux-musl")
target_link_libraries(portapty mbedtls)

get_property(portapty_path TARGET portapty PROPERTY LOCATION)
add_custom_command(TARGET portapty POST_BUILD COMMAND upx --best ${portapty_path} || exit 0)

#set_target_properties(portapty PROPERTIES COMPILE_OPTIONS "-m32;-Os" LINK_OPTIONS "-m elf_i386;-static;-s")
