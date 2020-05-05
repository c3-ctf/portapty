cmake_minimum_required(VERSION 3.11)
project(portapty)

cmake_policy(VERSION 3.16)

# Needed for _Thread_local
set(CMAKE_C_STANDARD 11)

#set(CMAKE_C_COMPILER musl-gcc)
#set(CMAKE_CXX_COMPILER musl-gcc)
#
option(PORTAPTY_NO_MUSL OFF)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(PORTAPTY_NO_MUSL ON)
  message("Building debuggable (but huge and non-portable) portapty")
  set(PORTAPTY_DEBUG ON)
else()
  set(PORTAPTY_DEBUG OFF)
endif()

if (NOT PORTAPTY_NO_MUSL)
  include_directories("/usr/include/x86_64-linux-musl")
#  set(CMAKE_C_COMPILER /usr/bin/musl-gcc)
  set(CMAKE_LINKER /usr/bin/musl-ldd)
  set(PORTAPTY_EXTRA util)
endif()

set(ENABLE_TESTING OFF)
set(USE_STATIC_MBEDTLS_LIBRARY ON)
include_directories(${CMAKE_SOURCE_DIR}/include)
add_definitions(-DMBEDTLS_CONFIG_FILE=<mbedtls.cfg.h>)

if (PORTAPTY_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb3")
else()
  add_definitions(-DPORTAPTY_QUIET=1)
  set(CMAKE_C_FLAGS "-static")
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  set(CMAKE_C_FLAGS_RELEASE "-Os -s -ffunction-sections -fdata-sections -Wl,--gc-sections -DNDEBUG")
#  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -DNDEBUG")
endif()

add_subdirectory(mbedtls)

# We need this for some mad reason

#if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
#  include_directories("/usr/include/")
#endif()


add_executable(portapty src/main.c src/net.c src/upgrade.c src/crypto.c src/server.c src/client.c)
target_include_directories(portapty PUBLIC "/usr/include/x86_64-linux-musl")
target_link_libraries(portapty mbedtls util ${PORTAPTY_EXTRA})

add_executable(mbedtls-err src/err.c)
target_link_libraries(mbedtls-err mbedtls util ${PORTAPTY_EXTRA})

if (NOT PORTAPTY_DEBUG)
#  get_property(portapty_path TARGET portapty PROPERTY LOCATION)
  set(portapty_path ${CMAKE_CURRENT_BINARY_DIR}/portapty)
  # This means we get a faster upgrade (and breaks `strings`, which is nice :P)
  # brute kills it for some reason, so no thanks
  add_custom_command(TARGET portapty POST_BUILD COMMAND upx --best ${portapty_path} || exit 0)
endif()

#set_target_properties(portapty PROPERTIES COMPILE_OPTIONS "-m32;-Os" LINK_OPTIONS "-m elf_i386;-static;-s")
