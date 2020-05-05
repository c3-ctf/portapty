cmake_minimum_required(VERSION 3.7)
project(portapty)

set(CMAKE_C_STANDARD 99)

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

#  set(CMAKE_C_COMPILER /usr/bin/musl-gcc)
endif()

set(ENABLE_TESTING OFF)
set(USE_STATIC_MBEDTLS_LIBRARY ON)
include_directories(${CMAKE_SOURCE_DIR}/include)
add_definitions(-DMBEDTLS_CONFIG_FILE=<mbedtls.cfg.h>)

if (PORTAPTY_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb3")
else()
  add_definitions(-DPORTAPTY_QUIET=1)
  include_directories("/usr/include/i386-linux-musl")
  set(CMAKE_LINKER /usr/bin/musl-ldd)
  if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "-specs \"${CMAKE_CURRENT_SOURCE_DIR}/musl-gcc.specs\"")
  endif()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -ffunction-sections -fdata-sections -m32 -DNDEBUG")
  set(CMAKE_C_FLAGS_RELEASE     "")
  # Evil hack to bypass -O2 on mbedtls
  unset(CMAKE_C_COMPILER_ID)
endif()

add_subdirectory(mbedtls)


add_executable(portapty src/main.c src/net.c src/upgrade.c src/crypto.c src/server.c src/client.c)
target_link_libraries(portapty mbedtls util)
if (NOT PORTAPTY_DEBUG)
  target_link_options(portapty PUBLIC "-s;-Wl,--gc-sections;-Wl,--as-needed;-Wl,-melf_i386")
endif()

add_executable(mbedtls-err src/err.c)
target_link_libraries(mbedtls-err mbedtls util)

if (NOT PORTAPTY_DEBUG)
#  get_property(portapty_path TARGET portapty PROPERTY LOCATION)
  set(portapty_path ${CMAKE_CURRENT_BINARY_DIR}/portapty)
  # This means we get a faster upgrade (and breaks `strings`, which is nice :P)
  # brute kills it for some reason, so no thanks
  add_custom_command(TARGET portapty POST_BUILD COMMAND upx --best ${portapty_path} || exit 0)
endif()
