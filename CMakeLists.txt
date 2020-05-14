cmake_minimum_required(VERSION 3.7)
project(portapty)

set(CMAKE_C_STANDARD 99)

#set(CMAKE_C_COMPILER musl-gcc)
#set(CMAKE_CXX_COMPILER musl-gcc)
#
option(PORTAPTY_NO_MUSL OFF)
option(PORTAPTY_32 ON)

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
  # Doesn't make much difference
  # add_definitions(-DPORTAPTY_QUIET=1)
  set(CMAKE_LINKER /usr/bin/musl-ldd)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -ffunction-sections -fdata-sections -DNDEBUG")
  if (PORTAPTY_32)
    # You have no idea how much grief this caused
    include_directories("/usr/include/i386-linux-musl")
    if (CMAKE_COMPILER_IS_GNUCC)
      set(CMAKE_C_FLAGS "-specs \"${CMAKE_CURRENT_SOURCE_DIR}/musl-gcc.specs\"")
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
  else()
    include_directories("/usr/include/x86_64-linux-musl")
    if (CMAKE_COMPILER_IS_GNUCC)
      set(CMAKE_C_FLAGS "-specs \"${CMAKE_CURRENT_SOURCE_DIR}/musl-gcc64.specs\"")
    endif()
  endif()
  set(CMAKE_C_FLAGS_RELEASE     "")
  # Evil hack to bypass -O2 on mbedtls
  unset(CMAKE_C_COMPILER_ID)
endif()

add_subdirectory(mbedtls)

set(sources src/main.c src/net.c src/upgrade.c src/crypto.c src/server.c src/client.c src/relay.c)

add_executable(portapty ${sources})
target_link_libraries(portapty mbedtls util)
target_link_options(portapty PUBLIC "-s;-Wl,--gc-sections;-Wl,--as-needed")
if (PORTAPTY_32)
  target_link_options(portapty PUBLIC "-Wl,-melf_i386")
endif()

add_executable(mbedtls-err src/err.c)
target_link_libraries(mbedtls-err mbedtls util)

if (NOT PORTAPTY_DEBUG)
  # This means we get a faster upgrade (and breaks `strings`, which is nice :P)
  # brute kills it for some reason, so no thanks
  add_custom_command(TARGET portapty POST_BUILD COMMAND upx --best --lzma $<TARGET_FILE:portapty> || exit 0)
endif()
