cmake_minimum_required(VERSION 3.10)  # bionic's cmake version

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

set(PROJECT_NAME oxen-whois)
project(${PROJECT_NAME}
    VERSION 0.0.1
    DESCRIPTION "oxen-whois - whois server for oxen blockchain"
    LANGUAGES CXX)

include(CheckCXXSourceCompiles)
include(CheckLibraryExists)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig)
pkg_check_modules(PC_OXENMQ liboxenmq REQUIRED)
pkg_check_modules(PC_SODIUM libsodium REQUIRED)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON) 

option(WITH_STATIC "static link all the stuff" OFF)

set(BUILD_TESTING OFF)
set(BUILD_UVW_LIBS ${WITH_STATIC})
set(USE_LIBCPP OFF)

add_library(uv_interface INTERFACE)
set(BUILD_STATIC_LIBS ${WITH_STATIC})
set(BUILD_SHARED_LIBS NOT ${WITH_STATIC})
add_subdirectory(external/uvw EXCLUDE_FROM_ALL)
if(WITH_STATIC)
  target_link_libraries(uv_interface INTERFACE uvw::uvw-static)
else()
  pkg_check_modules(PC_UV libuv REQUIRED)
  target_link_libraries(uv_interface INTERFACE ${PC_UV_LIBRARIES} uvw)
  target_include_directories(uv_interface PUBLIC ${PC_UV_INCLUDE_DIR})
endif()


add_executable(${PROJECT_NAME} whois.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC ${PC_OXENMQ_LIBRARIES} ${PC_SODIUM_LIBRARIES} uv_interface)
