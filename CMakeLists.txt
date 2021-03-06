cmake_minimum_required(VERSION 3.0)
project(Min-SGX)

# build options
option(BUILD_TESTS "build the mytest target" on)
option(CMAKE_BUILD_TYPE "(Debug|Prerelease|Release)" Debug)

# only support x64
set(SGX_ARCH x64)

# set SDK path
if (DEFINED ENV{SGX_SDK})
    set(SGX_SDK $ENV{SGX_SDK})
else()
    set(SGX_SDK /opt/intel/sgxsdk)
endif()

include(cmake/Init.cmake)

IF(CMAKE_BUILD_TYPE MATCHES Debug)
    set(SGX_MODE SIM)
    set(SGX_BUILD DEBUG)
ELSEIF(CMAKE_BUILD_TYPE MATCHES Prerelease)
    set(SGX_MODE HW)
    set(SGX_BUILD PRERELEASE)
ELSEIF(CMAKE_BUILD_TYPE MATCHES Release)
    set(SGX_MODE HW)
    set(SGX_BUILD RELEASE)
ELSE()
    message(FATAL_ERROR "unknown build type ${CMAKE_BUILD_TYPE}")
ENDIF()

include(cmake/ConfigSGX.cmake)

# check cmake configuration
message(STATUS "Building ${CMAKE_BUILD_TYPE} with CFLAGS ${CMAKE_C_FLAGS}")

add_subdirectory(App)
add_subdirectory(Enclave)