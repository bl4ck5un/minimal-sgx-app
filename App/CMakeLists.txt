set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted ${CMAKE_SOURCE_DIR}/Enclave/Enclave.edl
        --search-path ${CMAKE_SOURCE_DIR}/Enclave
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

###############################
#### dependencies
###############################

find_package(Boost QUIET REQUIRED COMPONENTS program_options filesystem system)
find_package(LOG4CXX REQUIRED)

# ###############################################################################
# grpc
# ###############################################################################

list(APPEND CMAKE_PREFIX_PATH "/opt/grpc" "/opt/protobuf")

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

# Generated sources
set(PROTO_OUTDIR ${CMAKE_CURRENT_SOURCE_DIR}/services/generated)
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/services/enclave.proto)

file(MAKE_DIRECTORY ${PROTO_OUTDIR})

protobuf_generate_cpp(PROTO_SRCS
        PROTO_HDRS
        ${PROTO_OUTDIR}
        ${PROTO_FILE})

grpc_generate_cpp(GRPC_SRCS
        GRPC_HDRS
        ${PROTO_OUTDIR}
        ${PROTO_FILE})

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

###############################
#### targets
###############################

add_executable(app
        main.cpp
        Enclave_u.c
        ocalls.cpp
        rpc.cpp
        logging.cpp
        config.cpp
        utils.cpp
        ${PROTO_SRCS}
        ${GRPC_SRCS})

include_directories(
        ${Boost_INCLUDE_DIRS}
        ${SGXSDK_INCLUDE_DIRS}
        ${MBEDTLS_LIB_DIR}/include
        ${LOG4CXX_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(app
        ${Boost_LIBRARIES}
        ${LOG4CXX_LIBRARY}
        ${SGX_URTS_LIBRARY} ${SGX_USVC_LIBRARY}
        gRPC::grpc++
        protobuf::libprotobuf
        -Wl,-rpath=/opt/grpc/lib:/opt/protobuf/lib # hardcode rpath for now.
        -lpthread -ldl)

add_dependencies(app enclave)

###############################
#### Output & Installtation
###############################
install(TARGETS app DESTINATION bin)
install(FILES
        ${CMAKE_SOURCE_DIR}/src/logging.conf
        DESTINATION conf)