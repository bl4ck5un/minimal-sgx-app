add_definitions(-DENCLAVE_STD_ALT)
add_definitions(-DIN_ENCLAVE)

###############################
#### list source code files
###############################

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "Enclave_t.c; Enclave_t.h")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_t.c
        COMMAND ${SGX_EDGER8R} --trusted ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl
        --search-path ${TC_ROOT_DIR}/Enclave
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

###############################
#### targets
###############################

add_library(enclave SHARED
        debug.c
        ecall_attestation.cpp
        Enclave_t.c
        glue.c
        log.cpp)

###############################
#### Include & Libs
###############################

set(CMAKE_C_FLAGS "${SGX_COMMON_CFLAGS} ${CMAKE_C_FLAGS} \
    -Wall -Werror=return-type -nostdinc -fvisibility=hidden -fpie -fstack-protector")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} \
    -std=c++11 -nostdinc++")

include_directories(
        $(CMAKE_CURRENT_SOURCE_DIR)
        ${TC_ROOT_DIR}/Common
        ${SGX_SDK}/include
        ${SGX_SDK}/include/tlibc
        ${SGX_SDK}/include/libcxx)

target_link_libraries(enclave "${SGX_COMMON_CFLAGS} \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0")

###############################
#### Output & Installtation
###############################

set(DEBUG_ENCLAVE_NAME "enclave.debug.so")

add_custom_command(TARGET enclave
        POST_BUILD
        COMMAND ${SGX_ENCLAVE_SIGNER} sign
        -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_private.pem
        -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml
        -enclave libenclave.so
        -out ${DEBUG_ENCLAVE_NAME}
        COMMENT "Signing the ${CMAKE_CURRENT_BINARY_DIR}/libenclave.so.")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${DEBUG_ENCLAVE_NAME} DESTINATION enclave)