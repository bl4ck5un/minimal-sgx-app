#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h> /* for size_t */
#include <wchar.h>

#include "sgx_edger8r.h" /* for sgx_ocall etc. */
#include "sgx_report.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_create_report(sgx_target_info_t* quote_enc_info,
                        sgx_report_t* report);
int ecall_get_mr_enclave(unsigned char mr_enclave[32]);

sgx_status_t SGX_CDECL ocall_logging(int level,
                                     const char* file,
                                     int line,
                                     const char* msg);
sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
