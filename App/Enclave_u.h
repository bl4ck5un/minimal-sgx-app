#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h> /* for size_t */
#include <string.h>
#include <wchar.h>

#include "sgx_edger8r.h" /* for sgx_satus_t etc. */
#include "sgx_report.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_LOGGING_DEFINED__
#define OCALL_LOGGING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION,
                 ocall_logging,
                 (int level, const char* file, int line, const char* msg));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ecall_create_report(sgx_enclave_id_t eid,
                                 int* retval,
                                 sgx_target_info_t* quote_enc_info,
                                 sgx_report_t* report);
sgx_status_t ecall_get_mr_enclave(sgx_enclave_id_t eid,
                                  int* retval,
                                  unsigned char mr_enclave[32]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
