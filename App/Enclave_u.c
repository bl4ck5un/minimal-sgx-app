#include "Enclave_u.h"

#include <errno.h>

typedef struct ms_ecall_create_report_t {
  int ms_retval;
  sgx_target_info_t* ms_quote_enc_info;
  sgx_report_t* ms_report;
} ms_ecall_create_report_t;

typedef struct ms_ecall_get_mr_enclave_t {
  int ms_retval;
  unsigned char* ms_mr_enclave;
} ms_ecall_get_mr_enclave_t;

typedef struct ms_ocall_logging_t {
  int ms_level;
  const char* ms_file;
  int ms_line;
  const char* ms_msg;
} ms_ocall_logging_t;

typedef struct ms_ocall_print_string_t {
  int ms_retval;
  const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_logging(void* pms)
{
  ms_ocall_logging_t* ms = SGX_CAST(ms_ocall_logging_t*, pms);
  ocall_logging(ms->ms_level, ms->ms_file, ms->ms_line, ms->ms_msg);

  return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
  ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
  ms->ms_retval = ocall_print_string(ms->ms_str);

  return SGX_SUCCESS;
}

static const struct {
  size_t nr_ocall;
  void* table[2];
} ocall_table_Enclave = {2,
                         {
                             (void*)Enclave_ocall_logging,
                             (void*)Enclave_ocall_print_string,
                         }};
sgx_status_t ecall_create_report(sgx_enclave_id_t eid,
                                 int* retval,
                                 sgx_target_info_t* quote_enc_info,
                                 sgx_report_t* report)
{
  sgx_status_t status;
  ms_ecall_create_report_t ms;
  ms.ms_quote_enc_info = quote_enc_info;
  ms.ms_report = report;
  status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
  if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
  return status;
}

sgx_status_t ecall_get_mr_enclave(sgx_enclave_id_t eid,
                                  int* retval,
                                  unsigned char mr_enclave[32])
{
  sgx_status_t status;
  ms_ecall_get_mr_enclave_t ms;
  ms.ms_mr_enclave = (unsigned char*)mr_enclave;
  status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
  if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
  return status;
}
