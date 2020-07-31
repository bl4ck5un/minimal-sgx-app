

#include <cstring>
#include <ctime>

#include "Enclave_t.h"
#include "debug.h"
#include "log.h"
#include "sgx_report.h"
#include "sgx_utils.h"

int ecall_create_report(sgx_target_info_t *quote_enc_info, sgx_report_t *report)
{
  sgx_report_data_t data;  // user defined data
  int ret = 0;
  memset(&data.d, 0x90, sizeof data.d);  // put in some data
  ret = sgx_create_report(quote_enc_info, &data, report);

  hexdump("measurement: ", report->body.mr_enclave.m, SGX_HASH_SIZE);
  return ret;
}

int ecall_get_mr_enclave(unsigned char mr_enclave[32])
{
  sgx_report_t report;

  sgx_status_t ret = sgx_create_report(nullptr, nullptr, &report);
  if (ret != SGX_SUCCESS) {
    LL_CRITICAL("failed to get mr_enclave");
    return -1;
  }

  memcpy(mr_enclave, report.body.mr_enclave.m, SGX_HASH_SIZE);

  return 0;
}