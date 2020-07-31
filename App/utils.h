

#ifndef SRC_APP_UTILS_H_
#define SRC_APP_UTILS_H_

#include <assert.h>
#include <pwd.h>
#include <sgx_eid.h>
#include <sgx_error.h>
#include <sgx_uae_service.h>
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

#include "logging.h"

#define MAX_PATH FILENAME_MAX

#define TOKEN_FILENAME "app.enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"

int initialize_enclave(const char *name, sgx_enclave_id_t *eid);
void print_error_message(sgx_status_t ret);
const std::string sgx_error_message(sgx_status_t ret);

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

#endif  // SRC_APP_UTILS_H_
