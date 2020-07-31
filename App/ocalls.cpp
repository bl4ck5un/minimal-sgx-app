

#include <sgx_tseal.h>
#include <string.h>
#include <unistd.h>

#include <ctime>
#include <iostream>
#include <string>

#include "App/logging.h"
#include "Enclave_u.h"

int ocall_print_string(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  int ret = printf("%s", str);
  fflush(stdout);
  return ret;
}
