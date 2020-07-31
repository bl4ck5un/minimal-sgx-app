#include "glue.h"

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "sgx.h"
#include "sgx_trts.h"

// real ocall to be implemented in the Application
extern int ocall_print_string(int *ret, char *str);
int printf_sgx(const char *fmt, ...)
{
  int ret;
  va_list ap;
  char buf[BUFSIZ] = {'\0'};
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);

  ocall_print_string(&ret, buf);
  return ret;
}
