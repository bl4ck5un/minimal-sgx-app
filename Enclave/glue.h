

#pragma once

#define _vsnprintf vsnprintf
#include <stdio.h> /* vsnprintf */

#if defined(__cplusplus)
extern "C" {
#endif

int mbedtls_sgx_drbg_random(void *p_rng, unsigned char *output, size_t out_len);
int mbedtls_hardware_poll(void *data,
                          unsigned char *output,
                          size_t len,
                          size_t *olen);
int printf_sgx(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif
