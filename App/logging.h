#include <log4cxx/logger.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef APP_LOG_H
#define APP_LOG_H

constexpr auto LOGGING_CONF_FILE = "/tc/conf/logging.conf";

// define _FALSE as a universal false for C++/C
#ifdef __cplusplus
#define _FALSE false
#else
#define _FALSE 0
#endif

// Logging utilities for untrusted world
extern char log_buffer[BUFSIZ];

#define LOG_TO_LOG4CXX(FUNC, fmt, arg...)     \
  do {                                        \
    snprintf(log_buffer, BUFSIZ, fmt, ##arg); \
    FUNC(logger, log_buffer)                  \
  } while (_FALSE);

#define LL_LOG(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_TRACE, fmt, ##arg)
#define LL_DEBUG(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_DEBUG, fmt, ##arg)
#define LL_TRACE(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_TRACE, fmt, ##arg)
#define LL_INFO(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_INFO, fmt, ##arg)
#define LL_WARNING(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_WARN, fmt, ##arg)
#define LL_ERROR(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_ERROR, fmt, ##arg)
#define LL_CRITICAL(fmt, arg...) LOG_TO_LOG4CXX(LOG4CXX_FATAL, fmt, ##arg)

// an ocall logger for enclave
#ifdef __cplusplus
extern "C" {
#endif
void ocall_logging(int level, const char* file, int line, const char* msg);
#ifdef __cplusplus
}
#endif

#endif  // APP_LOG_H