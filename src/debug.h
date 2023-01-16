/****************************************************************
 * Copyright (C) 2021 Schneider Electric                        *
 ****************************************************************/

#if !defined(__DEBUG_H__)
#define __DEBUG_H__

//#define DEBUG
//#define INFO
#define ERROR

#ifdef DEBUG
#define debug(format, ...)  fprintf(stderr, "DBG: "format, __VA_ARGS__); fprintf(stderr, "\r\n")
#define debugf(string) fprintf(stderr, string); fprintf(stderr, "\r\n")
#else
#define debug(format, ...)
#define debugf(string)
#endif

#ifdef INFO
#define info(format, ...)  fprintf(stderr, "INFO: "format, __VA_ARGS__); fprintf(stderr, "\r\n")
#define infof(string) fprintf(stderr, string); fprintf(stderr, "\r\n")
#else
#define info(format, ...)
#define infof(string)
#endif

#ifdef ERROR
#define error(format, ...)  fprintf(stderr, "ERROR:"format, __VA_ARGS__); fprintf(stderr, "\r\n")
#define errorf(string) fprintf(stderr, string); fprintf(stderr, "\r\n")
#else
#define error(format, ...)
#define errorf(string)
#endif

#endif
