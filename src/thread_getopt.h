/*
 * On iOS an applet is a thread of the app, and libc's getopt keeps its place in
 * variables of the whole process. Two applets parsing at once took each other's: tee
 * lost its -a, took it for the file to write, or read past its own arguments and ended
 * the app. These names go to the per-thread parser the ssh clients use
 * (openbsd-compat/getopt_long.c). Anywhere else this changes nothing.
 * The two functions are compiled once, in gnu_util.c.
 */
#ifndef SMALLCLUE_THREAD_GETOPT_H
#define SMALLCLUE_THREAD_GETOPT_H

#if defined(PSCAL_TARGET_IOS)
#include <getopt.h>
#include <unistd.h>

int smallclueThreadGetopt(int argc, char * const *argv, const char *opts);
int smallclueThreadGetoptLong(int argc, char * const *argv, const char *opts,
                              const struct option *longs, int *index);

int *pscal_getopt_opterr(void);
int *pscal_getopt_optind(void);
int *pscal_getopt_optopt(void);
int *pscal_getopt_optreset(void);
char **pscal_getopt_optarg(void);

#undef getopt
#undef getopt_long
#undef opterr
#undef optind
#undef optopt
#undef optreset
#undef optarg
#define getopt smallclueThreadGetopt
#define getopt_long smallclueThreadGetoptLong
#define opterr (*pscal_getopt_opterr())
#define optind (*pscal_getopt_optind())
#define optopt (*pscal_getopt_optopt())
#define optreset (*pscal_getopt_optreset())
#define optarg (*pscal_getopt_optarg())
#endif /* PSCAL_TARGET_IOS */

#endif /* SMALLCLUE_THREAD_GETOPT_H */
