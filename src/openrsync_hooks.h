#ifndef SMALLCLUE_OPENRSYNC_HOOKS_H
#define SMALLCLUE_OPENRSYNC_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

_Noreturn void pscal_openrsync_request_exit(int code);

const char *pscal_openrsync_getprogname(void);

_Noreturn void pscal_openrsync_err(int eval, const char *fmt, ...);
_Noreturn void pscal_openrsync_errc(int eval, int code, const char *fmt, ...);
_Noreturn void pscal_openrsync_errx(int eval, const char *fmt, ...);

void pscal_openrsync_warn(const char *fmt, ...);
void pscal_openrsync_warnc(int code, const char *fmt, ...);
void pscal_openrsync_warnx(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* SMALLCLUE_OPENRSYNC_HOOKS_H */
