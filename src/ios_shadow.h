/*
 * The shadow password calls su, sudo and passwd use, for the PSCAL app, where Darwin has none:
 * getspnam and lckpwdf on the app's /etc/shadow, which the kernel lets only root read, and a crypt
 * that speaks SHA-512 "$6$", the format Linux's crypt reads and writes.
 */
#ifndef SMALLCLUE_IOS_SHADOW_H
#define SMALLCLUE_IOS_SHADOW_H

#include <unistd.h>

struct spwd {
    char *sp_namp;
    char *sp_pwdp;
    long sp_lstchg;
    long sp_min;
    long sp_max;
    long sp_warn;
    long sp_inact;
    long sp_expire;
    unsigned long sp_flag;
};

struct spwd *smallclueGetspnam(const char *name);
int smallclueLckpwdf(void);
int smallclueUlckpwdf(void);
/* crypt(3) for "$6$[rounds=N$]salt"; NULL with EINVAL for any other method. */
char *smallclueCryptSha512(const char *key, const char *setting);

#define getspnam(name) smallclueGetspnam((name))
#define lckpwdf() smallclueLckpwdf()
#define ulckpwdf() smallclueUlckpwdf()
#undef crypt
#define crypt(key, setting) smallclueCryptSha512((key), (setting))

/* What passwd writes: SHA-512 with this many rounds. /etc/shadow can be read through the Files app,
 * so what matters is resisting guesses made elsewhere. */
#define SMALLCLUE_SHADOW_ROUNDS 100000

#endif /* SMALLCLUE_IOS_SHADOW_H */
