/*
 * stty: print or change terminal settings, compatible with GNU coreutils 9.
 *
 * The settings are kept in Linux's terms (flag values and c_cc slots from
 * asm-generic/termbits.h, NCCS 32), whatever the host is, so that `stty -g`
 * produces and accepts exactly what GNU stty on Linux does: a script may save
 * a terminal with one stty and restore it with the other. On a Linux host the
 * conversion to and from struct termios is the identity; on Darwin (iSH-AOK,
 * where this runs as host code in front of a Linux guest's tty) each flag and
 * control character is carried across by name, and a Linux-only setting
 * (iuclc, olcuc, xcase, cmspar, swtch) is reported off and does not take.
 *
 * Output follows GNU's: the short listing shows what differs from `sane`,
 * -a shows everything, both wrapped to the terminal's width; -g is four flag
 * words and NCCS control characters in hex. After a change the settings are
 * read back, and a difference is reported ("unable to perform all requested
 * operations") with exit status 1, as GNU does.
 *
 * Runs as a function call inside embedding hosts: no global state, and every
 * descriptor opened is closed.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "stty_app.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#if defined(PSCAL_TARGET_IOS)
#include "common/runtime_tty.h"
#endif

/* ------------------------------------------------------------------------ */
/* Linux's termios, the model everything below works in                      */

#define L_NCCS 32

#define L_VINTR 0
#define L_VQUIT 1
#define L_VERASE 2
#define L_VKILL 3
#define L_VEOF 4
#define L_VTIME 5
#define L_VMIN 6
#define L_VSWTC 7
#define L_VSTART 8
#define L_VSTOP 9
#define L_VSUSP 10
#define L_VEOL 11
#define L_VREPRINT 12
#define L_VDISCARD 13
#define L_VWERASE 14
#define L_VLNEXT 15
#define L_VEOL2 16

#define L_IGNBRK 0000001u
#define L_BRKINT 0000002u
#define L_IGNPAR 0000004u
#define L_PARMRK 0000010u
#define L_INPCK 0000020u
#define L_ISTRIP 0000040u
#define L_INLCR 0000100u
#define L_IGNCR 0000200u
#define L_ICRNL 0000400u
#define L_IUCLC 0001000u
#define L_IXON 0002000u
#define L_IXANY 0004000u
#define L_IXOFF 0010000u
#define L_IMAXBEL 0020000u
#define L_IUTF8 0040000u

#define L_OPOST 0000001u
#define L_OLCUC 0000002u
#define L_ONLCR 0000004u
#define L_OCRNL 0000010u
#define L_ONOCR 0000020u
#define L_ONLRET 0000040u
#define L_OFILL 0000100u
#define L_OFDEL 0000200u
#define L_NLDLY 0000400u
#define L_NL1 0000400u
#define L_CRDLY 0003000u
#define L_CR1 0001000u
#define L_CR2 0002000u
#define L_CR3 0003000u
#define L_TABDLY 0014000u
#define L_TAB1 0004000u
#define L_TAB2 0010000u
#define L_TAB3 0014000u
#define L_BSDLY 0020000u
#define L_BS1 0020000u
#define L_VTDLY 0040000u
#define L_VT1 0040000u
#define L_FFDLY 0100000u
#define L_FF1 0100000u

#define L_CBAUD 0010017u
#define L_CSIZE 0000060u
#define L_CS5 0000000u
#define L_CS6 0000020u
#define L_CS7 0000040u
#define L_CS8 0000060u
#define L_CSTOPB 0000100u
#define L_CREAD 0000200u
#define L_PARENB 0000400u
#define L_PARODD 0001000u
#define L_HUPCL 0002000u
#define L_CLOCAL 0004000u
#define L_CBAUDEX 0010000u
#define L_CMSPAR 010000000000u
#define L_CRTSCTS 020000000000u

#define L_ISIG 0000001u
#define L_ICANON 0000002u
#define L_XCASE 0000004u
#define L_ECHO 0000010u
#define L_ECHOE 0000020u
#define L_ECHOK 0000040u
#define L_ECHONL 0000100u
#define L_NOFLSH 0000200u
#define L_TOSTOP 0000400u
#define L_ECHOCTL 0001000u
#define L_ECHOPRT 0002000u
#define L_ECHOKE 0004000u
#define L_FLUSHO 0010000u
#define L_PENDIN 0040000u
#define L_IEXTEN 0100000u
#define L_EXTPROC 0200000u

typedef struct {
    uint32_t iflag, oflag, cflag, lflag;
    uint8_t line;
    uint8_t cc[L_NCCS];
} SttyMode;

/* ------------------------------------------------------------------------ */
/* Host struct termios <-> the Linux model                                   */

typedef struct {
    unsigned long host;
    uint32_t linux_value;
} SttyBit;

#define STTY_BIT(h, l) {(unsigned long)(h), (l)}

static const SttyBit sttyIBits[] = {
    STTY_BIT(IGNBRK, L_IGNBRK), STTY_BIT(BRKINT, L_BRKINT), STTY_BIT(IGNPAR, L_IGNPAR),
    STTY_BIT(PARMRK, L_PARMRK), STTY_BIT(INPCK, L_INPCK), STTY_BIT(ISTRIP, L_ISTRIP),
    STTY_BIT(INLCR, L_INLCR), STTY_BIT(IGNCR, L_IGNCR), STTY_BIT(ICRNL, L_ICRNL),
#ifdef IUCLC
    STTY_BIT(IUCLC, L_IUCLC),
#endif
    STTY_BIT(IXON, L_IXON), STTY_BIT(IXANY, L_IXANY), STTY_BIT(IXOFF, L_IXOFF),
#ifdef IMAXBEL
    STTY_BIT(IMAXBEL, L_IMAXBEL),
#endif
#ifdef IUTF8
    STTY_BIT(IUTF8, L_IUTF8),
#endif
};

/* The delay fields are mapped as single bits except TABDLY: Darwin's TAB3
 * is OXTABS, not TAB1|TAB2. */
static const SttyBit sttyOBits[] = {
    STTY_BIT(OPOST, L_OPOST),
#ifdef OLCUC
    STTY_BIT(OLCUC, L_OLCUC),
#endif
    STTY_BIT(ONLCR, L_ONLCR), STTY_BIT(OCRNL, L_OCRNL), STTY_BIT(ONOCR, L_ONOCR),
    STTY_BIT(ONLRET, L_ONLRET),
#ifdef OFILL
    STTY_BIT(OFILL, L_OFILL),
#endif
#ifdef OFDEL
    STTY_BIT(OFDEL, L_OFDEL),
#endif
#ifdef NL1
    STTY_BIT(NL1, L_NL1),
#endif
#if defined(CR1) && defined(CR2)
    STTY_BIT(CR1, L_CR1), STTY_BIT(CR2, L_CR2),
#endif
#ifdef BS1
    STTY_BIT(BS1, L_BS1),
#endif
#ifdef VT1
    STTY_BIT(VT1, L_VT1),
#endif
#ifdef FF1
    STTY_BIT(FF1, L_FF1),
#endif
};

static const SttyBit sttyCBits[] = {
    STTY_BIT(CSTOPB, L_CSTOPB), STTY_BIT(CREAD, L_CREAD), STTY_BIT(PARENB, L_PARENB),
    STTY_BIT(PARODD, L_PARODD), STTY_BIT(HUPCL, L_HUPCL), STTY_BIT(CLOCAL, L_CLOCAL),
#ifdef CMSPAR
    STTY_BIT(CMSPAR, L_CMSPAR),
#endif
#ifdef CRTSCTS
    STTY_BIT(CRTSCTS, L_CRTSCTS),
#endif
};

static const SttyBit sttyLBits[] = {
    STTY_BIT(ISIG, L_ISIG), STTY_BIT(ICANON, L_ICANON),
#ifdef XCASE
    STTY_BIT(XCASE, L_XCASE),
#endif
    STTY_BIT(ECHO, L_ECHO), STTY_BIT(ECHOE, L_ECHOE), STTY_BIT(ECHOK, L_ECHOK),
    STTY_BIT(ECHONL, L_ECHONL), STTY_BIT(NOFLSH, L_NOFLSH), STTY_BIT(TOSTOP, L_TOSTOP),
#ifdef ECHOCTL
    STTY_BIT(ECHOCTL, L_ECHOCTL),
#endif
#ifdef ECHOPRT
    STTY_BIT(ECHOPRT, L_ECHOPRT),
#endif
#ifdef ECHOKE
    STTY_BIT(ECHOKE, L_ECHOKE),
#endif
#ifdef FLUSHO
    STTY_BIT(FLUSHO, L_FLUSHO),
#endif
#ifdef PENDIN
    STTY_BIT(PENDIN, L_PENDIN),
#endif
    STTY_BIT(IEXTEN, L_IEXTEN),
#ifdef EXTPROC
    STTY_BIT(EXTPROC, L_EXTPROC),
#endif
};

#define STTY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    int host;
    int linux_index;
} SttyCc;

static const SttyCc sttyCcMap[] = {
    {VINTR, L_VINTR}, {VQUIT, L_VQUIT}, {VERASE, L_VERASE}, {VKILL, L_VKILL},
    {VEOF, L_VEOF}, {VEOL, L_VEOL},
#ifdef VEOL2
    {VEOL2, L_VEOL2},
#endif
#ifdef VSWTC
    {VSWTC, L_VSWTC},
#endif
    {VSTART, L_VSTART}, {VSTOP, L_VSTOP}, {VSUSP, L_VSUSP},
#ifdef VREPRINT
    {VREPRINT, L_VREPRINT},
#endif
#ifdef VDISCARD
    {VDISCARD, L_VDISCARD},
#endif
#ifdef VWERASE
    {VWERASE, L_VWERASE},
#endif
#ifdef VLNEXT
    {VLNEXT, L_VLNEXT},
#endif
};

/* Baud rates in Linux's CBAUD order: codes 0-15, then CBAUDEX|1.. */
typedef struct {
    unsigned long baud;
    uint32_t code;
    speed_t host;
    bool haveHost;
} SttySpeed;

#define STTY_SPEED(b, c, h) {(b), (c), (h), true}
static const SttySpeed sttySpeeds[] = {
    STTY_SPEED(0, 0, B0), STTY_SPEED(50, 1, B50), STTY_SPEED(75, 2, B75),
    STTY_SPEED(110, 3, B110), STTY_SPEED(134, 4, B134), STTY_SPEED(150, 5, B150),
    STTY_SPEED(200, 6, B200), STTY_SPEED(300, 7, B300), STTY_SPEED(600, 8, B600),
    STTY_SPEED(1200, 9, B1200), STTY_SPEED(1800, 10, B1800), STTY_SPEED(2400, 11, B2400),
    STTY_SPEED(4800, 12, B4800), STTY_SPEED(9600, 13, B9600), STTY_SPEED(19200, 14, B19200),
    STTY_SPEED(38400, 15, B38400),
#ifdef B57600
    STTY_SPEED(57600, L_CBAUDEX | 1, B57600),
#endif
#ifdef B115200
    STTY_SPEED(115200, L_CBAUDEX | 2, B115200),
#endif
#ifdef B230400
    STTY_SPEED(230400, L_CBAUDEX | 3, B230400),
#endif
#ifdef B460800
    STTY_SPEED(460800, L_CBAUDEX | 4, B460800),
#endif
#ifdef B500000
    STTY_SPEED(500000, L_CBAUDEX | 5, B500000),
#endif
#ifdef B576000
    STTY_SPEED(576000, L_CBAUDEX | 6, B576000),
#endif
#ifdef B921600
    STTY_SPEED(921600, L_CBAUDEX | 7, B921600),
#endif
#ifdef B1000000
    STTY_SPEED(1000000, L_CBAUDEX | 8, B1000000),
#endif
#ifdef B1152000
    STTY_SPEED(1152000, L_CBAUDEX | 9, B1152000),
#endif
#ifdef B1500000
    STTY_SPEED(1500000, L_CBAUDEX | 10, B1500000),
#endif
#ifdef B2000000
    STTY_SPEED(2000000, L_CBAUDEX | 11, B2000000),
#endif
#ifdef B2500000
    STTY_SPEED(2500000, L_CBAUDEX | 12, B2500000),
#endif
#ifdef B3000000
    STTY_SPEED(3000000, L_CBAUDEX | 13, B3000000),
#endif
#ifdef B3500000
    STTY_SPEED(3500000, L_CBAUDEX | 14, B3500000),
#endif
#ifdef B4000000
    STTY_SPEED(4000000, L_CBAUDEX | 15, B4000000),
#endif
};

static const SttySpeed *sttySpeedByHost(speed_t s) {
    for (size_t i = 0; i < STTY_COUNT(sttySpeeds); i++)
        if (sttySpeeds[i].host == s) return &sttySpeeds[i];
    return NULL;
}

static const SttySpeed *sttySpeedByCode(uint32_t code) {
    for (size_t i = 0; i < STTY_COUNT(sttySpeeds); i++)
        if (sttySpeeds[i].code == code) return &sttySpeeds[i];
    return NULL;
}

static const SttySpeed *sttySpeedByBaud(unsigned long baud) {
    for (size_t i = 0; i < STTY_COUNT(sttySpeeds); i++)
        if (sttySpeeds[i].baud == baud) return &sttySpeeds[i];
    return NULL;
}

static uint32_t sttyBitsToLinux(unsigned long host, const SttyBit *map, size_t n) {
    uint32_t out = 0;
    for (size_t i = 0; i < n; i++)
        if ((host & map[i].host) == map[i].host && map[i].host != 0) out |= map[i].linux_value;
    return out;
}

static unsigned long sttyBitsToHost(uint32_t lin, unsigned long hostIn, const SttyBit *map, size_t n) {
    unsigned long out = hostIn;
    for (size_t i = 0; i < n; i++) out &= ~map[i].host;
    for (size_t i = 0; i < n; i++)
        if (lin & map[i].linux_value) out |= map[i].host;
    return out;
}

static void sttyFromHost(const struct termios *t, SttyMode *m) {
    memset(m, 0, sizeof(*m));
    m->iflag = sttyBitsToLinux(t->c_iflag, sttyIBits, STTY_COUNT(sttyIBits));
    m->oflag = sttyBitsToLinux(t->c_oflag, sttyOBits, STTY_COUNT(sttyOBits));
#ifdef TABDLY
    switch (t->c_oflag & TABDLY) {
        case TAB1: m->oflag |= L_TAB1; break;
        case TAB2: m->oflag |= L_TAB2; break;
        case TAB3: m->oflag |= L_TAB3; break;
        default: break;
    }
#endif
    m->cflag = sttyBitsToLinux(t->c_cflag, sttyCBits, STTY_COUNT(sttyCBits));
    switch (t->c_cflag & CSIZE) {
        case CS5: m->cflag |= L_CS5; break;
        case CS6: m->cflag |= L_CS6; break;
        case CS7: m->cflag |= L_CS7; break;
        default: m->cflag |= L_CS8; break;
    }
    const SttySpeed *sp = sttySpeedByHost(cfgetospeed(t));
    m->cflag |= sp ? sp->code : 15u;
    m->lflag = sttyBitsToLinux(t->c_lflag, sttyLBits, STTY_COUNT(sttyLBits));
#if defined(__linux__)
    m->line = t->c_line;
#endif
    for (size_t i = 0; i < STTY_COUNT(sttyCcMap); i++) {
        cc_t c = t->c_cc[sttyCcMap[i].host];
        m->cc[sttyCcMap[i].linux_index] = (c == _POSIX_VDISABLE) ? 0 : c;
    }
    m->cc[L_VMIN] = t->c_cc[VMIN];
    m->cc[L_VTIME] = t->c_cc[VTIME];
}

static void sttyToHost(const SttyMode *m, struct termios *t) {
    t->c_iflag = sttyBitsToHost(m->iflag, t->c_iflag, sttyIBits, STTY_COUNT(sttyIBits));
    t->c_oflag = sttyBitsToHost(m->oflag, t->c_oflag, sttyOBits, STTY_COUNT(sttyOBits));
#ifdef TABDLY
    t->c_oflag &= ~(unsigned long)TABDLY;
    switch (m->oflag & L_TABDLY) {
        case L_TAB1: t->c_oflag |= TAB1; break;
        case L_TAB2: t->c_oflag |= TAB2; break;
        case L_TAB3: t->c_oflag |= TAB3; break;
        default: t->c_oflag |= TAB0; break;
    }
#endif
    t->c_cflag = sttyBitsToHost(m->cflag, t->c_cflag, sttyCBits, STTY_COUNT(sttyCBits));
    t->c_cflag &= ~(unsigned long)CSIZE;
    switch (m->cflag & L_CSIZE) {
        case L_CS5: t->c_cflag |= CS5; break;
        case L_CS6: t->c_cflag |= CS6; break;
        case L_CS7: t->c_cflag |= CS7; break;
        default: t->c_cflag |= CS8; break;
    }
    const SttySpeed *sp = sttySpeedByCode(m->cflag & L_CBAUD);
    if (sp) {
        cfsetispeed(t, sp->host);
        cfsetospeed(t, sp->host);
    }
    t->c_lflag = sttyBitsToHost(m->lflag, t->c_lflag, sttyLBits, STTY_COUNT(sttyLBits));
#if defined(__linux__)
    t->c_line = m->line;
#endif
    for (size_t i = 0; i < STTY_COUNT(sttyCcMap); i++) {
        uint8_t c = m->cc[sttyCcMap[i].linux_index];
        t->c_cc[sttyCcMap[i].host] = (c == 0) ? _POSIX_VDISABLE : c;
    }
    t->c_cc[VMIN] = m->cc[L_VMIN];
    t->c_cc[VTIME] = m->cc[L_VTIME];
}

/* ------------------------------------------------------------------------ */
/* The guest's termios itself, where the host fronts a Linux tty             */

#if !defined(__linux__)
/* iSH-AOK runs SmallCLUE as Darwin code in front of a Linux guest's tty, and
 * its libc shim passes Linux's own TCGETS/TCSETSW through with the kernel's
 * struct termios. That carries every bit, including the ones Darwin's struct
 * has no field for (iuclc, olcuc, xcase, cmspar, swtch), so it is tried
 * first. A real Darwin kernel refuses the request and the termios path
 * above is used instead. */
#define STTY_TCGETS 0x5401
#define STTY_TCSETSW 0x5403

typedef struct {
    uint32_t iflag, oflag, cflag, lflag;
    uint8_t line;
    uint8_t cc[19];
} SttyKernelTermios;

static bool sttyKernelGet(int fd, SttyMode *m) {
    SttyKernelTermios k;
    memset(&k, 0, sizeof(k));
    if (ioctl(fd, STTY_TCGETS, &k) != 0) return false;
    memset(m, 0, sizeof(*m));
    m->iflag = k.iflag;
    m->oflag = k.oflag;
    m->cflag = k.cflag;
    m->lflag = k.lflag;
    m->line = k.line;
    memcpy(m->cc, k.cc, sizeof(k.cc));
    return true;
}

static bool sttyKernelSet(int fd, const SttyMode *m) {
    SttyKernelTermios k;
    memset(&k, 0, sizeof(k));
    k.iflag = m->iflag;
    k.oflag = m->oflag;
    k.cflag = m->cflag;
    k.lflag = m->lflag;
    k.line = m->line;
    memcpy(k.cc, m->cc, sizeof(k.cc));
    return ioctl(fd, STTY_TCSETSW, &k) == 0;
}
#endif

/* ------------------------------------------------------------------------ */
/* GNU's tables                                                              */

typedef enum { STTY_CONTROL, STTY_INPUT, STTY_OUTPUT, STTY_LOCAL, STTY_COMBINATION } SttyType;

#define STTY_SANE_SET 1
#define STTY_SANE_UNSET 2
#define STTY_REV 4
#define STTY_OMIT 8

typedef struct {
    const char *name;
    SttyType type;
    int flags;
    uint32_t bits;
    uint32_t mask;
} SttyModeInfo;

static const SttyModeInfo sttyModes[] = {
    {"parenb", STTY_CONTROL, STTY_REV, L_PARENB, 0},
    {"parodd", STTY_CONTROL, STTY_REV, L_PARODD, 0},
    {"cmspar", STTY_CONTROL, STTY_REV, L_CMSPAR, 0},
    {"cs5", STTY_CONTROL, 0, L_CS5, L_CSIZE},
    {"cs6", STTY_CONTROL, 0, L_CS6, L_CSIZE},
    {"cs7", STTY_CONTROL, 0, L_CS7, L_CSIZE},
    {"cs8", STTY_CONTROL, 0, L_CS8, L_CSIZE},
    {"hupcl", STTY_CONTROL, STTY_REV, L_HUPCL, 0},
    {"hup", STTY_CONTROL, STTY_REV | STTY_OMIT, L_HUPCL, 0},
    {"cstopb", STTY_CONTROL, STTY_REV, L_CSTOPB, 0},
    {"cread", STTY_CONTROL, STTY_SANE_SET | STTY_REV, L_CREAD, 0},
    {"clocal", STTY_CONTROL, STTY_REV, L_CLOCAL, 0},
    {"crtscts", STTY_CONTROL, STTY_REV, L_CRTSCTS, 0},

    {"ignbrk", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_IGNBRK, 0},
    {"brkint", STTY_INPUT, STTY_SANE_SET | STTY_REV, L_BRKINT, 0},
    {"ignpar", STTY_INPUT, STTY_REV, L_IGNPAR, 0},
    {"parmrk", STTY_INPUT, STTY_REV, L_PARMRK, 0},
    {"inpck", STTY_INPUT, STTY_REV, L_INPCK, 0},
    {"istrip", STTY_INPUT, STTY_REV, L_ISTRIP, 0},
    {"inlcr", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_INLCR, 0},
    {"igncr", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_IGNCR, 0},
    {"icrnl", STTY_INPUT, STTY_SANE_SET | STTY_REV, L_ICRNL, 0},
    {"ixon", STTY_INPUT, STTY_REV, L_IXON, 0},
    {"ixoff", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_IXOFF, 0},
    {"tandem", STTY_INPUT, STTY_REV | STTY_OMIT, L_IXOFF, 0},
    {"iuclc", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_IUCLC, 0},
    {"ixany", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_IXANY, 0},
    {"imaxbel", STTY_INPUT, STTY_SANE_SET | STTY_REV, L_IMAXBEL, 0},
    {"iutf8", STTY_INPUT, STTY_SANE_UNSET | STTY_REV, L_IUTF8, 0},

    {"opost", STTY_OUTPUT, STTY_SANE_SET | STTY_REV, L_OPOST, 0},
    {"olcuc", STTY_OUTPUT, STTY_SANE_UNSET | STTY_REV, L_OLCUC, 0},
    {"ocrnl", STTY_OUTPUT, STTY_SANE_UNSET | STTY_REV, L_OCRNL, 0},
    {"onlcr", STTY_OUTPUT, STTY_SANE_SET | STTY_REV, L_ONLCR, 0},
    {"onocr", STTY_OUTPUT, STTY_SANE_UNSET | STTY_REV, L_ONOCR, 0},
    {"onlret", STTY_OUTPUT, STTY_SANE_UNSET | STTY_REV, L_ONLRET, 0},
    {"ofill", STTY_OUTPUT, STTY_SANE_UNSET | STTY_REV, L_OFILL, 0},
    {"ofdel", STTY_OUTPUT, STTY_SANE_UNSET | STTY_REV, L_OFDEL, 0},
    {"nl1", STTY_OUTPUT, STTY_SANE_UNSET, L_NL1, L_NLDLY},
    {"nl0", STTY_OUTPUT, STTY_SANE_SET, 0, L_NLDLY},
    {"cr3", STTY_OUTPUT, STTY_SANE_UNSET, L_CR3, L_CRDLY},
    {"cr2", STTY_OUTPUT, STTY_SANE_UNSET, L_CR2, L_CRDLY},
    {"cr1", STTY_OUTPUT, STTY_SANE_UNSET, L_CR1, L_CRDLY},
    {"cr0", STTY_OUTPUT, STTY_SANE_SET, 0, L_CRDLY},
    {"tab3", STTY_OUTPUT, STTY_SANE_UNSET, L_TAB3, L_TABDLY},
    {"tab2", STTY_OUTPUT, STTY_SANE_UNSET, L_TAB2, L_TABDLY},
    {"tab1", STTY_OUTPUT, STTY_SANE_UNSET, L_TAB1, L_TABDLY},
    {"tab0", STTY_OUTPUT, STTY_SANE_SET, 0, L_TABDLY},
    {"bs1", STTY_OUTPUT, STTY_SANE_UNSET, L_BS1, L_BSDLY},
    {"bs0", STTY_OUTPUT, STTY_SANE_SET, 0, L_BSDLY},
    {"vt1", STTY_OUTPUT, STTY_SANE_UNSET, L_VT1, L_VTDLY},
    {"vt0", STTY_OUTPUT, STTY_SANE_SET, 0, L_VTDLY},
    {"ff1", STTY_OUTPUT, STTY_SANE_UNSET, L_FF1, L_FFDLY},
    {"ff0", STTY_OUTPUT, STTY_SANE_SET, 0, L_FFDLY},

    {"isig", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ISIG, 0},
    {"icanon", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ICANON, 0},
    {"iexten", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_IEXTEN, 0},
    {"echo", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ECHO, 0},
    {"echoe", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ECHOE, 0},
    {"crterase", STTY_LOCAL, STTY_REV | STTY_OMIT, L_ECHOE, 0},
    {"echok", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ECHOK, 0},
    {"echonl", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_ECHONL, 0},
    {"noflsh", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_NOFLSH, 0},
    {"xcase", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_XCASE, 0},
    {"tostop", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_TOSTOP, 0},
    {"echoprt", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_ECHOPRT, 0},
    {"prterase", STTY_LOCAL, STTY_REV | STTY_OMIT, L_ECHOPRT, 0},
    {"echoctl", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ECHOCTL, 0},
    {"ctlecho", STTY_LOCAL, STTY_REV | STTY_OMIT, L_ECHOCTL, 0},
    {"echoke", STTY_LOCAL, STTY_SANE_SET | STTY_REV, L_ECHOKE, 0},
    {"crtkill", STTY_LOCAL, STTY_REV | STTY_OMIT, L_ECHOKE, 0},
    {"flusho", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_FLUSHO, 0},
    {"extproc", STTY_LOCAL, STTY_SANE_UNSET | STTY_REV, L_EXTPROC, 0},

    {"evenp", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"parity", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"oddp", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"nl", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"ek", STTY_COMBINATION, STTY_OMIT, 0, 0},
    {"sane", STTY_COMBINATION, STTY_OMIT, 0, 0},
    {"cooked", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"raw", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"pass8", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"litout", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"cbreak", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"decctlq", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"tabs", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"lcase", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"LCASE", STTY_COMBINATION, STTY_REV | STTY_OMIT, 0, 0},
    {"crt", STTY_COMBINATION, STTY_OMIT, 0, 0},
    {"dec", STTY_COMBINATION, STTY_OMIT, 0, 0},
    {NULL, STTY_CONTROL, 0, 0, 0},
};

typedef struct {
    const char *name;
    uint8_t saneval;
    int index;
} SttyControlInfo;

static const SttyControlInfo sttyControls[] = {
    {"intr", 3, L_VINTR},       {"quit", 28, L_VQUIT},       {"erase", 127, L_VERASE},
    {"kill", 21, L_VKILL},      {"eof", 4, L_VEOF},          {"eol", 0, L_VEOL},
    {"eol2", 0, L_VEOL2},       {"swtch", 0, L_VSWTC},       {"start", 17, L_VSTART},
    {"stop", 19, L_VSTOP},      {"susp", 26, L_VSUSP},       {"rprnt", 18, L_VREPRINT},
    {"werase", 23, L_VWERASE},  {"lnext", 22, L_VLNEXT},     {"discard", 15, L_VDISCARD},
    /* These must be last: the displays stop at "min". */
    {"min", 1, L_VMIN},         {"time", 0, L_VTIME},
    {NULL, 0, 0},
};

static uint32_t *sttyModeWord(SttyMode *m, SttyType type) {
    switch (type) {
        case STTY_CONTROL: return &m->cflag;
        case STTY_INPUT: return &m->iflag;
        case STTY_OUTPUT: return &m->oflag;
        case STTY_LOCAL: return &m->lflag;
        default: return NULL;
    }
}

/* ------------------------------------------------------------------------ */
/* Output                                                                    */

typedef struct {
    int currentCol;
    int maxCol;
} SttyOut;

static void sttyWrapf(SttyOut *o, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len < 0) return;
    if (0 < o->currentCol) {
        if (o->maxCol - o->currentCol < len) {
            putchar('\n');
            o->currentCol = 0;
        } else {
            putchar(' ');
            o->currentCol++;
        }
    }
    fputs(buf, stdout);
    o->currentCol += len;
}

static const char *sttyVisible(uint8_t ch, char *buf) {
    char *p = buf;
    if (ch == 0) return "<undef>";
    if (ch >= 32) {
        if (ch < 127) {
            *p++ = (char)ch;
        } else if (ch == 127) {
            *p++ = '^';
            *p++ = '?';
        } else {
            *p++ = 'M';
            *p++ = '-';
            if (ch >= 128 + 32) {
                if (ch < 128 + 127) {
                    *p++ = (char)(ch - 128);
                } else {
                    *p++ = '^';
                    *p++ = '?';
                }
            } else {
                *p++ = '^';
                *p++ = (char)(ch - 128 + 64);
            }
        }
    } else {
        *p++ = '^';
        *p++ = (char)(ch + 64);
    }
    *p = '\0';
    return buf;
}

static void sttyDisplaySpeed(SttyOut *o, const SttyMode *m, bool fancy) {
    const SttySpeed *sp = sttySpeedByCode(m->cflag & L_CBAUD);
    unsigned long baud = sp ? sp->baud : 0;
    if (fancy)
        sttyWrapf(o, "speed %lu baud;", baud);
    else
        sttyWrapf(o, "%lu\n", baud);
    if (!fancy) o->currentCol = 0;
}

static int sttyScreenColumns(void) {
    struct winsize ws;
    /* stdout, as GNU: wrapping is for where the listing is going. */
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
    const char *s = getenv("COLUMNS");
    if (s && *s) {
        char *end = NULL;
        long n = strtol(s, &end, 0);
        if (end && *end == '\0' && n > 0 && n <= INT_MAX) return (int)n;
    }
    return 80;
}

static bool sttyGetWinsize(int fd, struct winsize *ws) {
    memset(ws, 0, sizeof(*ws));
    return ioctl(fd, TIOCGWINSZ, ws) == 0;
}

static void sttyDisplayAll(SttyOut *o, const SttyMode *m, int fd) {
    char vis[16];
    sttyDisplaySpeed(o, m, true);
    struct winsize ws;
    if (sttyGetWinsize(fd, &ws)) sttyWrapf(o, "rows %d; columns %d;", ws.ws_row, ws.ws_col);
    sttyWrapf(o, "line = %d;", m->line);
    putchar('\n');
    o->currentCol = 0;
    for (int i = 0; strcmp(sttyControls[i].name, "min") != 0; i++)
        sttyWrapf(o, "%s = %s;", sttyControls[i].name, sttyVisible(m->cc[sttyControls[i].index], vis));
    sttyWrapf(o, "min = %u; time = %u;", m->cc[L_VMIN], m->cc[L_VTIME]);
    if (o->currentCol != 0) putchar('\n');
    o->currentCol = 0;
    SttyType prev = STTY_CONTROL;
    SttyMode copy = *m;
    for (int i = 0; sttyModes[i].name; i++) {
        if (sttyModes[i].flags & STTY_OMIT) continue;
        if (sttyModes[i].type != prev) {
            putchar('\n');
            o->currentCol = 0;
            prev = sttyModes[i].type;
        }
        uint32_t *w = sttyModeWord(&copy, sttyModes[i].type);
        uint32_t mask = sttyModes[i].mask ? sttyModes[i].mask : sttyModes[i].bits;
        if ((*w & mask) == sttyModes[i].bits)
            sttyWrapf(o, "%s", sttyModes[i].name);
        else if (sttyModes[i].flags & STTY_REV)
            sttyWrapf(o, "-%s", sttyModes[i].name);
    }
    putchar('\n');
    o->currentCol = 0;
}

static void sttyDisplayChanged(SttyOut *o, const SttyMode *m) {
    char vis[16];
    sttyDisplaySpeed(o, m, true);
    sttyWrapf(o, "line = %d;", m->line);
    putchar('\n');
    o->currentCol = 0;
    bool emptyLine = true;
    for (int i = 0; strcmp(sttyControls[i].name, "min") != 0; i++) {
        if (m->cc[sttyControls[i].index] == sttyControls[i].saneval) continue;
        emptyLine = false;
        sttyWrapf(o, "%s = %s;", sttyControls[i].name, sttyVisible(m->cc[sttyControls[i].index], vis));
    }
    if ((m->lflag & L_ICANON) == 0)
        sttyWrapf(o, "min = %u; time = %u;\n", m->cc[L_VMIN], m->cc[L_VTIME]);
    else if (!emptyLine)
        putchar('\n');
    o->currentCol = 0;
    emptyLine = true;
    SttyType prev = STTY_CONTROL;
    SttyMode copy = *m;
    for (int i = 0; sttyModes[i].name; i++) {
        if (sttyModes[i].flags & STTY_OMIT) continue;
        if (sttyModes[i].type != prev) {
            if (!emptyLine) {
                putchar('\n');
                o->currentCol = 0;
                emptyLine = true;
            }
            prev = sttyModes[i].type;
        }
        uint32_t *w = sttyModeWord(&copy, sttyModes[i].type);
        uint32_t mask = sttyModes[i].mask ? sttyModes[i].mask : sttyModes[i].bits;
        if ((*w & mask) == sttyModes[i].bits) {
            if (sttyModes[i].flags & STTY_SANE_UNSET) {
                sttyWrapf(o, "%s", sttyModes[i].name);
                emptyLine = false;
            }
        } else if ((sttyModes[i].flags & (STTY_SANE_SET | STTY_REV)) == (STTY_SANE_SET | STTY_REV)) {
            sttyWrapf(o, "-%s", sttyModes[i].name);
            emptyLine = false;
        }
    }
    if (!emptyLine) putchar('\n');
    o->currentCol = 0;
}

static void sttyDisplaySave(const SttyMode *m) {
    printf("%lx:%lx:%lx:%lx", (unsigned long)m->iflag, (unsigned long)m->oflag,
           (unsigned long)m->cflag, (unsigned long)m->lflag);
    for (int i = 0; i < L_NCCS; i++) printf(":%lx", (unsigned long)m->cc[i]);
    putchar('\n');
}

/* ------------------------------------------------------------------------ */
/* Settings                                                                  */

static void sttySane(SttyMode *m) {
    for (int i = 0; sttyControls[i].name; i++) m->cc[sttyControls[i].index] = sttyControls[i].saneval;
    for (int i = 0; sttyModes[i].name; i++) {
        uint32_t *w = sttyModeWord(m, sttyModes[i].type);
        if (!w) continue;
        uint32_t mask = sttyModes[i].mask ? sttyModes[i].mask : sttyModes[i].bits;
        if (sttyModes[i].flags & STTY_SANE_SET)
            *w = (*w & ~mask) | sttyModes[i].bits;
        else if (sttyModes[i].flags & STTY_SANE_UNSET)
            *w = *w & ~mask & ~sttyModes[i].bits;
    }
}

static bool sttyCombination(SttyMode *m, const char *name, bool rev) {
    if (!strcmp(name, "evenp") || !strcmp(name, "parity")) {
        if (rev) m->cflag = (m->cflag & ~L_PARENB & ~L_CSIZE) | L_CS8;
        else m->cflag = (m->cflag & ~L_PARODD & ~L_CSIZE) | L_PARENB | L_CS7;
    } else if (!strcmp(name, "oddp")) {
        if (rev) m->cflag = (m->cflag & ~L_PARENB & ~L_CSIZE) | L_CS8;
        else m->cflag = (m->cflag & ~L_CSIZE) | L_CS7 | L_PARODD | L_PARENB;
    } else if (!strcmp(name, "nl")) {
        if (rev) {
            m->iflag = (m->iflag | L_ICRNL) & ~L_INLCR & ~L_IGNCR;
            m->oflag = (m->oflag | L_ONLCR) & ~L_OCRNL & ~L_ONLRET;
        } else {
            m->iflag &= ~L_ICRNL;
            m->oflag &= ~L_ONLCR;
        }
    } else if (!strcmp(name, "ek")) {
        m->cc[L_VERASE] = 127;
        m->cc[L_VKILL] = 21;
    } else if (!strcmp(name, "sane")) {
        sttySane(m);
    } else if (!strcmp(name, "cbreak")) {
        if (rev) m->lflag |= L_ICANON;
        else m->lflag &= ~L_ICANON;
    } else if (!strcmp(name, "pass8")) {
        if (rev) {
            m->cflag = (m->cflag & ~L_CSIZE) | L_CS7 | L_PARENB;
            m->iflag |= L_ISTRIP;
        } else {
            m->cflag = (m->cflag & ~L_PARENB & ~L_CSIZE) | L_CS8;
            m->iflag &= ~L_ISTRIP;
        }
    } else if (!strcmp(name, "litout")) {
        if (rev) {
            m->cflag = (m->cflag & ~L_CSIZE) | L_CS7 | L_PARENB;
            m->iflag |= L_ISTRIP;
            m->oflag |= L_OPOST;
        } else {
            m->cflag = (m->cflag & ~L_PARENB & ~L_CSIZE) | L_CS8;
            m->iflag &= ~L_ISTRIP;
            m->oflag &= ~L_OPOST;
        }
    } else if (!strcmp(name, "raw") || !strcmp(name, "cooked")) {
        if ((name[0] == 'r' && !rev) || (name[0] == 'c' && rev)) {
            m->iflag = 0;
            m->oflag &= ~L_OPOST;
            m->lflag &= ~(L_ISIG | L_ICANON | L_XCASE);
            m->cc[L_VMIN] = 1;
            m->cc[L_VTIME] = 0;
        } else {
            m->iflag |= L_BRKINT | L_IGNPAR | L_ISTRIP | L_ICRNL | L_IXON;
            m->oflag |= L_OPOST;
            m->lflag |= L_ISIG | L_ICANON;
        }
    } else if (!strcmp(name, "decctlq")) {
        /* GNU's reading: decctlq clears ixany, -decctlq sets it. */
        if (rev) m->iflag |= L_IXANY;
        else m->iflag &= ~L_IXANY;
    } else if (!strcmp(name, "tabs")) {
        if (rev) m->oflag = (m->oflag & ~L_TABDLY) | L_TAB3;
        else m->oflag = (m->oflag & ~L_TABDLY);
    } else if (!strcmp(name, "lcase") || !strcmp(name, "LCASE")) {
        if (rev) {
            m->lflag &= ~L_XCASE;
            m->iflag &= ~L_IUCLC;
            m->oflag &= ~L_OLCUC;
        } else {
            m->lflag |= L_XCASE;
            m->iflag |= L_IUCLC;
            m->oflag |= L_OLCUC;
        }
    } else if (!strcmp(name, "crt")) {
        m->lflag |= L_ECHOE | L_ECHOCTL | L_ECHOKE;
    } else if (!strcmp(name, "dec")) {
        m->cc[L_VINTR] = 3;
        m->cc[L_VERASE] = 127;
        m->cc[L_VKILL] = 21;
        m->lflag |= L_ECHOE | L_ECHOCTL | L_ECHOKE;
        m->iflag &= ~L_IXANY;
    } else {
        return false;
    }
    return true;
}

/* GNU's integer_arg: decimal, 0x hex or 0 octal, nothing trailing. */
static bool sttyParseNumber(const char *s, unsigned long max, unsigned long *out) {
    if (!s || !*s || *s == '-' || *s == '+') return false;
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 0);
    if (errno || !end || *end || v > max) return false;
    *out = v;
    return true;
}

/* GNU's integer_arg failure: not a number, or a number too large. */
static int sttyIntegerError(const char *s) {
    char *end = NULL;
    errno = 0;
    (void)strtoul(s, &end, 0);
    bool numeric = s && *s && *s != '-' && *s != '+' && end && *end == '\0';
    if (numeric)
        fprintf(stderr, "stty: invalid integer argument: '%s': Value too large for defined data type\n", s);
    else
        fprintf(stderr, "stty: invalid integer argument: '%s'\n", s);
    return 1;
}

/* A control character in any of GNU's spellings. */
static bool sttyParseControl(const char *arg, const char *name, uint8_t *out) {
    unsigned long v;
    if (!strcmp(name, "min") || !strcmp(name, "time")) {
        if (!sttyParseNumber(arg, 255, &v)) return false;
        *out = (uint8_t)v;
        return true;
    }
    if (arg[0] != '\0' && arg[1] == '\0') {
        *out = (uint8_t)arg[0];
        return true;
    }
    if (!strcmp(arg, "^-") || !strcmp(arg, "undef")) {
        *out = 0;
        return true;
    }
    if (arg[0] == '^' && arg[1] != '\0' && arg[2] == '\0') {
        if (arg[1] == '?') *out = 127;
        else *out = (uint8_t)(arg[1] & 037);
        return true;
    }
    if (!sttyParseNumber(arg, 255, &v)) return false;
    *out = (uint8_t)v;
    return true;
}

/* A `stty -g` string: four flag words and NCCS control characters. */
static bool sttyRecover(const char *arg, SttyMode *m) {
    if (!strchr(arg, ':')) return false;
    unsigned long vals[4 + L_NCCS];
    int n = 0;
    const char *p = arg;
    while (n < 4 + L_NCCS) {
        if (!isxdigit((unsigned char)*p)) return false;
        char *end = NULL;
        errno = 0;
        unsigned long v = strtoul(p, &end, 16);
        if (errno || end == p) return false;
        if (n >= 4 && v > 255) return false;
        if (n < 4 && v > 0xffffffffUL) return false;
        vals[n++] = v;
        p = end;
        if (n < 4 + L_NCCS) {
            if (*p != ':') return false;
            p++;
        }
    }
    if (*p != '\0') return false;
    m->iflag = (uint32_t)vals[0];
    m->oflag = (uint32_t)vals[1];
    m->cflag = (uint32_t)vals[2];
    m->lflag = (uint32_t)vals[3];
    for (int i = 0; i < L_NCCS; i++) m->cc[i] = (uint8_t)vals[4 + i];
    return true;
}

static void sttyUsage(FILE *fp) {
    fputs("Usage: stty [-F DEVICE | --file=DEVICE] [SETTING]...\n"
          "  or:  stty [-F DEVICE | --file=DEVICE] [-a|--all]\n"
          "  or:  stty [-F DEVICE | --file=DEVICE] [-g|--save]\n"
          "Print or change terminal characteristics (GNU stty compatible).\n"
          "  -a, --all     print all current settings in human-readable form\n"
          "  -g, --save    print all current settings in a stty-readable form\n"
          "  -F, --file=DEVICE  open and use DEVICE instead of stdin\n"
          "Settings: [-]flag names (icanon, echo, ixon, opost, ...), raw, cooked,\n"
          "sane, cbreak, evenp, oddp, nl, ek, pass8, litout, tabs, crt, dec,\n"
          "intr/quit/erase/kill/eof/eol/eol2/swtch/start/stop/susp/rprnt/werase/\n"
          "lnext/discard CHAR (^X, ^?, ^-, undef, or a number), min N, time N,\n"
          "rows N, cols N, size, speed, ispeed N, ospeed N, N, line N, and a saved\n"
          "-g string.\n",
          fp);
}

static int sttyInvalid(const char *arg) {
    fprintf(stderr, "stty: invalid argument '%s'\nTry 'stty --help' for more information.\n", arg);
    return 1;
}

static int sttyMissing(const char *arg) {
    fprintf(stderr, "stty: missing argument to '%s'\nTry 'stty --help' for more information.\n", arg);
    return 1;
}

static bool sttyModesEqual(const SttyMode *a, const SttyMode *b, const SttyMode *mask) {
    if ((a->iflag ^ b->iflag) & mask->iflag) return false;
    if ((a->oflag ^ b->oflag) & mask->oflag) return false;
    if ((a->cflag ^ b->cflag) & mask->cflag) return false;
    if ((a->lflag ^ b->lflag) & mask->lflag) return false;
    for (int i = 0; i < L_NCCS; i++)
        if ((a->cc[i] ^ b->cc[i]) & mask->cc[i]) return false;
    return true;
}

int smallclueSttyCommand(int argc, char **argv) {
    const char *deviceName = NULL;
    bool verboseOutput = false, recoverableOutput = false;
    int status = 0;
    int fd = STDIN_FILENO;
    bool openedFd = false;
    char **settings = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nsettings = 0;
    if (!settings) return 1;

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (!strcmp(arg, "--")) {
            for (i++; i < argc; i++) settings[nsettings++] = argv[i];
            break;
        }
        if (!strcmp(arg, "-a") || !strcmp(arg, "--all")) {
            verboseOutput = true;
        } else if (!strcmp(arg, "-g") || !strcmp(arg, "--save")) {
            recoverableOutput = true;
        } else if (!strcmp(arg, "-F") || !strcmp(arg, "--file")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "stty: option requires an argument -- 'F'\nTry 'stty --help' for more information.\n");
                free(settings);
                return 1;
            }
            deviceName = argv[++i];
        } else if (!strncmp(arg, "--file=", 7)) {
            deviceName = arg + 7;
        } else if (!strncmp(arg, "-F", 2) && arg[2]) {
            deviceName = arg + 2;
        } else if (!strcmp(arg, "--help")) {
            sttyUsage(stdout);
            free(settings);
            return 0;
        } else if (!strcmp(arg, "--version")) {
            puts("stty (SmallCLUE) 9.4 -- a GNU stty compatible implementation");
            free(settings);
            return 0;
        } else if (!strcmp(arg, "-ag") || !strcmp(arg, "-ga")) {
            verboseOutput = recoverableOutput = true;
        } else {
            settings[nsettings++] = arg;
        }
    }

    if (verboseOutput && recoverableOutput) {
        fprintf(stderr, "stty: the options for verbose and stty-readable output styles are\n"
                        "mutually exclusive\n");
        free(settings);
        return 1;
    }
    if ((verboseOutput || recoverableOutput) && nsettings > 0) {
        fprintf(stderr, "stty: when specifying an output style, modes may not be set\n");
        free(settings);
        return 1;
    }

    const char *label = "'standard input'";
    char labelBuf[PATH_MAX + 4];
    if (deviceName) {
        fd = open(deviceName, O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            fprintf(stderr, "stty: %s: %s\n", deviceName, strerror(errno));
            free(settings);
            return 1;
        }
        openedFd = true;
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        snprintf(labelBuf, sizeof(labelBuf), "%s", deviceName);
        label = labelBuf;
    }

    struct termios host;
    SttyMode mode;
    bool kernelPath = false;
#if !defined(__linux__)
    kernelPath = sttyKernelGet(fd, &mode);
#endif
    if (!kernelPath && tcgetattr(fd, &host) != 0) {
        int err = errno;
#if defined(PSCAL_TARGET_IOS)
        /* PSCAL's virtual terminal has no termios: report its size, as before. */
        if (!deviceName && !pscalRuntimeStdinHasRealTTY()) {
            struct winsize ws;
            int rows = 24, cols = 80;
            if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
                rows = ws.ws_row;
                cols = ws.ws_col;
            }
            if (nsettings == 0) printf("speed 38400 baud; rows %d; columns %d;\n", rows, cols);
            free(settings);
            return 0;
        }
#endif
        fprintf(stderr, "stty: %s: %s\n", label, strerror(err));
        if (openedFd) close(fd);
        free(settings);
        return 1;
    }
    if (!kernelPath) sttyFromHost(&host, &mode);

    SttyOut out = {0, 80};
    if (nsettings == 0) {
        out.maxCol = sttyScreenColumns();
        if (verboseOutput) sttyDisplayAll(&out, &mode, fd);
        else if (recoverableOutput) sttyDisplaySave(&mode);
        else sttyDisplayChanged(&out, &mode);
        fflush(stdout);
        if (openedFd) close(fd);
        free(settings);
        return 0;
    }

    SttyMode want = mode;
    SttyMode asked;
    memset(&asked, 0, sizeof(asked));
    bool changed = false;
    bool winChange = false, haveWin = false;
    struct winsize win;
    bool resetScreen = false, saneScreen = false;

    for (int k = 0; k < nsettings && status == 0; k++) {
        const char *arg = settings[k];
        bool rev = false;
        const char *name = arg;
        if (name[0] == '-') {
            rev = true;
            name++;
        }
        bool matched = false;
        for (int i = 0; sttyModes[i].name; i++) {
            if (strcmp(name, sttyModes[i].name) != 0) continue;
            matched = true;
            if (rev && !(sttyModes[i].flags & STTY_REV)) {
                status = sttyInvalid(arg);
                break;
            }
            if (sttyModes[i].type == STTY_COMBINATION) {
                SttyMode before = want;
                sttyCombination(&want, name, rev);
                asked.iflag |= before.iflag ^ want.iflag;
                asked.oflag |= before.oflag ^ want.oflag;
                asked.cflag |= before.cflag ^ want.cflag;
                asked.lflag |= before.lflag ^ want.lflag;
                for (int c = 0; c < L_NCCS; c++)
                    if (before.cc[c] != want.cc[c]) asked.cc[c] = 0xff;
                if (!strcmp(name, "sane")) saneScreen = true;
            } else {
                uint32_t *w = sttyModeWord(&want, sttyModes[i].type);
                uint32_t *a = sttyModeWord(&asked, sttyModes[i].type);
                uint32_t mask = sttyModes[i].mask ? sttyModes[i].mask : sttyModes[i].bits;
                if (rev) *w &= ~mask & ~sttyModes[i].bits;
                else *w = (*w & ~mask) | sttyModes[i].bits;
                *a |= mask | sttyModes[i].bits;
            }
            changed = true;
            break;
        }
        if (matched || status) continue;

        for (int i = 0; sttyControls[i].name; i++) {
            if (strcmp(arg, sttyControls[i].name) != 0) continue;
            matched = true;
            if (k + 1 >= nsettings) {
                status = sttyMissing(arg);
                break;
            }
            uint8_t v;
            if (!sttyParseControl(settings[k + 1], arg, &v)) {
                status = sttyIntegerError(settings[k + 1]);
                break;
            }
            want.cc[sttyControls[i].index] = v;
            asked.cc[sttyControls[i].index] = 0xff;
            k++;
            changed = true;
            break;
        }
        if (matched || status) continue;

        unsigned long num;
        if (!strcmp(arg, "ispeed") || !strcmp(arg, "ospeed")) {
            if (k + 1 >= nsettings) {
                status = sttyMissing(arg);
                break;
            }
            const SttySpeed *sp = sttyParseNumber(settings[k + 1], ULONG_MAX, &num) ? sttySpeedByBaud(num) : NULL;
            if (!sp) {
                status = sttyInvalid(settings[k + 1]);
                break;
            }
            /* One speed field in this model: Linux keeps input and output
             * together unless CIBAUD is used, and GNU sets both on Linux. */
            want.cflag = (want.cflag & ~L_CBAUD) | sp->code;
            asked.cflag |= L_CBAUD;
            k++;
            changed = true;
        } else if (!strcmp(arg, "line")) {
            if (k + 1 >= nsettings) {
                status = sttyMissing(arg);
                break;
            }
            if (!sttyParseNumber(settings[k + 1], 255, &num)) {
                status = sttyIntegerError(settings[k + 1]);
                break;
            }
            want.line = (uint8_t)num;
            k++;
            changed = true;
        } else if (!strcmp(arg, "rows") || !strcmp(arg, "cols") || !strcmp(arg, "columns")) {
            if (k + 1 >= nsettings) {
                status = sttyMissing(arg);
                break;
            }
            if (!sttyParseNumber(settings[k + 1], USHRT_MAX, &num)) {
                status = sttyIntegerError(settings[k + 1]);
                break;
            }
            if (!haveWin) {
                sttyGetWinsize(fd, &win);
                haveWin = true;
            }
            if (arg[0] == 'r') win.ws_row = (unsigned short)num;
            else win.ws_col = (unsigned short)num;
            winChange = true;
            k++;
        } else if (!strcmp(arg, "size")) {
            struct winsize ws;
            if (!sttyGetWinsize(fd, &ws)) {
                fprintf(stderr, "stty: %s: %s\n", label, strerror(errno));
                status = 1;
                break;
            }
            printf("%d %d\n", ws.ws_row, ws.ws_col);
        } else if (!strcmp(arg, "speed")) {
            sttyDisplaySpeed(&out, &mode, false);
        } else if (!strcmp(arg, "reset")) {
            /* Not GNU's: kept from SmallCLUE's earlier stty, a full terminal
             * reset (RIS). */
            resetScreen = true;
        } else if (sttyParseNumber(arg, ULONG_MAX, &num) && sttySpeedByBaud(num)) {
            const SttySpeed *sp = sttySpeedByBaud(num);
            want.cflag = (want.cflag & ~L_CBAUD) | sp->code;
            asked.cflag |= L_CBAUD;
            changed = true;
        } else if (sttyRecover(arg, &want)) {
            SttyMode all;
            memset(&all, 0xff, sizeof(all));
            asked = all;
            changed = true;
        } else {
            status = sttyInvalid(arg);
        }
    }

    if (status == 0 && changed) {
        bool setOk;
        if (kernelPath) {
#if !defined(__linux__)
            setOk = sttyKernelSet(fd, &want);
#else
            setOk = false;
#endif
        } else {
            struct termios set = host;
            sttyToHost(&want, &set);
            setOk = tcsetattr(fd, TCSADRAIN, &set) == 0;
        }
        if (!setOk) {
            fprintf(stderr, "stty: %s: %s\n", label, strerror(errno));
            status = 1;
        } else {
            SttyMode got;
            bool gotOk;
            if (kernelPath) {
#if !defined(__linux__)
                gotOk = sttyKernelGet(fd, &got);
#else
                gotOk = false;
#endif
            } else {
                struct termios back;
                gotOk = tcgetattr(fd, &back) == 0;
                if (gotOk) sttyFromHost(&back, &got);
            }
            if (!gotOk) {
                fprintf(stderr, "stty: %s: %s\n", label, strerror(errno));
                status = 1;
            } else {
                /* Compare what was asked for: a setting this host cannot
                 * carry (a Linux-only one on Darwin) comes back different
                 * and is reported, as GNU reports any that did not take. */
                SttyMode mask = asked;
                if (!sttyModesEqual(&want, &got, &mask)) {
                    fprintf(stderr, "stty: %s: unable to perform all requested operations\n", label);
                    status = 1;
                }
            }
        }
    }
    if (status == 0 && winChange) {
        if (ioctl(fd, TIOCSWINSZ, &win) != 0) {
            fprintf(stderr, "stty: %s: %s\n", label, strerror(errno));
            status = 1;
        }
    }
    if (status == 0 && resetScreen && isatty(STDOUT_FILENO)) {
        fputs("\x1b" "c", stdout);
    }
    if (status == 0 && saneScreen && isatty(STDOUT_FILENO)) {
        /* Also SmallCLUE's earlier `stty sane`: attributes, wrap and the
         * cursor back on. Only for a terminal, so a script's capture is
         * exactly GNU's (empty). */
        fputs("\x1b[0m\x1b[?7h\x1b[?25h", stdout);
    }
    fflush(stdout);
    if (openedFd) close(fd);
    free(settings);
    return status;
}
