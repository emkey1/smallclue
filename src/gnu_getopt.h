/*
 * glibc's getopt_long, without its global state: short clusters ("-bl",
 * "-n5", "-n 5"), long options with unique-prefix abbreviation, "--name=v"
 * and "--name v", operands permuted to the end (unless POSIXLY_CORRECT) or,
 * with inOrder (glibc's leading '-'), returned as they come, "--" ending
 * the options, and glibc's exact messages. Each call keeps its
 * state in a GnuGetopt, so an applet run as a function call starts clean.
 * Compiled once, in gnu_util.c.
 */
#ifndef SMALLCLUE_GNU_GETOPT_H
#define SMALLCLUE_GNU_GETOPT_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { GNU_NO_ARG, GNU_REQ_ARG, GNU_OPT_ARG };

typedef struct {
    const char *name;
    int hasArg;
    int val;
} GnuLongOpt;

typedef struct {
    int argc;
    char **argv;
    const char *prog;          /* for messages */
    const char *shorts;        /* "bln:" -- ':' after a letter takes an argument; a
                                * leading '+' stops at the first operand, as glibc's */
    const GnuLongOpt *longs;   /* in the program's own order (ambiguity lists it) */
    size_t nlongs;
    int ind;
    const char *cluster;       /* the rest of a short cluster, or NULL */
    bool done;                 /* after "--", or at the first operand under POSIXLY_CORRECT */
    bool inOrder;              /* operands come back as option 1, in g->arg */
    const char *arg;           /* the current option's argument, or NULL */
    char **ops;                /* the operands, in order */
    int nops;
} GnuGetopt;

void gnuGetoptInit(GnuGetopt *g, int argc, char **argv, const char *prog, const char *shorts,
                                 const GnuLongOpt *longs, size_t nlongs);

static inline void gnuGetoptFree(GnuGetopt *g) {
    free(g->ops);
    g->ops = NULL;
}

int gnuGetoptLong(GnuGetopt *g, const char *body);

/* The next option's value; -1 when they are all read (operands in g->ops);
 * '?' after printing glibc's message for a bad one. */
int gnuGetopt(GnuGetopt *g);

#endif /* SMALLCLUE_GNU_GETOPT_H */
