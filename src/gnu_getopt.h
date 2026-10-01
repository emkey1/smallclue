/*
 * glibc's getopt_long, without its global state: short clusters ("-bl",
 * "-n5", "-n 5"), long options with unique-prefix abbreviation, "--name=v"
 * and "--name v", operands permuted to the end (unless POSIXLY_CORRECT) or,
 * with inOrder (glibc's leading '-'), returned as they come, "--" ending
 * the options, and glibc's exact messages. Each call keeps its
 * state in a GnuGetopt, so an applet run as a function call starts clean.
 * Header-only and static.
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
    const char *shorts;        /* "bln:" -- ':' after a letter takes an argument */
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

static inline void gnuGetoptInit(GnuGetopt *g, int argc, char **argv, const char *prog, const char *shorts,
                                 const GnuLongOpt *longs, size_t nlongs) {
    memset(g, 0, sizeof(*g));
    g->argc = argc;
    g->argv = argv;
    g->prog = prog;
    g->shorts = shorts;
    g->longs = longs;
    g->nlongs = nlongs;
    g->ind = 1;
    g->ops = (char **)calloc((size_t)argc + 1, sizeof(char *));
}

static inline void gnuGetoptFree(GnuGetopt *g) {
    free(g->ops);
    g->ops = NULL;
}

static inline int gnuGetoptLong(GnuGetopt *g, const char *body) {
    const char *eq = strchr(body, '=');
    size_t len = eq ? (size_t)(eq - body) : strlen(body);
    const GnuLongOpt *found = NULL;
    bool ambiguous = false;
    for (size_t i = 0; i < g->nlongs; i++) {
        const GnuLongOpt *o = &g->longs[i];
        if (strncmp(o->name, body, len)) continue;
        if (strlen(o->name) == len) {
            found = o;
            ambiguous = false;
            break;
        }
        if (!found) found = o;
        else if (found->hasArg != o->hasArg || found->val != o->val) ambiguous = true;
    }
    if (ambiguous) {
        fprintf(stderr, "%s: option '--%s' is ambiguous; possibilities:", g->prog, body);
        for (size_t i = 0; i < g->nlongs; i++)
            if (!strncmp(g->longs[i].name, body, len)) fprintf(stderr, " '--%s'", g->longs[i].name);
        fputc('\n', stderr);
        return '?';
    }
    if (!found) {
        fprintf(stderr, "%s: unrecognized option '--%s'\n", g->prog, body);
        return '?';
    }
    g->arg = NULL;
    if (eq) {
        if (found->hasArg == GNU_NO_ARG) {
            fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n", g->prog, found->name);
            return '?';
        }
        g->arg = eq + 1;
    } else if (found->hasArg == GNU_REQ_ARG) {
        if (g->ind >= g->argc) {
            fprintf(stderr, "%s: option '--%s' requires an argument\n", g->prog, found->name);
            return '?';
        }
        g->arg = g->argv[g->ind++];
    }
    return found->val;
}

/* The next option's value; -1 when they are all read (operands in g->ops);
 * '?' after printing glibc's message for a bad one. */
static inline int gnuGetopt(GnuGetopt *g) {
    g->arg = NULL;
    if (!g->cluster) {
        for (;;) {
            if (g->ind >= g->argc) return -1;
            char *a = g->argv[g->ind++];
            if (g->done || a[0] != '-' || a[1] == '\0') {
                if (g->inOrder) {
                    g->arg = a;
                    return 1;
                }
                g->ops[g->nops++] = a;
                if (getenv("POSIXLY_CORRECT")) g->done = true;
                continue;
            }
            if (!strcmp(a, "--")) {
                g->done = true;
                continue;
            }
            if (a[1] == '-') return gnuGetoptLong(g, a + 2);
            g->cluster = a + 1;
            break;
        }
    }
    char c = *g->cluster++;
    const char *spec = c != ':' ? strchr(g->shorts, c) : NULL;
    if (!spec) {
        fprintf(stderr, "%s: invalid option -- '%c'\n", g->prog, c);
        if (!*g->cluster) g->cluster = NULL;
        return '?';
    }
    if (spec[1] == ':') {
        if (*g->cluster) {
            g->arg = g->cluster;
        } else if (spec[2] == ':') {
            g->arg = NULL;    /* optional: only when attached */
        } else if (g->ind < g->argc) {
            g->arg = g->argv[g->ind++];
        } else {
            fprintf(stderr, "%s: option requires an argument -- '%c'\n", g->prog, c);
            g->cluster = NULL;
            return '?';
        }
        g->cluster = NULL;
    } else if (!*g->cluster) {
        g->cluster = NULL;
    }
    return (unsigned char)c;
}

#endif /* SMALLCLUE_GNU_GETOPT_H */
