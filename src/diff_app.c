/*
 * diff applet: unified-diff output between two files, via a classic
 * O(n*m) dynamic-programming LCS (longest common subsequence) rather than
 * a full Myers O(ND) implementation -- simpler and entirely sufficient for
 * the config-file/source-file sizes this is actually used on, at the cost
 * of using more memory/time on very large inputs than a proper Myers diff
 * would. Needed both to inspect changes directly and as the natural
 * prerequisite for `patch`.
 */

#include "diff_app.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    char **lines;
    size_t count;
    size_t capacity;
    bool finalNewline;
} DiffLineArray;

static bool diffLineArrayAppend(DiffLineArray *arr, const char *line, size_t len) {
    if (arr->count == arr->capacity) {
        size_t newCap = arr->capacity ? arr->capacity * 2 : 64;
        char **resized = (char **)realloc(arr->lines, newCap * sizeof(char *));
        if (!resized) return false;
        arr->lines = resized;
        arr->capacity = newCap;
    }
    char *copy = (char *)malloc(len + 1);
    if (!copy) return false;
    memcpy(copy, line, len);
    copy[len] = '\0';
    arr->lines[arr->count++] = copy;
    return true;
}

static void diffLineArrayFree(DiffLineArray *arr) {
    for (size_t i = 0; i < arr->count; ++i) {
        free(arr->lines[i]);
    }
    free(arr->lines);
    arr->lines = NULL;
    arr->count = arr->capacity = 0;
}

static bool diffReadLines(const char *path, DiffLineArray *out) {
    memset(out, 0, sizeof(*out));
    FILE *fp = (strcmp(path, "-") == 0) ? stdin : fopen(path, "rb");
    if (!fp) {
        return false;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    out->finalNewline = true;
    while ((len = getline(&line, &cap, fp)) >= 0) {
        bool hadNewline = (len > 0 && line[len - 1] == '\n');
        size_t contentLen = hadNewline ? (size_t)(len - 1) : (size_t)len;
        if (!diffLineArrayAppend(out, line, contentLen)) {
            free(line);
            if (fp != stdin) fclose(fp);
            return false;
        }
        out->finalNewline = hadNewline;
    }
    free(line);
    if (fp != stdin) fclose(fp);
    return true;
}

typedef enum { DIFF_OP_EQUAL, DIFF_OP_DELETE, DIFF_OP_INSERT } DiffOpType;

typedef struct {
    DiffOpType type;
    size_t aIndex; /* valid for EQUAL/DELETE */
    size_t bIndex; /* valid for EQUAL/INSERT */
} DiffOp;

/* Builds the LCS DP table and backtracks it into a straight-line edit
 * script (deletes before inserts at each divergence point, matching
 * conventional diff output ordering). */
static DiffOp *diffComputeEditScript(DiffLineArray *a, DiffLineArray *b, size_t *opCount) {
    size_t n = a->count, m = b->count;
    size_t *dp = (size_t *)calloc((n + 1) * (m + 1), sizeof(size_t));
    if (!dp) return NULL;
#define DP(i, j) dp[(i) * (m + 1) + (j)]
    for (size_t i = 1; i <= n; ++i) {
        for (size_t j = 1; j <= m; ++j) {
            if (strcmp(a->lines[i - 1], b->lines[j - 1]) == 0) {
                DP(i, j) = DP(i - 1, j - 1) + 1;
            } else {
                size_t up = DP(i - 1, j);
                size_t left = DP(i, j - 1);
                DP(i, j) = up > left ? up : left;
            }
        }
    }

    DiffOp *ops = (DiffOp *)malloc((n + m) * sizeof(DiffOp));
    if (!ops) {
        free(dp);
        return NULL;
    }
    size_t count = 0;
    size_t i = n, j = m;
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && strcmp(a->lines[i - 1], b->lines[j - 1]) == 0) {
            ops[count].type = DIFF_OP_EQUAL;
            ops[count].aIndex = i - 1;
            ops[count].bIndex = j - 1;
            count++;
            i--; j--;
        } else if (j > 0 && (i == 0 || DP(i, j - 1) >= DP(i - 1, j))) {
            ops[count].type = DIFF_OP_INSERT;
            ops[count].bIndex = j - 1;
            count++;
            j--;
        } else {
            ops[count].type = DIFF_OP_DELETE;
            ops[count].aIndex = i - 1;
            count++;
            i--;
        }
    }
#undef DP
    free(dp);

    /* Reverse (we built it backwards). */
    for (size_t k = 0; k < count / 2; ++k) {
        DiffOp tmp = ops[k];
        ops[k] = ops[count - 1 - k];
        ops[count - 1 - k] = tmp;
    }
    *opCount = count;
    return ops;
}

static void diffPrintHunk(DiffOp *ops, size_t start, size_t end, DiffLineArray *a, DiffLineArray *b) {
    /* Compute the 1-based start line/count for each side across this
     * hunk's op range. */
    size_t aStart = SIZE_MAX, bStart = SIZE_MAX, aCount = 0, bCount = 0;
    for (size_t k = start; k < end; ++k) {
        if (ops[k].type == DIFF_OP_EQUAL || ops[k].type == DIFF_OP_DELETE) {
            if (aStart == SIZE_MAX) aStart = ops[k].aIndex;
            aCount++;
        }
        if (ops[k].type == DIFF_OP_EQUAL || ops[k].type == DIFF_OP_INSERT) {
            if (bStart == SIZE_MAX) bStart = ops[k].bIndex;
            bCount++;
        }
    }
    if (aStart == SIZE_MAX) aStart = (start < end && end <= a->count) ? 0 : 0;
    if (bStart == SIZE_MAX) bStart = 0;

    printf("@@ -%zu,%zu +%zu,%zu @@\n",
           aCount ? aStart + 1 : aStart, aCount,
           bCount ? bStart + 1 : bStart, bCount);
    for (size_t k = start; k < end; ++k) {
        switch (ops[k].type) {
            case DIFF_OP_EQUAL:
                printf(" %s\n", a->lines[ops[k].aIndex]);
                break;
            case DIFF_OP_DELETE:
                printf("-%s\n", a->lines[ops[k].aIndex]);
                break;
            case DIFF_OP_INSERT:
                printf("+%s\n", b->lines[ops[k].bIndex]);
                break;
        }
    }
}

#define DIFF_CONTEXT_LINES 3

static bool diffPrintUnified(DiffOp *ops, size_t opCount, DiffLineArray *a, DiffLineArray *b,
                             const char *pathA, const char *pathB) {
    bool anyDiff = false;
    for (size_t k = 0; k < opCount; ++k) {
        if (ops[k].type != DIFF_OP_EQUAL) {
            anyDiff = true;
            break;
        }
    }
    if (!anyDiff) {
        return false;
    }

    printf("--- %s\n", pathA);
    printf("+++ %s\n", pathB);

    size_t k = 0;
    while (k < opCount) {
        if (ops[k].type == DIFF_OP_EQUAL) {
            k++;
            continue;
        }
        /* Start of a hunk: back up up to DIFF_CONTEXT_LINES of leading
         * context. */
        size_t hunkStart = k;
        size_t contextBack = 0;
        while (hunkStart > 0 && contextBack < DIFF_CONTEXT_LINES && ops[hunkStart - 1].type == DIFF_OP_EQUAL) {
            hunkStart--;
            contextBack++;
        }
        /* Extend through changes, merging in runs of equal context up to
         * 2*DIFF_CONTEXT_LINES (otherwise start a new hunk after enough
         * trailing context). */
        size_t hunkEnd = k;
        while (hunkEnd < opCount) {
            if (ops[hunkEnd].type != DIFF_OP_EQUAL) {
                hunkEnd++;
                continue;
            }
            size_t equalRun = 0;
            size_t probe = hunkEnd;
            while (probe < opCount && ops[probe].type == DIFF_OP_EQUAL) {
                probe++;
                equalRun++;
            }
            if (probe >= opCount || equalRun > DIFF_CONTEXT_LINES * 2) {
                hunkEnd += (equalRun < DIFF_CONTEXT_LINES) ? equalRun : DIFF_CONTEXT_LINES;
                break;
            }
            hunkEnd = probe;
        }
        diffPrintHunk(ops, hunkStart, hunkEnd, a, b);
        k = hunkEnd;
    }
    return true;
}

int smallclueDiffCommand(int argc, char **argv) {
    bool briefOnly = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-u") == 0) {
            /* unified is the only mode implemented; accept and ignore */
        } else if (strcmp(arg, "-q") == 0 || strcmp(arg, "--brief") == 0) {
            briefOnly = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "diff: unsupported option '%s'\n", arg);
            return 2;
        } else {
            break;
        }
    }
    if (argc - argi != 2) {
        fprintf(stderr, "usage: diff [-u] [-q] FILE1 FILE2\n");
        return 2;
    }
    const char *pathA = argv[argi];
    const char *pathB = argv[argi + 1];

    struct stat stA, stB;
    bool aIsDir = stat(pathA, &stA) == 0 && S_ISDIR(stA.st_mode);
    bool bIsDir = stat(pathB, &stB) == 0 && S_ISDIR(stB.st_mode);
    if (aIsDir || bIsDir) {
        fprintf(stderr, "diff: directory comparison is not supported\n");
        return 2;
    }

    DiffLineArray a, b;
    if (!diffReadLines(pathA, &a)) {
        fprintf(stderr, "diff: %s: cannot read\n", pathA);
        return 2;
    }
    if (!diffReadLines(pathB, &b)) {
        fprintf(stderr, "diff: %s: cannot read\n", pathB);
        diffLineArrayFree(&a);
        return 2;
    }

    size_t opCount = 0;
    DiffOp *ops = diffComputeEditScript(&a, &b, &opCount);
    if (!ops) {
        fprintf(stderr, "diff: out of memory\n");
        diffLineArrayFree(&a);
        diffLineArrayFree(&b);
        return 2;
    }

    bool differs;
    if (briefOnly) {
        differs = false;
        for (size_t k = 0; k < opCount; ++k) {
            if (ops[k].type != DIFF_OP_EQUAL) {
                differs = true;
                break;
            }
        }
        if (differs) {
            printf("Files %s and %s differ\n", pathA, pathB);
        }
    } else {
        differs = diffPrintUnified(ops, opCount, &a, &b, pathA, pathB);
    }

    free(ops);
    diffLineArrayFree(&a);
    diffLineArrayFree(&b);
    return differs ? 1 : 0;
}
