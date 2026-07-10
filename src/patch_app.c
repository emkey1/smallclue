/*
 * patch applet: applies unified-diff patches (as produced by `diff -u` or
 * this project's own diff applet) to files -- a common step in build
 * recipes that patch source before compiling, and previously entirely
 * unavailable.
 *
 * Scope: unified diff format only (no context-diff "***"/plain-diff "c/a/d"
 * formats), single or multiple file sections per patch, -p N path-strip.
 * Context lines are verified strictly against the target file; a hunk
 * whose context doesn't match at the expected position is reported and
 * skipped (not applied) rather than attempting fuzzy/offset matching --
 * real patch(1)'s fuzz-search recovery is a further refinement this
 * doesn't attempt, but the common case (a patch generated against the
 * exact tree being patched) applies cleanly.
 */

#include "patch_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PATCH_PATH_MAX 4096

typedef struct {
    char **lines;
    size_t count;
    size_t capacity;
} PatchLineArray;

static bool patchLineArrayAppend(PatchLineArray *arr, const char *line) {
    if (arr->count == arr->capacity) {
        size_t newCap = arr->capacity ? arr->capacity * 2 : 64;
        char **resized = (char **)realloc(arr->lines, newCap * sizeof(char *));
        if (!resized) return false;
        arr->lines = resized;
        arr->capacity = newCap;
    }
    char *copy = strdup(line);
    if (!copy) return false;
    arr->lines[arr->count++] = copy;
    return true;
}

static void patchLineArrayFree(PatchLineArray *arr) {
    for (size_t i = 0; i < arr->count; ++i) {
        free(arr->lines[i]);
    }
    free(arr->lines);
    arr->lines = NULL;
    arr->count = arr->capacity = 0;
}

static bool patchReadFileLines(const char *path, PatchLineArray *out) {
    memset(out, 0, sizeof(*out));
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, fp)) >= 0) {
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        if (!patchLineArrayAppend(out, line)) {
            free(line);
            fclose(fp);
            return false;
        }
    }
    free(line);
    fclose(fp);
    return true;
}

typedef struct {
    char kind;    /* ' ', '-', '+' */
    char *text;   /* content, without the leading kind char */
} PatchHunkLine;

typedef struct {
    long oldStart, oldCount, newStart, newCount;
    PatchHunkLine *lines;
    size_t lineCount, lineCapacity;
} PatchHunk;

typedef struct {
    char *oldPath, *newPath;
    PatchHunk *hunks;
    size_t hunkCount, hunkCapacity;
} PatchFileSection;

static bool patchHunkAppendLine(PatchHunk *hunk, char kind, const char *text) {
    if (hunk->lineCount == hunk->lineCapacity) {
        size_t newCap = hunk->lineCapacity ? hunk->lineCapacity * 2 : 32;
        PatchHunkLine *resized = (PatchHunkLine *)realloc(hunk->lines, newCap * sizeof(PatchHunkLine));
        if (!resized) return false;
        hunk->lines = resized;
        hunk->lineCapacity = newCap;
    }
    hunk->lines[hunk->lineCount].kind = kind;
    hunk->lines[hunk->lineCount].text = strdup(text);
    if (!hunk->lines[hunk->lineCount].text) return false;
    hunk->lineCount++;
    return true;
}

static bool patchSectionAppendHunk(PatchFileSection *section, PatchHunk hunk) {
    if (section->hunkCount == section->hunkCapacity) {
        size_t newCap = section->hunkCapacity ? section->hunkCapacity * 2 : 8;
        PatchHunk *resized = (PatchHunk *)realloc(section->hunks, newCap * sizeof(PatchHunk));
        if (!resized) return false;
        section->hunks = resized;
        section->hunkCapacity = newCap;
    }
    section->hunks[section->hunkCount++] = hunk;
    return true;
}

static char *patchStripPath(const char *path, int stripCount) {
    const char *p = path;
    for (int i = 0; i < stripCount; ++i) {
        const char *slash = strchr(p, '/');
        if (!slash) break;
        p = slash + 1;
    }
    return strdup(p);
}

/* Parses "--- path\t(optional stuff)" / "+++ path..." header text (the
 * part after the 4-char marker), stripping any trailing tab-separated
 * timestamp/metadata real diff appends. */
static char *patchExtractHeaderPath(const char *line, int stripCount) {
    const char *start = line + 4;
    while (*start == ' ') start++;
    const char *end = start;
    while (*end && *end != '\t') end++;
    char buf[PATCH_PATH_MAX];
    size_t len = (size_t)(end - start);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, start, len);
    buf[len] = '\0';
    return patchStripPath(buf, stripCount);
}

static bool patchParseHunkHeader(const char *line, PatchHunk *hunk) {
    long oldStart, oldCount = 1, newStart, newCount = 1;
    if (sscanf(line, "@@ -%ld,%ld +%ld,%ld @@", &oldStart, &oldCount, &newStart, &newCount) == 4) {
        /* full form */
    } else if (sscanf(line, "@@ -%ld +%ld,%ld @@", &oldStart, &newStart, &newCount) == 3) {
        oldCount = 1;
    } else if (sscanf(line, "@@ -%ld,%ld +%ld @@", &oldStart, &oldCount, &newStart) == 3) {
        newCount = 1;
    } else if (sscanf(line, "@@ -%ld +%ld @@", &oldStart, &newStart) == 2) {
        oldCount = 1;
        newCount = 1;
    } else {
        return false;
    }
    memset(hunk, 0, sizeof(*hunk));
    hunk->oldStart = oldStart;
    hunk->oldCount = oldCount;
    hunk->newStart = newStart;
    hunk->newCount = newCount;
    return true;
}

static PatchFileSection *patchParseSections(PatchLineArray *patchLines, size_t *sectionCount, int stripCount) {
    PatchFileSection *sections = NULL;
    size_t count = 0, capacity = 0;
    size_t i = 0;
    while (i < patchLines->count) {
        if (strncmp(patchLines->lines[i], "--- ", 4) != 0) {
            i++;
            continue;
        }
        if (i + 1 >= patchLines->count || strncmp(patchLines->lines[i + 1], "+++ ", 4) != 0) {
            i++;
            continue;
        }
        if (count == capacity) {
            size_t newCap = capacity ? capacity * 2 : 4;
            PatchFileSection *resized = (PatchFileSection *)realloc(sections, newCap * sizeof(PatchFileSection));
            if (!resized) {
                free(sections);
                return NULL;
            }
            sections = resized;
            capacity = newCap;
        }
        PatchFileSection *section = &sections[count++];
        memset(section, 0, sizeof(*section));
        section->oldPath = patchExtractHeaderPath(patchLines->lines[i], stripCount);
        section->newPath = patchExtractHeaderPath(patchLines->lines[i + 1], stripCount);
        i += 2;

        while (i < patchLines->count && strncmp(patchLines->lines[i], "@@ ", 3) == 0) {
            PatchHunk hunk;
            if (!patchParseHunkHeader(patchLines->lines[i], &hunk)) {
                i++;
                continue;
            }
            i++;
            long remainingOld = hunk.oldCount;
            long remainingNew = hunk.newCount;
            while (i < patchLines->count && (remainingOld > 0 || remainingNew > 0)) {
                const char *l = patchLines->lines[i];
                char kind = l[0];
                if (kind == '\\') {
                    /* "\ No newline at end of file" -- ignore. */
                    i++;
                    continue;
                }
                if (kind != ' ' && kind != '-' && kind != '+') {
                    break;
                }
                if (!patchHunkAppendLine(&hunk, kind, l + 1)) {
                    return NULL;
                }
                if (kind == ' ') { remainingOld--; remainingNew--; }
                else if (kind == '-') { remainingOld--; }
                else { remainingNew--; }
                i++;
            }
            if (!patchSectionAppendHunk(section, hunk)) {
                return NULL;
            }
        }
    }
    *sectionCount = count;
    return sections;
}

static int smallcluePatchApplySection(PatchFileSection *section, const char *overridePath, bool verbose) {
    const char *targetPath = overridePath ? overridePath : section->newPath;
    PatchLineArray original;
    bool haveOriginal = patchReadFileLines(targetPath, &original);
    if (!haveOriginal) {
        memset(&original, 0, sizeof(original));
    }

    PatchLineArray output = {0};
    size_t cursor = 0; /* 0-based index into `original` */
    bool ok = true;

    for (size_t h = 0; h < section->hunkCount && ok; ++h) {
        PatchHunk *hunk = &section->hunks[h];
        size_t hunkStart0 = hunk->oldStart > 0 ? (size_t)(hunk->oldStart - 1) : 0;
        if (hunk->oldCount == 0) {
            /* Pure insertion at this position; oldStart still points at
             * the line to insert before (or count+1 style for EOF). */
        }
        if (hunkStart0 > original.count) {
            fprintf(stderr, "patch: %s: hunk #%zu out of range\n", targetPath, h + 1);
            ok = false;
            break;
        }
        while (cursor < hunkStart0) {
            if (!patchLineArrayAppend(&output, original.lines[cursor])) { ok = false; break; }
            cursor++;
        }
        if (!ok) break;

        for (size_t k = 0; k < hunk->lineCount; ++k) {
            PatchHunkLine *hl = &hunk->lines[k];
            if (hl->kind == ' ' || hl->kind == '-') {
                if (cursor >= original.count || strcmp(original.lines[cursor], hl->text) != 0) {
                    fprintf(stderr, "patch: %s: hunk #%zu FAILED (context mismatch at line %zu)\n",
                            targetPath, h + 1, cursor + 1);
                    ok = false;
                    break;
                }
                if (hl->kind == ' ') {
                    if (!patchLineArrayAppend(&output, hl->text)) { ok = false; break; }
                }
                cursor++;
            } else { /* '+' */
                if (!patchLineArrayAppend(&output, hl->text)) { ok = false; break; }
            }
        }
        if (verbose && ok) {
            printf("patching hunk #%zu of %s\n", h + 1, targetPath);
        }
    }

    if (ok) {
        while (cursor < original.count) {
            if (!patchLineArrayAppend(&output, original.lines[cursor])) { ok = false; break; }
            cursor++;
        }
    }

    if (ok) {
        char tmpPath[PATCH_PATH_MAX];
        snprintf(tmpPath, sizeof(tmpPath), "%s.patchtmp.XXXXXX", targetPath);
        int fd = mkstemp(tmpPath);
        if (fd < 0) {
            fprintf(stderr, "patch: %s: %s\n", tmpPath, strerror(errno));
            ok = false;
        } else {
            FILE *out = fdopen(fd, "w");
            for (size_t i = 0; i < output.count; ++i) {
                fprintf(out, "%s\n", output.lines[i]);
            }
            fclose(out);
            if (rename(tmpPath, targetPath) != 0) {
                fprintf(stderr, "patch: %s: %s\n", targetPath, strerror(errno));
                unlink(tmpPath);
                ok = false;
            } else if (verbose) {
                printf("patched %s\n", targetPath);
            }
        }
    }

    patchLineArrayFree(&original);
    patchLineArrayFree(&output);
    return ok ? 0 : 1;
}

int smallcluePatchCommand(int argc, char **argv) {
    int stripCount = 1; /* GNU patch's own default is 0, but 1 matches the
                          * overwhelmingly common "a/file" "b/file" prefix
                          * that `diff -u` / `git diff` / this project's
                          * own diff applet don't add, and that most
                          * vendored source patches DO include. */
    const char *patchFilePath = NULL;
    const char *overridePath = NULL;
    bool verbose = false;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-p") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "patch: -p requires a number\n");
                return 1;
            }
            stripCount = atoi(argv[++argi]);
        } else if (strncmp(arg, "-p", 2) == 0 && arg[2] != '\0') {
            stripCount = atoi(arg + 2);
        } else if (strcmp(arg, "-i") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "patch: -i requires a file\n");
                return 1;
            }
            patchFilePath = argv[++argi];
        } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            verbose = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "patch: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (argi < argc) {
        overridePath = argv[argi++];
    }

    PatchLineArray patchLines;
    bool ok;
    if (patchFilePath) {
        ok = patchReadFileLines(patchFilePath, &patchLines);
    } else {
        memset(&patchLines, 0, sizeof(patchLines));
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        ok = true;
        while ((len = getline(&line, &cap, stdin)) >= 0) {
            if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
            if (!patchLineArrayAppend(&patchLines, line)) { ok = false; break; }
        }
        free(line);
    }
    if (!ok) {
        fprintf(stderr, "patch: failed to read patch input\n");
        return 1;
    }

    size_t sectionCount = 0;
    PatchFileSection *sections = patchParseSections(&patchLines, &sectionCount, stripCount);
    patchLineArrayFree(&patchLines);
    if (!sections || sectionCount == 0) {
        fprintf(stderr, "patch: no valid unified-diff hunks found\n");
        free(sections);
        return 1;
    }

    int status = 0;
    for (size_t s = 0; s < sectionCount; ++s) {
        const char *target = (sectionCount == 1) ? overridePath : NULL;
        if (smallcluePatchApplySection(&sections[s], target, verbose) != 0) {
            status = 1;
        }
    }
    free(sections);
    return status;
}
