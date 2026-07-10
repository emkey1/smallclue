/* Minimal raw-mode line editor for interactive use: cursor movement,
 * history (up/down + ~/.sh_history), kill/yank basics, and filename/applet
 * tab completion. Falls back to a plain read loop on non-ttys. */

#include "sh_interp.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define SH_HISTORY_MAX 500

static char *gHistory[SH_HISTORY_MAX];
static int gHistoryCount = 0;

#include "../smallclue.h"

void shLineEditAddHistory(const char *line) {
    if (!line || !*line) {
        return;
    }
    /* Skip immediate duplicates. */
    if (gHistoryCount > 0 && strcmp(gHistory[gHistoryCount - 1], line) == 0) {
        return;
    }
    if (gHistoryCount == SH_HISTORY_MAX) {
        free(gHistory[0]);
        memmove(gHistory, gHistory + 1, (SH_HISTORY_MAX - 1) * sizeof(char *));
        gHistoryCount--;
    }
    gHistory[gHistoryCount++] = strdup(line);
}

static char *historyFilePath(void) {
    const char *home = getenv("HOME");
    if (!home) {
        return NULL;
    }
    size_t len = strlen(home) + sizeof("/.sh_history") + 1;
    char *path = (char *)malloc(len);
    if (path) {
        snprintf(path, len, "%s/.sh_history", home);
    }
    return path;
}

void shLineEditLoadHistory(void) {
    char *path = historyFilePath();
    if (!path) {
        return;
    }
    FILE *f = fopen(path, "r");
    free(path);
    if (!f) {
        return;
    }
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len > 0) {
            shLineEditAddHistory(line);
        }
    }
    fclose(f);
}

void shLineEditSaveHistory(void) {
    char *path = historyFilePath();
    if (!path) {
        return;
    }
    FILE *f = fopen(path, "w");
    free(path);
    if (!f) {
        return;
    }
    for (int i = 0; i < gHistoryCount; ++i) {
        /* multi-line entries are stored joined by newline; write them raw */
        fprintf(f, "%s\n", gHistory[i]);
    }
    fclose(f);
}

/* ---- completion ------------------------------------------------------------- */

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} Completions;

static void completionsPush(Completions *c, const char *s) {
    if (c->count + 1 > c->capacity) {
        size_t cap = c->capacity ? c->capacity * 2 : 16;
        char **tmp = (char **)realloc(c->items, cap * sizeof(char *));
        if (!tmp) {
            return;
        }
        c->items = tmp;
        c->capacity = cap;
    }
    c->items[c->count++] = strdup(s);
}

static void completionsFree(Completions *c) {
    for (size_t i = 0; i < c->count; ++i) {
        free(c->items[i]);
    }
    free(c->items);
    memset(c, 0, sizeof(*c));
}

/* Complete the token at the end of `line` (first word: commands too). */
static void gatherCompletions(const char *token, bool first_word, Completions *out) {
    /* Filename completion. */
    const char *slash = strrchr(token, '/');
    char dirpath[4096];
    const char *prefix;
    if (slash) {
        size_t dlen = (size_t)(slash - token) + 1;
        if (dlen >= sizeof(dirpath)) {
            return;
        }
        memcpy(dirpath, token, dlen);
        dirpath[dlen] = '\0';
        prefix = slash + 1;
    } else {
        strcpy(dirpath, "./");
        prefix = token;
    }
    DIR *dir = opendir(slash ? dirpath : ".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.' && prefix[0] != '.') {
                continue;
            }
            if (strncmp(ent->d_name, prefix, strlen(prefix)) == 0) {
                char full[4600];
                snprintf(full, sizeof(full), "%s%s", slash ? dirpath : "", ent->d_name);
                completionsPush(out, full);
            }
        }
        closedir(dir);
    }
    /* Command-position: applet names too. */
    if (first_word && !slash) {
        size_t count = 0;
        const SmallclueApplet *applets = smallclueGetApplets(&count);
        for (size_t i = 0; applets && i < count; ++i) {
            if (strncmp(applets[i].name, token, strlen(token)) == 0) {
                completionsPush(out, applets[i].name);
            }
        }
    }
}

/* ---- raw mode editor ---------------------------------------------------------- */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    size_t cursor;
    const char *prompt;
    int history_index; /* gHistoryCount = live line */
    char *saved_live;
} EditState;

static void ensureCap(EditState *st, size_t need) {
    if (st->len + need + 1 > st->cap) {
        size_t cap = st->cap ? st->cap * 2 : 128;
        while (cap < st->len + need + 1) {
            cap *= 2;
        }
        char *tmp = (char *)realloc(st->buf, cap);
        if (!tmp) {
            return;
        }
        st->buf = tmp;
        st->cap = cap;
    }
}

static void redraw(EditState *st) {
    /* \r, prompt, buffer, clear to end, then reposition cursor. */
    fprintf(stderr, "\r\033[K%s%.*s", st->prompt, (int)st->len, st->buf);
    size_t tail = st->len - st->cursor;
    if (tail > 0) {
        fprintf(stderr, "\033[%zuD", tail);
    }
    fflush(stderr);
}

static void editInsert(EditState *st, const char *s, size_t n) {
    ensureCap(st, n);
    memmove(st->buf + st->cursor + n, st->buf + st->cursor, st->len - st->cursor);
    memcpy(st->buf + st->cursor, s, n);
    st->len += n;
    st->cursor += n;
}

static void loadHistoryEntry(EditState *st, int index) {
    if (index < 0 || index > gHistoryCount) {
        return;
    }
    if (st->history_index == gHistoryCount && index != gHistoryCount) {
        free(st->saved_live);
        st->saved_live = strndup(st->buf, st->len);
    }
    const char *entry;
    if (index == gHistoryCount) {
        entry = st->saved_live ? st->saved_live : "";
    } else {
        entry = gHistory[index];
    }
    st->len = 0;
    st->cursor = 0;
    ensureCap(st, strlen(entry));
    /* history entries may be multi-line; display newlines as spaces */
    for (const char *p = entry; *p; ++p) {
        char c = (*p == '\n') ? ' ' : *p;
        st->buf[st->len++] = c;
    }
    st->cursor = st->len;
    st->history_index = index;
}

static void tabComplete(EditState *st) {
    /* Find token start. */
    size_t start = st->cursor;
    while (start > 0 && !strchr(" \t;|&<>()", st->buf[start - 1])) {
        start--;
    }
    size_t tlen = st->cursor - start;
    char *token = strndup(st->buf + start, tlen);
    bool first_word = true;
    for (size_t i = 0; i < start; ++i) {
        if (!strchr(" \t", st->buf[i])) {
            first_word = strchr(";|&(", st->buf[i]) != NULL ? true : false;
            if (!first_word) {
                /* something precedes: only true again right after separators */
            }
        }
    }
    /* Simpler: first_word if all chars before token are blanks/separators. */
    first_word = true;
    for (size_t i = 0; i < start; ++i) {
        if (!strchr(" \t;|&(", st->buf[i])) {
            first_word = false;
            break;
        }
    }

    Completions comps = {0};
    gatherCompletions(token, first_word, &comps);
    if (comps.count == 1) {
        /* Complete fully; add slash for dirs, space otherwise. */
        const char *comp = comps.items[0];
        size_t clen = strlen(comp);
        if (clen > tlen) {
            editInsert(st, comp + tlen, clen - tlen);
        }
        struct stat stbuf;
        char pathbuf[4600];
        snprintf(pathbuf, sizeof(pathbuf), "%s", comp);
        if (stat(pathbuf, &stbuf) == 0 && S_ISDIR(stbuf.st_mode)) {
            editInsert(st, "/", 1);
        } else {
            editInsert(st, " ", 1);
        }
    } else if (comps.count > 1) {
        /* Extend to the longest common prefix; on repeat, list. */
        size_t common = strlen(comps.items[0]);
        for (size_t i = 1; i < comps.count; ++i) {
            size_t j = 0;
            while (j < common && comps.items[i][j] == comps.items[0][j]) {
                j++;
            }
            common = j;
        }
        if (common > tlen) {
            editInsert(st, comps.items[0] + tlen, common - tlen);
        } else {
            fprintf(stderr, "\n");
            for (size_t i = 0; i < comps.count; ++i) {
                fprintf(stderr, "%s  ", comps.items[i]);
            }
            fprintf(stderr, "\n");
        }
    }
    completionsFree(&comps);
    free(token);
    redraw(st);
}

char *shReadLineInteractive(ShInterp *interp, const char *prompt) {
    if (!isatty(STDIN_FILENO)) {
        /* Plain line read. */
        size_t cap = 256, len = 0;
        char *line = (char *)malloc(cap);
        if (!line) {
            return NULL;
        }
        for (;;) {
            char c;
            ssize_t r = read(STDIN_FILENO, &c, 1);
            if (r < 0 && errno == EINTR) {
                if (interp->got_sigint) {
                    free(line);
                    return NULL;
                }
                continue;
            }
            if (r <= 0) {
                if (len == 0) {
                    free(line);
                    return NULL;
                }
                break;
            }
            if (c == '\n') {
                break;
            }
            if (len + 2 > cap) {
                cap *= 2;
                char *tmp = (char *)realloc(line, cap);
                if (!tmp) {
                    free(line);
                    return NULL;
                }
                line = tmp;
            }
            line[len++] = c;
        }
        line[len] = '\0';
        return line;
    }

    struct termios orig, raw;
    if (tcgetattr(STDIN_FILENO, &orig) != 0) {
        return NULL;
    }
    raw = orig;
    raw.c_lflag &= ~(unsigned)(ECHO | ICANON);
    raw.c_iflag &= ~(unsigned)(IXON);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSADRAIN, &raw);

    EditState st;
    memset(&st, 0, sizeof(st));
    st.prompt = prompt ? prompt : "$ ";
    st.history_index = gHistoryCount;
    ensureCap(&st, 64);

    fprintf(stderr, "%s", st.prompt);
    fflush(stderr);

    char *result = NULL;
    bool done = false, eof = false;

    while (!done) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r < 0 && errno == EINTR) {
            if (interp->got_sigint) {
                fprintf(stderr, "^C\n");
                eof = false;
                st.len = 0;
                st.cursor = 0;
                free(st.buf);
                st.buf = NULL;
                st.cap = 0;
                tcsetattr(STDIN_FILENO, TCSADRAIN, &orig);
                free(st.saved_live);
                return NULL;
            }
            continue;
        }
        if (r <= 0) {
            eof = st.len == 0;
            done = true;
            break;
        }

        switch ((unsigned char)c) {
            case '\r':
            case '\n':
                fprintf(stderr, "\n");
                done = true;
                break;
            case 4: /* ^D */
                if (st.len == 0) {
                    eof = true;
                    done = true;
                } else if (st.cursor < st.len) {
                    memmove(st.buf + st.cursor, st.buf + st.cursor + 1,
                            st.len - st.cursor - 1);
                    st.len--;
                    redraw(&st);
                }
                break;
            case 127:
            case 8: /* backspace */
                if (st.cursor > 0) {
                    memmove(st.buf + st.cursor - 1, st.buf + st.cursor, st.len - st.cursor);
                    st.cursor--;
                    st.len--;
                    redraw(&st);
                }
                break;
            case 1: /* ^A */
                st.cursor = 0;
                redraw(&st);
                break;
            case 5: /* ^E */
                st.cursor = st.len;
                redraw(&st);
                break;
            case 2: /* ^B */
                if (st.cursor > 0) {
                    st.cursor--;
                    redraw(&st);
                }
                break;
            case 6: /* ^F */
                if (st.cursor < st.len) {
                    st.cursor++;
                    redraw(&st);
                }
                break;
            case 11: /* ^K */
                st.len = st.cursor;
                redraw(&st);
                break;
            case 21: /* ^U */
                memmove(st.buf, st.buf + st.cursor, st.len - st.cursor);
                st.len -= st.cursor;
                st.cursor = 0;
                redraw(&st);
                break;
            case 23: /* ^W: delete word */
                {
                    size_t end = st.cursor;
                    size_t begin = end;
                    while (begin > 0 && st.buf[begin - 1] == ' ') {
                        begin--;
                    }
                    while (begin > 0 && st.buf[begin - 1] != ' ') {
                        begin--;
                    }
                    memmove(st.buf + begin, st.buf + end, st.len - end);
                    st.len -= end - begin;
                    st.cursor = begin;
                    redraw(&st);
                }
                break;
            case 12: /* ^L */
                fprintf(stderr, "\033[H\033[2J");
                redraw(&st);
                break;
            case '\t':
                tabComplete(&st);
                break;
            case 27: { /* escape sequences */
                char seq[4];
                if (read(STDIN_FILENO, seq, 1) != 1) {
                    break;
                }
                if (seq[0] != '[' && seq[0] != 'O') {
                    break;
                }
                if (read(STDIN_FILENO, seq + 1, 1) != 1) {
                    break;
                }
                switch (seq[1]) {
                    case 'A': /* up */
                        if (st.history_index > 0) {
                            loadHistoryEntry(&st, st.history_index - 1);
                            redraw(&st);
                        }
                        break;
                    case 'B': /* down */
                        if (st.history_index < gHistoryCount) {
                            loadHistoryEntry(&st, st.history_index + 1);
                            redraw(&st);
                        }
                        break;
                    case 'C': /* right */
                        if (st.cursor < st.len) {
                            st.cursor++;
                            redraw(&st);
                        }
                        break;
                    case 'D': /* left */
                        if (st.cursor > 0) {
                            st.cursor--;
                            redraw(&st);
                        }
                        break;
                    case 'H':
                        st.cursor = 0;
                        redraw(&st);
                        break;
                    case 'F':
                        st.cursor = st.len;
                        redraw(&st);
                        break;
                    case '3': { /* delete */
                        char tilde;
                        if (read(STDIN_FILENO, &tilde, 1) == 1 && tilde == '~' &&
                            st.cursor < st.len) {
                            memmove(st.buf + st.cursor, st.buf + st.cursor + 1,
                                    st.len - st.cursor - 1);
                            st.len--;
                            redraw(&st);
                        }
                        break;
                    }
                    default:
                        break;
                }
                break;
            }
            default:
                if ((unsigned char)c >= 32 || c == '\t') {
                    editInsert(&st, &c, 1);
                    if (st.cursor == st.len) {
                        fputc(c, stderr);
                        fflush(stderr);
                    } else {
                        redraw(&st);
                    }
                }
                break;
        }
    }

    tcsetattr(STDIN_FILENO, TCSADRAIN, &orig);
    free(st.saved_live);

    if (eof) {
        free(st.buf);
        return NULL;
    }
    if (!st.buf) {
        return strdup("");
    }
    st.buf[st.len] = '\0';
    result = st.buf;
    return result;
}
