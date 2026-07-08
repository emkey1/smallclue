/*
 * Standalone printf(1) applet: POSIX sh scripts routinely call
 * /usr/bin/printf directly (rather than relying on a shell builtin), and
 * there was no equivalent applet at all before this.
 */

#include "printf_app.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Expands backslash escapes in an ARGUMENT string (used for %b): \n \t \\
 * \a \b \f \r \v plus \0NNN (octal, up to 3 digits) and \xHH (hex).
 * Returns a newly allocated string; caller frees. */
static char *smallcluePrintfExpandEscapes(const char *s) {
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < len; ++i) {
        if (s[i] == '\\' && i + 1 < len) {
            char c = s[i + 1];
            switch (c) {
                case 'n': out[o++] = '\n'; i++; continue;
                case 't': out[o++] = '\t'; i++; continue;
                case 'r': out[o++] = '\r'; i++; continue;
                case 'a': out[o++] = '\a'; i++; continue;
                case 'b': out[o++] = '\b'; i++; continue;
                case 'f': out[o++] = '\f'; i++; continue;
                case 'v': out[o++] = '\v'; i++; continue;
                case '\\': out[o++] = '\\'; i++; continue;
                case '"': out[o++] = '"'; i++; continue;
                case '0': {
                    int val = 0, digits = 0;
                    size_t j = i + 2;
                    while (j < len && digits < 3 && s[j] >= '0' && s[j] <= '7') {
                        val = val * 8 + (s[j] - '0');
                        j++; digits++;
                    }
                    out[o++] = (char)val;
                    i = j - 1;
                    continue;
                }
                case 'x': {
                    int val = 0, digits = 0;
                    size_t j = i + 2;
                    while (j < len && digits < 2 && isxdigit((unsigned char)s[j])) {
                        char hc = s[j];
                        int hv = (hc >= '0' && hc <= '9') ? hc - '0' : (tolower((unsigned char)hc) - 'a' + 10);
                        val = val * 16 + hv;
                        j++; digits++;
                    }
                    if (digits > 0) {
                        out[o++] = (char)val;
                        i = j - 1;
                        continue;
                    }
                    break;
                }
                default:
                    break;
            }
        }
        out[o++] = s[i];
    }
    out[o] = '\0';
    return out;
}

/* Processes one pass of the format string, consuming arguments from
 * args[*argIdx..argc) as %-directives are encountered, and interpreting
 * \n/\t/etc escapes in the format string itself as it goes. Returns true
 * if at least one %-conversion directive was present (used by the caller
 * to decide whether to loop the format again over remaining args,
 * matching POSIX printf's repeat-until-args-exhausted behavior). */
static bool smallcluePrintfRunOnce(const char *format, char **args, int argc, int *argIdx) {
    bool hadDirective = false;
    for (const char *p = format; *p; ++p) {
        if (*p == '\\' && p[1]) {
            switch (p[1]) {
                case 'n': putchar('\n'); p++; continue;
                case 't': putchar('\t'); p++; continue;
                case 'r': putchar('\r'); p++; continue;
                case 'a': putchar('\a'); p++; continue;
                case 'b': putchar('\b'); p++; continue;
                case 'f': putchar('\f'); p++; continue;
                case 'v': putchar('\v'); p++; continue;
                case '\\': putchar('\\'); p++; continue;
                default: break;
            }
        }
        if (*p != '%') {
            putchar(*p);
            continue;
        }
        p++;
        if (*p == '%') {
            putchar('%');
            continue;
        }
        if (*p == '\0') {
            putchar('%');
            break;
        }
        /* Copy the directive (flags/width/precision + conversion char)
         * into a small sub-format buffer, then let the real snprintf do
         * the formatting work (width/precision/flags all just work). */
        char spec[64];
        size_t specLen = 0;
        spec[specLen++] = '%';
        while (*p && strchr("-+ #0123456789.", *p) && specLen < sizeof(spec) - 2) {
            spec[specLen++] = *p++;
        }
        if (!*p) {
            spec[specLen] = '\0';
            fputs(spec, stdout);
            break;
        }
        char conv = *p;
        spec[specLen++] = conv;
        spec[specLen] = '\0';

        const char *arg = (*argIdx < argc) ? args[*argIdx] : "";
        if (*argIdx < argc) (*argIdx)++;
        hadDirective = true;

        char out[256];
        switch (conv) {
            case 'd': case 'i': {
                long long v = strtoll(arg, NULL, 10);
                char longSpec[68];
                snprintf(longSpec, sizeof(longSpec), "%.*sll%c", (int)specLen - 1, spec, 'd');
                snprintf(out, sizeof(out), longSpec, v);
                fputs(out, stdout);
                break;
            }
            case 'o': case 'u': case 'x': case 'X': {
                unsigned long long v = strtoull(arg, NULL, 0);
                char longSpec[68];
                snprintf(longSpec, sizeof(longSpec), "%.*sll%c", (int)specLen - 1, spec, conv);
                snprintf(out, sizeof(out), longSpec, v);
                fputs(out, stdout);
                break;
            }
            case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': {
                double v = strtod(arg, NULL);
                snprintf(out, sizeof(out), spec, v);
                fputs(out, stdout);
                break;
            }
            case 'c':
                printf(spec, arg[0]);
                break;
            case 's':
                printf(spec, arg);
                break;
            case 'b': {
                char *expanded = smallcluePrintfExpandEscapes(arg);
                if (expanded) {
                    fputs(expanded, stdout);
                    free(expanded);
                }
                break;
            }
            default:
                fputs(spec, stdout);
                break;
        }
    }
    return hadDirective;
}

int smallcluePrintfCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "printf: missing format string\n");
        return 1;
    }
    const char *format = argv[1];
    char **args = argv + 2;
    int nargs = argc - 2;

    int argIdx = 0;
    bool hadDirective = smallcluePrintfRunOnce(format, args, nargs, &argIdx);
    /* POSIX printf: if the format consumed at least one conversion
     * directive and there are still unconsumed arguments left, reapply
     * the whole format again from the start, repeating until arguments
     * run out. Guarded on hadDirective so a directive-less format (e.g.
     * just literal text) isn't looped forever. */
    while (hadDirective && argIdx < nargs) {
        hadDirective = smallcluePrintfRunOnce(format, args, nargs, &argIdx);
    }
    return 0;
}
