/* Vendored from PSCAL core/utils.c: the UTF-8 decoding and shell-identifier
 * scanning helpers the exsh lexer/parser rely on. */

#include "sh_utils.h"

#include <ctype.h>

bool decodeUtf8Codepoint(const char *text, size_t len, uint32_t *out_codepoint, size_t *out_advance) {
    if (!text || len == 0 || !out_codepoint || !out_advance) {
        return false;
    }

    unsigned char c0 = (unsigned char)text[0];
    if (c0 <= 0x7F) {
        *out_codepoint = c0;
        *out_advance = 1;
        return true;
    }

    if (c0 >= 0xC2 && c0 <= 0xDF) {
        if (len < 2) return false;
        unsigned char c1 = (unsigned char)text[1];
        if ((c1 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x1F) << 6) | (uint32_t)(c1 & 0x3F);
        *out_advance = 2;
        return true;
    }

    if (c0 == 0xE0) {
        if (len < 3) return false;
        unsigned char c1 = (unsigned char)text[1];
        unsigned char c2 = (unsigned char)text[2];
        if (c1 < 0xA0 || c1 > 0xBF || (c2 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x0F) << 12) |
                         ((uint32_t)(c1 & 0x3F) << 6) |
                         (uint32_t)(c2 & 0x3F);
        *out_advance = 3;
        return true;
    }

    if ((c0 >= 0xE1 && c0 <= 0xEC) || (c0 >= 0xEE && c0 <= 0xEF)) {
        if (len < 3) return false;
        unsigned char c1 = (unsigned char)text[1];
        unsigned char c2 = (unsigned char)text[2];
        if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x0F) << 12) |
                         ((uint32_t)(c1 & 0x3F) << 6) |
                         (uint32_t)(c2 & 0x3F);
        *out_advance = 3;
        return true;
    }

    if (c0 == 0xED) {
        if (len < 3) return false;
        unsigned char c1 = (unsigned char)text[1];
        unsigned char c2 = (unsigned char)text[2];
        if (c1 < 0x80 || c1 > 0x9F || (c2 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x0F) << 12) |
                         ((uint32_t)(c1 & 0x3F) << 6) |
                         (uint32_t)(c2 & 0x3F);
        *out_advance = 3;
        return true;
    }

    if (c0 == 0xF0) {
        if (len < 4) return false;
        unsigned char c1 = (unsigned char)text[1];
        unsigned char c2 = (unsigned char)text[2];
        unsigned char c3 = (unsigned char)text[3];
        if (c1 < 0x90 || c1 > 0xBF ||
            (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x07) << 18) |
                         ((uint32_t)(c1 & 0x3F) << 12) |
                         ((uint32_t)(c2 & 0x3F) << 6) |
                         (uint32_t)(c3 & 0x3F);
        *out_advance = 4;
        return true;
    }

    if (c0 >= 0xF1 && c0 <= 0xF3) {
        if (len < 4) return false;
        unsigned char c1 = (unsigned char)text[1];
        unsigned char c2 = (unsigned char)text[2];
        unsigned char c3 = (unsigned char)text[3];
        if ((c1 & 0xC0) != 0x80 ||
            (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x07) << 18) |
                         ((uint32_t)(c1 & 0x3F) << 12) |
                         ((uint32_t)(c2 & 0x3F) << 6) |
                         (uint32_t)(c3 & 0x3F);
        *out_advance = 4;
        return true;
    }

    if (c0 == 0xF4) {
        if (len < 4) return false;
        unsigned char c1 = (unsigned char)text[1];
        unsigned char c2 = (unsigned char)text[2];
        unsigned char c3 = (unsigned char)text[3];
        if (c1 < 0x80 || c1 > 0x8F ||
            (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) return false;
        *out_codepoint = ((uint32_t)(c0 & 0x07) << 18) |
                         ((uint32_t)(c1 & 0x3F) << 12) |
                         ((uint32_t)(c2 & 0x3F) << 6) |
                         (uint32_t)(c3 & 0x3F);
        *out_advance = 4;
        return true;
    }

    return false;
}

bool isShellIdentifierStartCodepoint(uint32_t codepoint) {
    if (codepoint == '_') {
        return true;
    }
    if (codepoint <= 0x7F) {
        return isalpha((unsigned char)codepoint) != 0;
    }
    return codepoint <= 0x10FFFF;
}

bool isShellIdentifierContinueCodepoint(uint32_t codepoint, bool allow_hash) {
    if (codepoint == '_') {
        return true;
    }
    if (allow_hash && codepoint == '#') {
        return true;
    }
    if (codepoint <= 0x7F) {
        return isalnum((unsigned char)codepoint) != 0;
    }
    return codepoint <= 0x10FFFF;
}

bool consumeShellIdentifier(const char *text, size_t len, size_t *out_advance, bool allow_hash) {
    if (out_advance) {
        *out_advance = 0;
    }
    if (!text || len == 0) {
        return false;
    }

    uint32_t codepoint = 0;
    size_t advance = 0;
    if (!decodeUtf8Codepoint(text, len, &codepoint, &advance) ||
        !isShellIdentifierStartCodepoint(codepoint)) {
        return false;
    }

    size_t consumed = advance;
    while (consumed < len) {
        if (!decodeUtf8Codepoint(text + consumed, len - consumed, &codepoint, &advance) ||
            !isShellIdentifierContinueCodepoint(codepoint, allow_hash)) {
            break;
        }
        consumed += advance;
    }

    if (out_advance) {
        *out_advance = consumed;
    }
    return true;
}
