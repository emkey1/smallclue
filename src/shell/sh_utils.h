#ifndef SMALLCLUE_SH_UTILS_H
#define SMALLCLUE_SH_UTILS_H

/* Minimal subset of PSCAL's core/utils.h needed by the vendored exsh
 * lexer/parser. Keeps the shell front-end free of any PSCAL dependency. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool decodeUtf8Codepoint(const char *text, size_t len, uint32_t *out_codepoint, size_t *out_advance);
bool isShellIdentifierStartCodepoint(uint32_t codepoint);
bool isShellIdentifierContinueCodepoint(uint32_t codepoint, bool allow_hash);
bool consumeShellIdentifier(const char *text, size_t len, size_t *out_advance, bool allow_hash);

#ifdef __cplusplus
}
#endif

#endif /* SMALLCLUE_SH_UTILS_H */
