#ifndef SHELL_QUOTE_MARKERS_H
#define SHELL_QUOTE_MARKERS_H

#define SHELL_QUOTE_MARK_SINGLE ((char)0x01)
#define SHELL_QUOTE_MARK_DOUBLE ((char)0x02)
/* Precedes a backslash-escaped character in word text so the expander can
 * treat it literally (upstream exsh loses this distinction; its VM runtime
 * never needed it, but the smallclue interpreter does -- e.g. "\$x" vs "$x"). */
#define SHELL_ESCAPE_MARK ((char)0x03)

#endif /* SHELL_QUOTE_MARKERS_H */
