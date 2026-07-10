/* Deep copy of exsh AST subtrees. Function definitions must outlive the
 * program that defined them, so `f() { ...; }` snapshots its body here. */

#include "sh_interp.h"

#include <stdlib.h>
#include <string.h>

ShellProgram *shCopyProgram(const ShellProgram *program);
static ShellCommand *copyCommand(const ShellCommand *command);

static ShellWord *copyWord(const ShellWord *word) {
    if (!word) {
        return NULL;
    }
    ShellWord *copy = shellCreateWord(word->text ? word->text : "",
                                      word->single_quoted, word->double_quoted,
                                      word->has_parameter_expansion,
                                      word->has_arithmetic_expansion,
                                      word->line, word->column);
    if (!copy) {
        return NULL;
    }
    copy->has_command_substitution = word->has_command_substitution;
    copy->is_assignment = word->is_assignment;
    for (size_t i = 0; i < word->expansions.count; ++i) {
        shellWordAddExpansion(copy, word->expansions.items[i]);
    }
    for (size_t i = 0; i < word->command_substitutions.count; ++i) {
        const ShellCommandSubstitution *cs = &word->command_substitutions.items[i];
        shellWordAddCommandSubstitution(copy, cs->style, cs->command, cs->span_length);
    }
    return copy;
}

static ShellRedirection *copyRedirection(const ShellRedirection *redir) {
    if (!redir) {
        return NULL;
    }
    ShellRedirection *copy = shellCreateRedirection(redir->type, redir->io_number,
                                                    copyWord(redir->target),
                                                    redir->line, redir->column);
    if (!copy) {
        return NULL;
    }
    if (redir->here_document) {
        shellRedirectionSetHereDocument(copy, redir->here_document, redir->here_document_quoted);
    }
    if (redir->here_string_literal) {
        shellRedirectionSetHereStringLiteral(copy, redir->here_string_literal);
    }
    if (redir->dup_target) {
        shellRedirectionSetDupTarget(copy, redir->dup_target);
    }
    return copy;
}

static void copyRedirectionsInto(ShellRedirectionArray *dst, const ShellRedirectionArray *src) {
    for (size_t i = 0; i < src->count; ++i) {
        ShellRedirection *r = copyRedirection(src->items[i]);
        if (!r) {
            continue;
        }
        if (dst->count + 1 > dst->capacity) {
            size_t cap = dst->capacity ? dst->capacity * 2 : 4;
            ShellRedirection **tmp =
                (ShellRedirection **)realloc(dst->items, cap * sizeof(*tmp));
            if (!tmp) {
                shellFreeRedirection(r);
                return;
            }
            dst->items = tmp;
            dst->capacity = cap;
        }
        dst->items[dst->count++] = r;
    }
}

static ShellPipeline *copyPipeline(const ShellPipeline *pipeline) {
    if (!pipeline) {
        return NULL;
    }
    ShellPipeline *copy = shellCreatePipeline();
    if (!copy) {
        return NULL;
    }
    for (size_t i = 0; i < pipeline->command_count; ++i) {
        ShellCommand *cmd = copyCommand(pipeline->commands[i]);
        if (cmd) {
            shellPipelineAddCommand(copy, cmd);
            shellPipelineSetMergeStderr(copy, i, shellPipelineGetMergeStderr(pipeline, i));
        }
    }
    shellPipelineSetNegated(copy, pipeline->negated);
    copy->has_explicit_negation = pipeline->has_explicit_negation;
    return copy;
}

static ShellLogicalList *copyLogical(const ShellLogicalList *logical) {
    if (!logical) {
        return NULL;
    }
    ShellLogicalList *copy = shellCreateLogicalList();
    if (!copy) {
        return NULL;
    }
    for (size_t i = 0; i < logical->count; ++i) {
        /* connectors[i] precedes pipelines[i]; index 0 is a placeholder. */
        shellLogicalListAdd(copy, copyPipeline(logical->pipelines[i]),
                            logical->connectors[i]);
    }
    return copy;
}

static ShellCommand *copyCommand(const ShellCommand *command) {
    if (!command) {
        return NULL;
    }
    ShellCommand *copy = NULL;
    switch (command->type) {
        case SHELL_COMMAND_SIMPLE: {
            copy = shellCreateSimpleCommand();
            if (!copy) {
                return NULL;
            }
            for (size_t i = 0; i < command->data.simple.words.count; ++i) {
                ShellWord *w = copyWord(command->data.simple.words.items[i]);
                if (w) {
                    shellCommandAddWord(copy, w);
                }
            }
            break;
        }
        case SHELL_COMMAND_ARITHMETIC:
            copy = shellCreateArithmeticCommand(
                command->data.arithmetic.expression ? strdup(command->data.arithmetic.expression)
                                                    : strdup(""));
            break;
        case SHELL_COMMAND_PIPELINE:
            copy = shellCreatePipelineCommand(copyPipeline(command->data.pipeline));
            break;
        case SHELL_COMMAND_LOGICAL:
            copy = shellCreateLogicalCommand(copyLogical(command->data.logical));
            break;
        case SHELL_COMMAND_SUBSHELL:
            copy = shellCreateSubshellCommand(shCopyProgram(command->data.subshell.body));
            break;
        case SHELL_COMMAND_BRACE_GROUP:
            copy = shellCreateBraceGroupCommand(shCopyProgram(command->data.brace_group.body));
            break;
        case SHELL_COMMAND_LOOP: {
            const ShellLoop *loop = command->data.loop;
            ShellLoop *loop_copy = NULL;
            if (loop->is_cstyle_for) {
                loop_copy = shellCreateCStyleForLoop(loop->cstyle_init, loop->cstyle_condition,
                                                     loop->cstyle_update,
                                                     shCopyProgram(loop->body));
            } else if (loop->is_for) {
                ShellWordArray values;
                memset(&values, 0, sizeof(values));
                for (size_t i = 0; i < loop->for_values.count; ++i) {
                    ShellWord *w = copyWord(loop->for_values.items[i]);
                    if (!w) {
                        continue;
                    }
                    if (values.count + 1 > values.capacity) {
                        size_t cap = values.capacity ? values.capacity * 2 : 4;
                        ShellWord **tmp = (ShellWord **)realloc(values.items, cap * sizeof(*tmp));
                        if (!tmp) {
                            shellFreeWord(w);
                            continue;
                        }
                        values.items = tmp;
                        values.capacity = cap;
                    }
                    values.items[values.count++] = w;
                }
                loop_copy = shellCreateForLoop(copyWord(loop->for_variable), &values,
                                               shCopyProgram(loop->body));
            } else {
                loop_copy = shellCreateLoop(loop->is_until, copyCommand(loop->condition),
                                            shCopyProgram(loop->body));
            }
            if (loop_copy) {
                copyRedirectionsInto(&loop_copy->redirections, &loop->redirections);
                copy = shellCreateLoopCommand(loop_copy);
            }
            break;
        }
        case SHELL_COMMAND_CONDITIONAL: {
            const ShellConditional *cond = command->data.conditional;
            copy = shellCreateConditionalCommand(
                shellCreateConditional(copyCommand(cond->condition),
                                       shCopyProgram(cond->then_branch),
                                       shCopyProgram(cond->else_branch)));
            break;
        }
        case SHELL_COMMAND_CASE: {
            const ShellCase *cs = command->data.case_stmt;
            ShellCase *cs_copy = shellCreateCase(copyWord(cs->subject));
            if (!cs_copy) {
                return NULL;
            }
            for (size_t i = 0; i < cs->clauses.count; ++i) {
                const ShellCaseClause *clause = cs->clauses.items[i];
                ShellCaseClause *clause_copy = shellCreateCaseClause(clause->line, clause->column);
                if (!clause_copy) {
                    continue;
                }
                for (size_t p = 0; p < clause->patterns.count; ++p) {
                    shellCaseClauseAddPattern(clause_copy, copyWord(clause->patterns.items[p]));
                }
                shellCaseClauseSetBody(clause_copy, shCopyProgram(clause->body));
                shellCaseAddClause(cs_copy, clause_copy);
            }
            copy = shellCreateCaseCommand(cs_copy);
            break;
        }
        case SHELL_COMMAND_FUNCTION: {
            const ShellFunction *fn = command->data.function;
            copy = shellCreateFunctionCommand(
                shellCreateFunction(fn->name, fn->parameter_metadata, shCopyProgram(fn->body)));
            break;
        }
    }
    if (!copy) {
        return NULL;
    }
    copy->exec = command->exec;
    copy->line = command->line;
    copy->column = command->column;
    copyRedirectionsInto(&copy->redirections, &command->redirections);
    return copy;
}

ShellProgram *shCopyProgram(const ShellProgram *program) {
    if (!program) {
        return NULL;
    }
    ShellProgram *copy = shellCreateProgram();
    if (!copy) {
        return NULL;
    }
    for (size_t i = 0; i < program->commands.count; ++i) {
        ShellCommand *cmd = copyCommand(program->commands.items[i]);
        if (cmd) {
            shellProgramAddCommand(copy, cmd);
        }
    }
    return copy;
}
