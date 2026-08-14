#!/bin/sh
# Behavioral test battery for the smallclue shell.
# Each case runs under both the reference shell and the smallclue shell;
# stdout + exit status must match.
#
# Usage: test_sh.sh /path/to/scsh [/path/to/reference-sh]

SCSH="${1:?usage: test_sh.sh /path/to/scsh [reference-sh]}"
REF="${2:-/bin/sh}"

pass=0
fail=0
failed_cases=""

check() {
    desc="$1"
    script="$2"
    ref_out=$(printf '%s' "$script" | "$REF" -s 2>/dev/null)
    ref_st=$?
    got_out=$(printf '%s' "$script" | "$SCSH" -s 2>/dev/null)
    got_st=$?
    if [ "$ref_out" = "$got_out" ] && [ "$ref_st" = "$got_st" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        failed_cases="$failed_cases
FAIL: $desc
  script:   $script
  expected: [$ref_out] (exit $ref_st)
  got:      [$got_out] (exit $got_st)"
    fi
}

# ---- words and quoting ----
check "plain echo" 'echo hello world'
check "single quotes" "echo 'a  b  c'"
check "double quotes" 'echo "a  b  c"'
check "mixed quotes" 'echo "it'"'"'s"'
check "escaped dollar" 'echo \$HOME'
check "escaped dollar in dquotes" 'x=5; echo "\$x is $x"'
check "empty string arg" 'set -- ""; echo $#'
check "concatenated quotes" 'echo "foo"bar'"'baz'"
check "backslash space" 'echo a\ b'

# ---- variables ----
check "assignment and use" 'x=hello; echo $x'
check "assignment with spaces in value" 'x="a b  c"; echo "$x"'
check "unquoted expansion splits" 'x="a b  c"; set -- $x; echo $#'
check "quoted expansion no split" 'x="a b  c"; set -- "$x"; echo $#'
check "default value unset" 'echo ${nosuch:-default}'
check "default value empty" 'x=; echo ${x:-default}'
check "default value dash only" 'x=; echo ${x-default}'
check "assign default" 'echo ${newvar:=assigned}; echo $newvar'
check "alternative value" 'x=set; echo ${x:+alt}'
check "alternative unset" 'echo ${nosuch:+alt}'
check "length" 'x=hello; echo ${#x}'
check "prefix strip shortest" 'x=a/b/c; echo ${x#*/}'
check "prefix strip longest" 'x=a/b/c; echo ${x##*/}'
check "suffix strip shortest" 'x=a/b/c; echo ${x%/*}'
check "suffix strip longest" 'x=a/b/c; echo ${x%%/*}'
check "unset builtin" 'x=1; unset x; echo ${x:-gone}'
check "readonly rejected" 'readonly r=1; r=2; echo $r'
check "export to child" 'export FOO=bar; '"$REF"' -c '"'"'echo $FOO'"'"''

# ---- positional / special params ----
check "positional params" 'set -- a b c; echo $1 $2 $3 $#'
check "shift" 'set -- a b c; shift; echo $1 $#'
check "shift 2" 'set -- a b c; shift 2; echo $1 $#'
check "dollar-star quoted" 'set -- a "b c"; for x in "$*"; do echo "[$x]"; done'
check "dollar-at quoted" 'set -- a "b c"; for x in "$@"; do echo "[$x]"; done'
check "dollar-at empty" 'set --; for x in "$@"; do echo "[$x]"; done; echo end'
check "IFS join star" 'IFS=:; set -- a b c; echo "$*"'
check "exit status" 'false; echo $?'
check "last status chain" 'true; false; echo $?'

# ---- arithmetic ----
check "basic arith" 'echo $((1 + 2))'
check "precedence" 'echo $((2 + 3 * 4))'
check "parens" 'echo $(((2 + 3) * 4))'
check "variables in arith" 'x=7; echo $((x * 2))'
check "dollar variables in arith" 'x=7; echo $(($x * 2))'
check "comparison" 'echo $((3 > 2))'
check "logical" 'echo $((1 && 0)) $((1 || 0))'
check "ternary" 'echo $((1 ? 10 : 20))'
check "assignment in arith" 'echo $((x = 5)) $x'
check "negative" 'echo $((-5 + 3))'
check "hex octal" 'echo $((0x10)) $((010))'
check "modulo division" 'echo $((17 % 5)) $((17 / 5))'
check "bitwise" 'echo $((5 & 3)) $((5 | 3)) $((5 ^ 3))'
check "shifts" 'echo $((1 << 4)) $((16 >> 2))'

# ---- command substitution ----
check "dollar paren" 'echo $(echo inner)'
check "backticks" 'echo `echo inner`'
check "nested" 'echo $(echo a $(echo b))'
check "in dquotes preserves ws" 'echo "$(printf "a  b")"'
check "strips trailing newlines" 'x=$(printf "abc\n\n\n"); echo "[$x]"'
check "subst exit status" 'x=$(false); echo $?'

# ---- control flow ----
check "if else" 'if false; then echo t; else echo f; fi'
check "elif" 'if false; then echo a; elif true; then echo b; else echo c; fi'
check "while loop" 'i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done'
check "until loop" 'i=0; until [ $i -ge 3 ]; do echo $i; i=$((i+1)); done'
check "for loop" 'for i in x y z; do echo $i; done'
check "for over params" 'set -- p q; for i; do echo $i; done'
check "break" 'for i in 1 2 3 4; do [ $i = 3 ] && break; echo $i; done'
check "continue" 'for i in 1 2 3; do [ $i = 2 ] && continue; echo $i; done'
check "break n" 'for i in 1 2; do for j in a b; do break 2; done; echo $i; done; echo out'
check "case basic" 'case abc in a*) echo starts-a;; *) echo other;; esac'
check "case multiple patterns" 'case xyz in a|b) echo ab;; x*|y*) echo xy;; esac'
check "case no match" 'case q in a) echo a;; b) echo b;; esac; echo after'
check "case question mark" 'case ab in a?) echo two;; esac'
check "nested if in while" 'i=0; while [ $i -lt 4 ]; do i=$((i+1)); if [ $i = 2 ]; then continue; fi; echo $i; done'

# ---- functions ----
check "function basic" 'f() { echo in-f; }; f'
check "function args" 'f() { echo $1 $2 $#; }; f a b'
check "function return" 'f() { return 3; }; f; echo $?'
check "function nested params restored" 'set -- outer; f() { echo $1; }; f inner; echo $1'
check "function local" 'x=global; f() { local x=local; echo $x; }; f; echo $x'
check "recursive function" 'f() { [ $1 -le 0 ] && return; echo $1; f $(($1 - 1)); }; f 3'
check "function overrides binary" 'true() { echo custom; }; true'

# ---- redirections ----
check "output redirect" 't=/tmp/scsh_test1.$$; echo data > $t; cat $t; rm -f $t'
check "append" 't=/tmp/scsh_test2.$$; echo a > $t; echo b >> $t; cat $t; rm -f $t'
check "input redirect" 't=/tmp/scsh_test3.$$; echo content > $t; cat < $t; rm -f $t'
check "stderr redirect" 'ls /definitely/no/such/dir 2>/dev/null; echo ok'
check "stderr to stdout" 'echo visible 2>&1'
check "fd close" 'exec 3>/dev/null; exec 3>&-; echo ok'
check "heredoc" 'cat <<EOF
line1
line2
EOF'
check "heredoc with expansion" 'x=world; cat <<EOF
hello $x
EOF'
check "heredoc quoted no expansion" 'x=world; cat <<"EOF"
hello $x
EOF'
check "heredoc dash strips tabs" 'cat <<-EOF
	indented
EOF'

# ---- pipelines ----
check "simple pipe" 'echo hello | cat'
check "multi pipe" 'printf "b\na\nc\n" | sort | head -1'
check "pipe exit status" 'true | false; echo $?'
check "negation" '! false; echo $?'
check "negation true" '! true; echo $?'
check "pipe to while read" 'printf "1\n2\n" | while read n; do echo "got $n"; done'

# ---- globbing ----
check "glob no match stays" 'echo /tmp/no_such_glob_*_xyz'
check "glob matches" 'd=/tmp/scsh_glob_fixed; rm -rf $d; mkdir -p $d; touch $d/a.txt $d/b.txt; echo $d/*.txt; rm -rf $d'
check "quoted glob no expand" 'echo "*"'
check "noglob option" 'set -f; echo *; set +f'

# ---- test builtin ----
check "test string eq" '[ abc = abc ]; echo $?'
check "test string ne" '[ abc != def ]; echo $?'
check "test numeric" '[ 5 -gt 3 ]; echo $?'
check "test -z -n" '[ -z "" ] && [ -n x ]; echo $?'
check "test file exists" '[ -e /dev/null ]; echo $?'
check "test dir" '[ -d /tmp ]; echo $?'
check "test not" '[ ! -e /no/such/file ]; echo $?'
check "test and" '[ 1 -eq 1 -a 2 -eq 2 ]; echo $?'
check "test or" '[ 1 -eq 2 -o 2 -eq 2 ]; echo $?'
check "test empty string false" '[ "" ]; echo $?'

# ---- builtins ----
check "cd and pwd" 'cd /tmp && pwd'
check "cd dash" 'cd /tmp; cd /; cd - >/dev/null; pwd'
check "eval" 'x="echo evaled"; eval $x'
check "eval builds vars" 'eval "y=42"; echo $y'
check "dot sourcing" 't=/tmp/scsh_src.$$; echo "sourced_var=99" > $t; . $t; echo $sourced_var; rm -f $t'
check "printf s" 'printf "%s-%s\n" a b'
check "printf d" 'printf "%03d\n" 7'
check "printf cycles" 'printf "%s\n" a b c'
check "printf escapes" 'printf "a\tb\n"'
check "read splits" 'echo "a b c" | { read x y; echo "[$x][$y]"; }'
check "read raw" 'printf "a,b\n" | { read -r v; printf "%s\n" "$v"; }'
check "true false" 'true; echo $?; false; echo $?'
check "colon" ': ignored args; echo $?'
check "type builtin" 'type cd >/dev/null 2>&1; echo $?'
check "command -v" 'command -v cd'
check "getopts" 'set -- -a -b arg; while getopts ab:c opt; do echo "opt=$opt arg=$OPTARG"; done'
check "umask" 'umask 022; umask'

# ---- set options ----
check "errexit" 'set -e; false; echo unreachable'
check "errexit condition ok" 'set -e; if false; then echo t; fi; echo ok'
check "errexit and-or ok" 'set -e; false || true; echo ok'
check "nounset" 'set -u; echo $undefined_var_xyz 2>/dev/null; echo unreachable'
check "noclobber" 't=/tmp/scsh_nc.$$; echo x > $t; set -C; echo y > $t 2>/dev/null; echo $?; cat $t; rm -f $t'

# ---- subshells / grouping ----
check "subshell var isolation" 'x=out; (x=in; echo $x); echo $x'
check "subshell cd isolation" 'cd /tmp; (cd /); pwd'
check "brace group shares scope" 'x=out; { x=in; }; echo $x'
check "subshell exit status" '(exit 5); echo $?'
check "group redirect" '{ echo a; echo b; } | wc -l | tr -d " "'

# ---- misc ----
check "exit code" 'exit 7'
check "tilde HOME" 'HOME=/tmp; echo ~'
check "comments" 'echo before # comment
echo after'
check "semicolons" 'echo a; echo b'
check "multiline string" 'x="line1
line2"; echo "$x"'
check "backslash newline" 'echo a\
b'
check "empty command sub" 'x=$(true); echo "[$x]"'
check "nested quotes in sub" 'echo "$(echo "inner quoted")"'
check "command not found status" 'no_such_command_xyz 2>/dev/null; echo $?'
check "wait for background" 'sleep 0.1 & wait; echo done'
check "background exit status" 'true & wait $!; echo $?'

echo ""
echo "======================================"
echo "PASS: $pass  FAIL: $fail"
if [ -n "$failed_cases" ]; then
    echo "$failed_cases"
    exit 1
fi
exit 0
