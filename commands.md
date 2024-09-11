# FA Command List
Below is the list of available commands:
- [label](#label)
- [add](#add)
- [add-offset-range](#add-offset-range)
- [align](#align)
- [argument](#argument)
- [b](#b)
- [clear](#clear)
- [deref-data](#deref-data)
- [find](#find)
- [find-bytes](#find-bytes)
- [find-bytes-ida](#find-bytes-ida)
- [find-immediate](#find-immediate)
- [find-str](#find-str)
- [function-end](#function-end)
- [function-lines](#function-lines)
- [function-start](#function-start)
- [goto-ref](#goto-ref)
- [if](#if)
- [if-not](#if-not)
- [intersect](#intersect)
- [keystone-find-opcodes](#keystone-find-opcodes)
- [keystone-verify-opcodes](#keystone-verify-opcodes)
- [load](#load)
- [locate](#locate)
- [make-code](#make-code)
- [make-comment](#make-comment)
- [make-function](#make-function)
- [make-literal](#make-literal)
- [make-unknown](#make-unknown)
- [max-xrefs](#max-xrefs)
- [min-xrefs](#min-xrefs)
- [most-common](#most-common)
- [next-instruction](#next-instruction)
- [offset](#offset)
- [operand](#operand)
- [print](#print)
- [python-if](#python-if)
- [run](#run)
- [set-const](#set-const)
- [set-enum](#set-enum)
- [set-name](#set-name)
- [set-struct-member](#set-struct-member)
- [set-type](#set-type)
- [single](#single)
- [sort](#sort)
- [stop-if-empty](#stop-if-empty)
- [store](#store)
- [symdiff](#symdiff)
- [trace](#trace)
- [union](#union)
- [unique](#unique)
- [verify-aligned](#verify-aligned)
- [verify-bytes](#verify-bytes)
- [verify-name](#verify-name)
- [verify-opcode](#verify-opcode)
- [verify-operand](#verify-operand)
- [verify-ref](#verify-ref)
- [verify-segment](#verify-segment)
- [verify-single](#verify-single)
- [verify-str](#verify-str)
- [xref](#xref)
- [xrefs-to](#xrefs-to)
## label
```
builtin interpreter command. mark a label
```
## add
```
usage: add [-h] value

add an hard-coded value into resultset

EXAMPLE:
    results = []
    -> add 80
    result = [80]

positional arguments:
  value

options:
  -h, --help  show this help message and exit
```
## add-offset-range
```
usage: add-offset-range [-h] start end step

adds a python-range to resultset

EXAMPLE:
    result = [0, 0x200]
    -> add-offset-range 0 4 8
    result = [0, 4, 8, 0x200, 0x204, 0x208]

positional arguments:
  start
  end
  step

options:
  -h, --help  show this help message and exit
```
## align
```
usage: align [-h] value

align results to given base (round-up)

EXAMPLE:
    results = [0, 2, 4, 6, 8]
    -> align 4
    results = [0, 4, 4, 8, 8]

positional arguments:
  value

options:
  -h, --help  show this help message and exit
```
## argument
```
usage: argument [-h] arg

get function's argument assignment address

EXAMPLE:
    0x00000000: ldr r0, =dest
    0x00000004: ldr r1, =src
    0x00000008: mov r2, #4
    0x0000000c: bl memcpy

    results = [0x0c]
    -> argument 2
    results = [8]  # address of 3rd argument

positional arguments:
  arg         argument number

options:
  -h, --help  show this help message and exit
```
## b
```
usage: b [-h] label

branch unconditionally to label

EXAMPLE:
    results = []

    add 1
    -> b skip
    add 2
    label skip
    add 3

    results = [1, 3]

positional arguments:
  label       label to jump to

options:
  -h, --help  show this help message and exit
```
## clear
```
usage: clear [-h]

clears the current result-set

EXAMPLE:
    results = [0, 4, 8]
    -> clear
    results = []

options:
  -h, --help  show this help message and exit
```
## deref-data
```
usage: deref-data [-h] -l LEN

Dereference pointer as integer data type. Note that the data is assumed to be stored in little endian format. Example #1: 0x00000000: LDR R1, [SP, #0x34] results = [0] -> deref-data -l 4 results = [0xe5d1034] Example #2: 0x00000000: LDR R1, [SP, #0x34] results = [0]
-> deref-data -l 2 results = [0x1034]

options:
  -h, --help         show this help message and exit
  -l LEN, --len LEN  length of the data in bytes
```
## find
```
usage: find [-h] name

find another symbol defined in other SIG files

positional arguments:
  name        symbol name

options:
  -h, --help  show this help message and exit
```
## find-bytes
```
usage: find-bytes [-h] hex_str

expands the result-set with the occurrences of the given bytes

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08

    results = []
    -> find-bytes 01020304
    result = [0]

    -> find-bytes 05060708
    results = [0, 4]

positional arguments:
  hex_str

options:
  -h, --help  show this help message and exit
```
## find-bytes-ida
```
usage: find-bytes-ida [-h] expression

expands the result-set with the occurrences of the given bytes
expression in "ida bytes syntax"

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08

    results = []
    -> find-bytes-ida '01 02 03 04'
    result = [0]

    -> find-bytes-ida '05 06 ?? 08'
    results = [0, 4]

positional arguments:
  expression

options:
  -h, --help  show this help message and exit
```
## find-immediate
```
usage: find-immediate [-h] expression

expands the result-set with the occurrences of the given
immediate in "ida immediate syntax"

EXAMPLE:
    0x00000000: ldr r0, =0x1234
    0x00000004: add r0, #2 ; 0x1236

    results = []
    -> find-immediate 0x1236
    result = [4]

positional arguments:
  expression

options:
  -h, --help  show this help message and exit
```
## find-str
```
usage: find-str [-h] [--null-terminated] hex_str

expands the result-set with the occurrences of the given
string

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08
    0x00000008: 30 31 32 33 -> ASCII '0123'

    results = []
    -> find-str '0123'

    result = [8]

positional arguments:
  hex_str

options:
  -h, --help         show this help message and exit
  --null-terminated
```
## function-end
```
usage: function-end [-h]

goto function's end

EXAMPLE:
    0x00000000: push {r4-r7, lr} -> function's prolog
    ...
    0x000000f0: push {r4-r7, pc} -> function's epilog

    results = [0]
    -> function-end
    result = [0xf0]

options:
  -h, --help  show this help message and exit
```
## function-lines
```
usage: function-lines [-h] [--after | --before]

get all function's lines

EXAMPLE:
    0x00000000: push {r4-r7, lr} -> function's prolog
    0x00000004: mov r1, r0
    ...
    0x000000c0: mov r0, r5
    ...
    0x000000f0: push {r4-r7, pc} -> function's epilog

    results = [0xc0]
    -> function-lines
    result = [0, 4, ..., 0xc0, ..., 0xf0]

options:
  -h, --help  show this help message and exit
  --after     include only function lines which occur after currentresultset
  --before    include only function lines which occur before current resultset
```
## function-start
```
usage: function-start [-h] [cmd ...]

goto function's start

EXAMPLE:
    0x00000000: push {r4-r7, lr} -> function's prolog
    ...
    0x000000f0: pop {r4-r7, pc} -> function's epilog

    results = [0xf0]
    -> function-start
    result = [0]

positional arguments:
  cmd         command

options:
  -h, --help  show this help message and exit
```
## goto-ref
```
usage: goto-ref [-h] [--code] [--data]

goto reference

EXAMPLE:
    0x00000000: ldr r0, =0x12345678

    results = [0]
    -> goto-ref --data
    results = [0x12345678]

options:
  -h, --help  show this help message and exit
  --code      include code references
  --data      include data references
```
## if
```
usage: if [-h] cond label

perform an 'if' statement to create conditional branches
using an FA command

EXAMPLE:
    results = [0, 4, 8]

    -> if 'verify-single' a_is_single_label

    set-name a_isnt_single
    b end

    label a_is_single_label
    set-name a_is_single

    label end

positional arguments:
  cond        condition as an FA command
  label       label to jump to if condition is true

options:
  -h, --help  show this help message and exit
```
## if-not
```
usage: if-not [-h] cond label

perform an 'if not' statement to create conditional branches
using an FA command

EXAMPLE:
    results = [0, 4, 8]

    -> if-not 'verify-single' a_is_single_label

    set-name a_is_single
    b end

    label a_is_not_single_label
    set-name a_is_not_single

    label end

positional arguments:
  cond        condition as an FA command
  label       label to jump to if condition is false

options:
  -h, --help  show this help message and exit
```
## intersect
```
usage: intersect [-h] [--piped] variables [variables ...]

intersect two or more variables

EXAMPLE:
    results = [0, 4, 8]
    store a
    ...
    results = [0, 12, 20]
    store b

    -> intersect a b
    results = [0]

positional arguments:
  variables    variable names

options:
  -h, --help   show this help message and exit
  --piped, -p
```
## keystone-find-opcodes
```
usage: keystone-find-opcodes [-h] [--bele] [--or] arch mode code

use keystone to search for the supplied opcodes

EXAMPLE:
    0x00000000: push {r4-r7, lr}
    0x00000004: mov r0, r1

    results = []
    -> keystone-find-opcodes --bele KS_ARCH_ARM KS_MODE_ARM 'mov r0, r1;'
    result = [4]

positional arguments:
  arch        keystone architecture const (evaled)
  mode        keystone mode const (evald)
  code        keystone architecture const (opcodes to compile)

options:
  -h, --help  show this help message and exit
  --bele      figure out the endianity from IDA instead of explicit mode
  --or        mandatory. expands search results
```
## keystone-verify-opcodes
```
usage: keystone-verify-opcodes [-h] [--bele] [--until UNTIL] arch mode code

use keystone to verify the result-set matches the given
opcodes

EXAMPLE:
    0x00000000: push {r4-r7, lr}
    0x00000004: mov r0, r1

    results = [0, 4]
    -> keystone-verify-opcodes --bele KS_ARCH_ARM KS_MODE_ARM 'mov r0, r1'
    result = [4]

positional arguments:
  arch           keystone architecture const (evaled)
  mode           keystone mode const (evald)
  code           keystone architecture const (opcodes to compile)

options:
  -h, --help     show this help message and exit
  --bele         figure out the endianity from IDA instead of explicit mode
  --until UNTIL  keep going onwards opcode-opcode until verified
```
## load
```
usage: load [-h] name

go back to previous result-set saved by 'store' command.

EXAMPLE:
    results = [0, 4, 8]
    store foo

    find-bytes 12345678
    results = [0, 4, 8, 10, 20]

    -> load foo
    results = [0, 4, 8]

positional arguments:
  name        name of variable in history to go back to

options:
  -h, --help  show this help message and exit
```
## locate
```
usage: locate [-h] name [name ...]

goto symbol by name

EXAMPLE:
    0x00000000: main:
    0x00000000:     mov r0, r1
    0x00000004: foo:
    0x00000004:     bx lr

    results = [0, 4]
    -> locate foo
    result = [4]

positional arguments:
  name

options:
  -h, --help  show this help message and exit
```
## make-code
```
usage: make-code [-h]

convert into a code block

options:
  -h, --help  show this help message and exit
```
## make-comment
```
usage: make-comment [-h] comment

add comment for given addresses

EXAMPLE:
    0x00000200: 01 02 03 04
    0x00000204: 30 31 32 33

    results = [0x200]
    -> make-comment 'bla bla'
    results = [0x200]

    0x00000200: 01 02 03 04 ; bla bla
    0x00000204: 30 31 32 33

positional arguments:
  comment     comment string

options:
  -h, --help  show this help message and exit
```
## make-function
```
usage: make-function [-h]

convert into a function

options:
  -h, --help  show this help message and exit
```
## make-literal
```
usage: make-literal [-h]

convert into a literal

options:
  -h, --help  show this help message and exit
```
## make-unknown
```
usage: make-unknown [-h]

convert into an unknown block

options:
  -h, --help  show this help message and exit
```
## max-xrefs
```
usage: max-xrefs [-h]

get the result with most xrefs pointing at it

options:
  -h, --help  show this help message and exit
```
## min-xrefs
```
usage: min-xrefs [-h]

get the result with least xrefs pointing at it

options:
  -h, --help  show this help message and exit
```
## most-common
```
usage: most-common [-h]

get the result appearing the most in the result-set

EXAMPLE:
    results = [0, 4, 4, 8, 12]
    -> most-common
    result = [4]

options:
  -h, --help  show this help message and exit
```
## next-instruction
```
usage: next-instruction [-h] [--limit LIMIT] [--back] [--op0 OP0] [--op1 OP1] [--op2 OP2] [--op3 OP3] [--op4 OP4] [--op5 OP5] mnem [mnem ...]

Map the resultset to the next instruction of a given pattern. The instruction is searched for linearly.

Example #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}
    0x0000000c: mov r2, r3
    
    results = [0, 4, 8]
    -> next-instruction mov
    results = [0, 4, 12]

Example #2:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}
    0x0000000c: mov r2, r3
    
    results = [0, 4, 8]
    -> next-instruction mov --op 2
    results = [12, 12, 12]

positional arguments:
  mnem

options:
  -h, --help     show this help message and exit
  --limit LIMIT  Number of instructions to search per address
  --back         Search backwards instead of forwards
  --op0 OP0
  --op1 OP1
  --op2 OP2
  --op3 OP3
  --op4 OP4
  --op5 OP5
```
## offset
```
usage: offset [-h] offset

advance the result-set by a given offset

EXAMPLE:
    results = [0, 4, 8, 12]
    -> offset 4
    result = [4, 8, 12, 16]

positional arguments:
  offset

options:
  -h, --help  show this help message and exit
```
## operand
```
usage: operand [-h] op

get operand value from given instruction

EXAMPLE #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [4]
    -> operand 1
    results = [2]  # because r2

positional arguments:
  op          operand number

options:
  -h, --help  show this help message and exit
```
## print
```
usage: print [-h] [phrase]

prints the current result-set (for debugging)

positional arguments:
  phrase      optional string

options:
  -h, --help  show this help message and exit
```
## python-if
```
usage: python-if [-h] cond label

perform an 'if' statement to create conditional branches
using an eval'ed expression

EXAMPLE:
    results = [0, 4, 8]

    verify-single
    store a

    # jump to a_is_single_label since a == []
    -> python-if a a_is_single_label
    set-name a_isnt_single
    b end

    label a_is_single_label
    set-name a_is_single

    label end

positional arguments:
  cond        condition to evaluate (being eval'ed)
  label       label to jump to if condition is true

options:
  -h, --help  show this help message and exit
```
## run
```
usage: run [-h] name

run another SIG file

positional arguments:
  name        SIG filename

options:
  -h, --help  show this help message and exit
```
## set-const
```
usage: set-const [-h] name

define a const value

positional arguments:
  name

options:
  -h, --help  show this help message and exit
```
## set-enum
```
usage: set-enum [-h] enum_name enum_key

define an enum value

positional arguments:
  enum_name
  enum_key

options:
  -h, --help  show this help message and exit
```
## set-name
```
usage: set-name [-h] name

set symbol name

positional arguments:
  name

options:
  -h, --help  show this help message and exit
```
## set-struct-member
```
usage: set-struct-member [-h] struct_name member_name member_type

add a struct member

positional arguments:
  struct_name
  member_name
  member_type

options:
  -h, --help   show this help message and exit
```
## set-type
```
usage: set-type [-h] type_str

sets the type in the disassembler

positional arguments:
  type_str

options:
  -h, --help  show this help message and exit
```
## single
```
usage: single [-h] index

peek a single result from the result-set (zero-based)

EXAMPLE:
    results = [0, 4, 8, 12]
    -> single 2
    result = [8]

positional arguments:
  index       result index

options:
  -h, --help  show this help message and exit
```
## sort
```
usage: sort [-h]

performs a sort on the current result-set

EXAMPLE:
    results = [4, 12, 0, 8]
    -> sort
    result = [0, 4, 8 ,12]

options:
  -h, --help  show this help message and exit
```
## stop-if-empty
```
usage: stop-if-empty [-h]

exit if current resultset is empty

EXAMPLE:
    results = []

    -> stop-if-empty
    add 1

    results = []

options:
  -h, --help  show this help message and exit
```
## store
```
usage: store [-h] name

save current result-set in a variable.
You can later load the result-set using 'load'

EXAMPLE:
    results = [0, 4, 8]
    -> store foo

    find-bytes --or 12345678
    results = [0, 4, 8, 10, 20]

    load foo
    results = [0, 4, 8]

positional arguments:
  name        name of variable to use

options:
  -h, --help  show this help message and exit
```
## symdiff
```
usage: symdiff [-h] variables [variables ...]

symmetric difference between two or more variables

EXAMPLE:
    results = [0, 4, 8]
    store a
    ...
    results = [0, 12, 20]
    store b

    -> symdiff a b
    results = [4, 8, 12, 20]

positional arguments:
  variables   variable names

options:
  -h, --help  show this help message and exit
```
## trace
```
usage: trace [-h]

sets a pdb breakpoint

options:
  -h, --help  show this help message and exit
```
## union
```
usage: union [-h] [--piped] variables [variables ...]

union two or more variables

EXAMPLE:
    results = [0, 4, 8]
    store a
    ...
    results = [0, 12, 20]
    store b

    -> union a b
    results = [0, 4, 8, 12, 20]

positional arguments:
  variables    variable names

options:
  -h, --help   show this help message and exit
  --piped, -p
```
## unique
```
usage: unique [-h]

make the resultset unique

EXAMPLE:
    results = [0, 4, 8, 8, 12]
    -> unique
    result = [0, 4, 8, 12]

options:
  -h, --help  show this help message and exit
```
## verify-aligned
```
usage: verify-aligned [-h] value

leave only results fitting required alignment

EXAMPLE:
    results = [0, 2, 4, 6, 8]
    -> verify-aligned 4
    results = [0, 4, 8]

positional arguments:
  value

options:
  -h, --help  show this help message and exit
```
## verify-bytes
```
usage: verify-bytes [-h] hex_str

reduce the result-set to those matching the given bytes

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08

    results = [0, 2, 4, 6, 8]
    -> verify-bytes '05 06 07 08'
    results = [4]

positional arguments:
  hex_str

options:
  -h, --help  show this help message and exit
```
## verify-name
```
usage: verify-name [-h] name

verifies the given name appears in result set

positional arguments:
  name

options:
  -h, --help  show this help message and exit
```
## verify-opcode
```
usage: verify-opcode [-h] [--op0 OP0] [--op1 OP1] [--op2 OP2] [--op3 OP3] [--op4 OP4] [--op5 OP5] mnem [mnem ...]

reduce the result-set to those matching the given instruction

EXAMPLE #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [0, 2, 4, 6, 8]
    -> verify-opcode mov
    results = [0, 4]

EXAMPLE #2:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [0, 2, 4, 6, 8]
    -> verify-opcode mov --op1 r2
    results = [4]

positional arguments:
  mnem

options:
  -h, --help  show this help message and exit
  --op0 OP0
  --op1 OP1
  --op2 OP2
  --op3 OP3
  --op4 OP4
  --op5 OP5
```
## verify-operand
```
usage: verify-operand [-h] [--op0 OP0] [--op1 OP1] [--op2 OP2] name

reduce the result-set to those matching the given instruction

EXAMPLE #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [0, 2, 4, 6, 8]
    -> verify-operand mov
    results = [0, 4]

EXAMPLE #2:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [0, 2, 4, 6, 8]
    -> verify-operand mov --op1 2
    results = [4]

positional arguments:
  name

options:
  -h, --help  show this help message and exit
  --op0 OP0
  --op1 OP1
  --op2 OP2
```
## verify-ref
```
usage: verify-ref [-h] [--code] [--data] [--name NAME]

verifies a given reference exists to current result set

options:
  -h, --help   show this help message and exit
  --code       include code references
  --data       include data references
  --name NAME  symbol name
```
## verify-segment
```
usage: verify-segment [-h] [--regex] name

reduce the result-set to those in the given segment name

EXAMPLE:
    .text:0x00000000 01 02 03 04
    .text:0x00000004 30 31 32 33

    .data:0x00000200 01 02 03 04
    .data:0x00000204 30 31 32 33

    results = [0, 0x200]
    -> verify-segment .data
    results = [0x200]

positional arguments:
  name        segment name

options:
  -h, --help  show this help message and exit
  --regex     interpret name as a regex
```
## verify-single
```
usage: verify-single [-h]

verifies the result-list contains a single value

EXAMPLE #1:
    results = [4, 12, 0, 8]
    -> verify-single
    result = []

EXAMPLE #2:
    results = [4]
    -> verify-single
    result = [4]

options:
  -h, --help  show this help message and exit
```
## verify-str
```
usage: verify-str [-h] [--null-terminated] hex_str

reduce the result-set to those matching the given string

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 30 31 32 33 -> ascii '0123'

    results = [0, 2, 4]
    -> verify-str '0123'
    results = [4]

positional arguments:
  hex_str

options:
  -h, --help         show this help message and exit
  --null-terminated
```
## xref
```
usage: xref [-h]

goto xrefs pointing at current search results

options:
  -h, --help  show this help message and exit
```
## xrefs-to
```
usage: xrefs-to [-h] [--function-start] [--or] [--and] [--name NAME] [--bytes BYTES]

search for xrefs pointing at given parameter

options:
  -h, --help        show this help message and exit
  --function-start  goto function prolog for each xref
  --or              expand the current result set
  --and             reduce the current result set
  --name NAME       parameter as label name
  --bytes BYTES     parameter as bytes
```
