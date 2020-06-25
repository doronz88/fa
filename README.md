# FA

## What is it?

FA stands for Firmware Analysis and intended **For Humans**.

FA allows one to easily perform code exploration, symbol searching and 
other functionality with ease.

Usually such tasks would require you to understand complicated APIs,
write machine-dependant code and perform other tedious tasks.
FA is meant to replace the steps one usually performs like a robot 
(find X string, goto xref, find the next call function, ...) in 
a much friendlier and maintainable manner. 

The current codebase is very IDA-plugin-oriented. In the future I'll
consider adding compatibility for other disassemblers such as:
Ghidra, Radare and etc...


Pull Requests are of course more than welcome :smirk:.

## Requirements

Supported IDA 7.x.

In your IDA's python directory, run:

```sh
python -m pip install -r requirements.txt
```

And for testing:
```sh
python -m pip install -r requirements_testing.txt
```

## I wanna start using, but where do I start?

Before using, you should understand the terminology for: 
Projects, SIG files and Loaders.

So, grab a cup of coffee, listen to some [nice music](https://www.youtube.com/watch?v=5rrIx7yrxwQ), and please devote 
a few minutes of your time into reading this README.

### Projects

The "project" is kind of the namespace for different signatures.
For example, either: linux, linux_x86, linux_arm etc... are good 
project names that can be specified if you are working on either 
platforms. 

By dividing the signatures into such projects, Windows symbols for 
example won't be searched for Linux projects, which will result 
in a better directory organization layout, better performance and
less rate for false-positives. 

The signatures are located by default in the `signatures` directory.
If one wishes to use a different location, you may create `config.ini`
at FA's root with the following contents:

```ini
[global]
signatures_root = /a/b/c
```

### SIG format

The SIG format is a core feature of FA regarding symbol searching. Each
SIG file is residing within the project directory and is automatically searched
when requested to generate the project's symbol list.

The format is Hjson-based and is used to describe what you, 
**as a human**, would do in order to perform the given task (symbol searching
or binary exploration).

SIG syntax (single):
```hjson
{
    type: function/global/number # doesn't really have meaning
    name: name
    instructions : [
        # Available commands are listed below
        command1
        command2
    ]
}
```

Each line in the `instructions` list behaves like a shell
command-line that gets the previous results as the input 
and outputs the next results
to the next line.

Confused? That's alright :grinning:. [Just look at the examples below](#examples)

User may also use his own python script files to perform 
the search. Just create a new `.py` file in your project 
directory and implement the `run(**kwargs)` method. Also, the project's
path is appended to python's `sys.path` so you may import
your scripts from one another.

To view the list of available commands, [view the list below](#available-commands)

### Examples

#### Finding a global struct

```hjson
{
    type: global,
    name: g_awsome_global,
    instructions: [
            # find the byte sequence '11 22 33 44'
            find-bytes --or '11 22 33 44'

            # advance offset by 20
            offset 20

            # verify the current bytes are 'aa bb cc dd'
            verify-bytes 'aa bb cc dd'

            # go back by 20 bytes offset
            offset -20

            # set global name
            set-name g_awsome_global
	]
}
```

#### Find function by reference to string

```hjson
{
    type: function
    name: free
    instructions: [
            # search the string "free"
            find-str --or 'free' --null-terminated

            # goto xref
            xref

            # goto function's prolog
            function-start

            # reduce to the singletone with most xrefs to
            max-xrefs

            # set name and type
            set-name free
            set-type 'void free(void *block)'
	]
}
```

#### Performing code exploration

```hjson
{
    type: function-list
    name: arm-explorer
    instructions: [
            # search for some potential function prologs
            arm-find-all 'push {r4, lr}'
            arm-find-all 'push {r4, r5, lr}'
            thumb-find-all 'push {r4, lr}'
            thumb-find-all 'push {r4, r5, lr}'

            # convert into functions
            make-function
	]
}
```

#### Performing string exploration

```hjson
{
    type: explorer
    name: arm-string-explorer
    instructions: [
            # goto printf
            locate printf

            # iterate every xref
            xref

            # and for each, go word-word backwards
            add-offset-range 0 -40 -4

            # if ldr to r0
            verify-operand ldr --op0 r0

            # go to the global string
            goto-ref --data

            # and make it literal
            make-literal
	]
}
```

#### Finding several functions in a row

```hjson
{
    type: function
    name: cool_functions
    instructions: [
            # find string
            find-str --or 'init_stuff' --null-terminated

            # goto to xref
            xref
    
            # goto function start
            function-start

            # verify only one single result
            unique

            # iterating every 4-byte opcode            
            add-offset-range 0 80 4

            # if mnemonic is bl
            verify-operand bl

            # sort results
            sort

            # mark resultset checkpoint
            checkpoint BLs

            # set first bl to malloc function
            single 0
            goto-ref --code 
            set-name malloc
            set-type 'void *malloc(unsigned int size)'

            # go back to the results from 4 commands ago 
            # (the sort results)
            back-to-checkpoint BLs

            # rename next symbol :)
            single 1
            goto-ref --code
            set-name free
            set-type 'void free(void *block)'
	]
}
```

#### Python script to find a list of symbols

```python
from fa.commands.find_str import find_str 
from fa.commands.set_name import set_name
from fa.commands.unique import unique
from fa import context

def run(**kwargs):
    # throw an exception if not running within ida context
    context.verify_ida('script-name')

    # locate the global string, verify it's unique, and set it's 
    # name within the idb 
    results = set_name(unique(find_str('hello world', null_terminated=True)),
                       'g_hello_world_string')

    if len(results) != 1:
        # no results
        return {}
    
    # return a dictionary of the found symbols
    return {'g_hello_world_string': results[0]}
```

#### Python script to automate SIG files interpreter

```python
TEMPLATE = '''
find-str --or '{unique_string}'
xref
function-start
unique
set-name '{function_name}'
'''

def run(**kwargs):
    results = {}
    interp = kwargs['interpreter']

    for function_name in ['func1', 'func2', 'func3']:
        instructions = TEMPLATE.format(unique_string=function_name, 
                                       function_name=function_name).split('\n')
        
        results[function_name] = interp.find_from_instructions_list(instructions)

    return results
```

#### Python script to dynamically add structs

```python
from fa.commands.set_type import set_type
from fa import types

TEMPLATE = '''
find-str --or '{unique_string}'
xref
'''

def run(**kwargs):
    interp = kwargs['interpreter']

    types.add_const('CONST7', 7)
    types.add_const('CONST8', 8)

    foo_e = types.FaEnum('foo_e')
    foo_e.add_value('val2', 2)
    foo_e.add_value('val1', 1)
    foo_e.update_idb()

    special_struct_t = types.FaStruct('special_struct_t')
    special_struct_t.add_field('member1', 'const char *', size=4)
    special_struct_t.add_field('member2', 'const char *', size=4, offset=0x20)
    special_struct_t.update_idb()

    for function_name in ['unique_magic1', 'unique_magic2']:
        instructions = TEMPLATE.format(unique_string=function_name, 
                                       function_name=function_name).split('\n')
        
        results = interp.find_from_instructions_list(instructions)
        for ea in results:
            # the set_type can receive either a string, FaStruct
            # or FaEnum :-)
            set_type(ea, special_struct_t)

    return {}
```

### Aliases

Each command can be "alias"ed using the file 
found in `fa/commands/alias` or in `<project_root>/alias`

Syntax for each line is as follows: `alias_command = command`
For example:
```
ppc32-verify = keystone-verify-opcodes --bele KS_ARCH_PPC KS_MODE_PPC32
```

Project aliases have higher priority.

### Loaders

Loaders are the entry point into running FA. 
In the future we'll possibly add Ghidra and other tools.

#### IDA

Go to: `File->Script File... (ALT+F7)` and select `ida_loader.py`.

You should get a nice prompt inside the output window welcoming you
into using FA. Also, a quick usage guide will also be printed so you 
don't have to memorize everything.

The prompt should look like:
```
FA> 
FA>     ---------------------------------
FA>     FA Loaded successfully
FA> 
FA>     Quick usage:
FA>     fa_instance.set_project(project_name) # select project name
FA>     print(fa_instance.list_projects()) # prints available projects
FA>     print(fa_instance.find(symbol_name)) # searches for the specific symbol
FA>     fa_instance.get_python_symbols(filename=None) # run project's python scripts (all or single)
FA>     fa_instance.symbols() # searches for the symbols in the current project
FA> 
FA>     HotKeys:
FA>     Ctrl-6: Set current project
FA>     Ctrl-7: Search project symbols
FA>     Ctrl-8: Create temporary signature
FA>     Ctrl-Shift-8: Create temporary signature and open an editor
FA>     Ctrl-9: Find temporary signature
FA>     Ctrl-0: Prompt for adding the temporary signature as permanent
FA>     ---------------------------------
FA> project set: test-project-ida

```

Also, an additional `FA Toolbar` will be added with quick functions that
are also available under the `Edit` menu.

A QuickStart Tip:

`Ctrl+6` to select your project, then `Ctrl+7` to find all its defined symbols.


You can also run IDA in script mode just to extract symbols using:

```sh
ida -S"ida_loader.py <signatures-root> <project-name> --symbols-file=/tmp/symbols.txt" foo.idb
```

#### ELF

In order to use FA on a RAW ELF file, simply use the following command-line:

```sh
python elf_loader.py <elf-file> <signatures_root> <project>
```

### Available commands

#### stop-if-empty

```
usage: stop-if-empty

builtin interpreter command. stops parsing current SIG if 
current resultset is empty 
```

#### add-offset-range
```
usage: add-offset-range [-h] start end step

adds a python-range of offsets, to the current search results

positional arguments:
  start
  end
  step

optional arguments:
  -h, --help  show this help message and exit
```

#### aligned
```
usage: aligned [-h] value

reduces the list to only those aligned to a specific value

positional arguments:
  value

optional arguments:
  -h, --help  show this help message and exit
```

#### back
```
usage: back [-h] amount

goes back in history of search results to those returned from a previous
command

positional arguments:
  amount      amount of command results to go back by

optional arguments:
  -h, --help  show this help message and exit
```

#### back-to-checkpoint
```
usage: back-to-checkpoint [-h] name

goes back in history to the result-set saved by a previous checkpoint

positional arguments:
  name        name of checkpoint in history to go back to

optional arguments:
  -h, --help  show this help message and exit
```

#### checkpoint
```
usage: checkpoint [-h] name

saves current result-set in checkpoint named "name"

positional arguments:
  name        name of checkpoint to use

optional arguments:
  -h, --help  show this help message and exit
```

#### clear
```
usage: clear [-h]

clears the current search results

optional arguments:
  -h, --help  show this help message and exit
```

#### find-bytes
```
usage: find-bytes [-h] [--or] hex_str

expands the search results by the given bytes set

positional arguments:
  hex_str

optional arguments:
  -h, --help  show this help message and exit
  --or
```

#### find-bytes-ida
```
usage: find-bytes-ida [-h] [--or] expression

expands the search results by an ida-bytes expression (Alt+B)

positional arguments:
  expression

optional arguments:
  -h, --help  show this help message and exit
  --or
```

#### find-str
```
usage: find-str [-h] [--or] [--null-terminated] hex_str

expands the search results by the given string

positional arguments:
  hex_str

optional arguments:
  -h, --help         show this help message and exit
  --or
  --null-terminated
```

#### function-end
```
usage: function-end [-h] [--not-unique]

goto function's end

optional arguments:
  -h, --help    show this help message and exit
  --not-unique
```

#### function-lines
```
usage: function-lines [-h]

get all function lines

optional arguments:
  -h, --help  show this help message and exit
```

#### function-start
```
usage: function-start [-h] [--not-unique]

goto function's prolog

optional arguments:
  -h, --help    show this help message and exit
  --not-unique
```

#### goto-ref
```
usage: goto-ref [-h] [--code] [--data]

goto reference

optional arguments:
  -h, --help  show this help message and exit
  --code      include code references
  --data      include data references
```

#### keystone-find-opcodes
```
usage: keystone-find-opcodes [-h] [--bele] [--or] arch mode code

use keystone to search for the supplied opcodes

positional arguments:
  arch        keystone architecture const (evaled)
  mode        keystone mode const (evald)
  code        keystone architecture const (opcodes to compile)

optional arguments:
  -h, --help  show this help message and exit
  --bele      figure out the endianity from IDA instead of explicit mode
  --or        mandatory. expands search results
```

#### keystone-verify-opcodes
```
usage: keystone-verify-opcodes [-h] [--bele] [--until UNTIL] arch mode code

use keystone-engine to verify the given results match the supplied code

positional arguments:
  arch           keystone architecture const (evaled)
  mode           keystone mode const (evald)
  code           keystone architecture const (opcodes to compile)

optional arguments:
  -h, --help     show this help message and exit
  --bele         figure out the endianity from IDA instead of explicit mode
  --until UNTIL  keep going onwards opcode-opcode until verified
```

#### locate
```
usage: locate [-h] name

goto label by name

positional arguments:
  name

optional arguments:
  -h, --help  show this help message and exit
```

#### make-code
```
usage: make-code [-h]

convert into a code block

optional arguments:
  -h, --help  show this help message and exit
```

#### make-function
```
usage: make-function [-h]

convert into a function

optional arguments:
  -h, --help  show this help message and exit
```

#### make-literal
```
usage: make-literal [-h]

convert into a literal

optional arguments:
  -h, --help  show this help message and exit
```

#### max-xrefs
```
usage: max-xrefs [-h]

get the result with most xrefs pointing at it

optional arguments:
  -h, --help  show this help message and exit
```

#### min-xrefs
```
usage: min-xrefs [-h]

get the result with least xrefs pointing at it

optional arguments:
  -h, --help  show this help message and exit
```

#### most-common
```
usage: most-common [-h]

get the result appearing the most in the result-set

optional arguments:
  -h, --help  show this help message and exit
```

#### offset
```
usage: offset [-h] offset

advance by a given offset

positional arguments:
  offset

optional arguments:
  -h, --help  show this help message and exit
```

#### print
```
usage: print [-h]

prints the current search results

optional arguments:
  -h, --help  show this help message and exit
```

#### set-name
```
usage: set-name [-h] name

set name in disassembler

positional arguments:
  name

optional arguments:
  -h, --help  show this help message and exit
```

#### set-type
```
usage: set-type [-h] type_str

sets the type in the disassembler

positional arguments:
  type_str

optional arguments:
  -h, --help  show this help message and exit
```

#### single
```
usage: single [-h] index

peek a single result from the resultset

positional arguments:
  index       result index

optional arguments:
  -h, --help  show this help message and exit
```

#### sort
```
usage: sort [-h]

performs a python-sort on the current result list

optional arguments:
  -h, --help  show this help message and exit
```

#### trace
```
usage: trace [-h]

sets a pdb breakpoint

optional arguments:
  -h, --help  show this help message and exit
```

#### unique
```
usage: unique [-h]

verifies the result-list contains a single value

optional arguments:
  -h, --help  show this help message and exit
```

#### verify-bytes
```
usage: verify-bytes [-h] [--until UNTIL] hex_str

reduces the search list to those matching the given bytes

positional arguments:
  hex_str

optional arguments:
  -h, --help     show this help message and exit
  --until UNTIL  keep advancing by a given size until a match
```

#### verify-name
```
usage: verify-name [-h] name

verifies the given name appears in result set

positional arguments:
  name

optional arguments:
  -h, --help  show this help message and exit
```

#### verify-operand
```
usage: verify-operand [-h] [--op0 OP0] [--op1 OP1] [--op2 OP2] name

verifies the given opcode's operands

positional arguments:
  name

optional arguments:
  -h, --help  show this help message and exit
  --op0 OP0
  --op1 OP1
  --op2 OP2
```

#### verify-ref
```
usage: verify-ref [-h] [--code] [--data] name

verifies a given reference exists to current result set

positional arguments:
  name

optional arguments:
  -h, --help  show this help message and exit
  --code      include code references
  --data      include data references
```

#### verify-str
```
usage: verify-str [-h] [--until UNTIL] [--null-terminated] hex_str

reduces the search list to those matching the given string

positional arguments:
  hex_str

optional arguments:
  -h, --help         show this help message and exit
  --until UNTIL      keep advancing by a given size until a match
  --null-terminated
```

#### xref
```
usage: xref [-h]

goto xrefs pointing at current search results

optional arguments:
  -h, --help  show this help message and exit
```

#### xrefs-to
```
usage: xrefs-to [-h] [--function-start] [--or] [--and] [--name NAME]
                [--bytes BYTES]

search for xrefs pointing at given parameter

optional arguments:
  -h, --help        show this help message and exit
  --function-start  goto function prolog for each xref
  --or              expand the current result set
  --and             reduce the current result set
  --name NAME       parameter as label name
  --bytes BYTES     parameter as bytes
```

### Credits

Icons were downloaded from: [www.flaticon.com](http://www.flaticon.com).

Creators: inipagistudio, becris, freepik

