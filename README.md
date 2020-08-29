![Python application](https://github.com/doronz88/fa/workflows/Python%20application/badge.svg)

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

## Where to start?

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
If you wish to use a different location, you may create `config.ini`
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
directory and implement the `run(interpreter)` method. 
Also, the project's path is appended to python's `sys.path` 
so you may import your scripts from one another.

To view the list of available commands, [view the list below](#available-commands)

### Examples

#### Finding a global struct

```hjson
{
    name: g_awsome_global,
    instructions: [
            # find the byte sequence '11 22 33 44'
            find-bytes '11 22 33 44'

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
    name: free
    instructions: [
            # search the string "free"
            find-str 'free' --null-terminated

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

#### Finding enums and constants 

```hjson
{
    name: consts-finder
    instructions: [
            # goto printf
            locate printf

            # iterate all its function lines
            function-lines

            # save this result
            store printf-lines
            
            # look for: li r7, ???
            verify-operand li --op0 7

            # extract second operand
            operand 1

            # define the constant
            set-const IMPORTANT_OFFSET

            # load previous results
            load printf-lines
            
            # look for: li r7, ???
            verify-operand li --op0 8

            # get second operand
            operand 1

            # set this enum value
            set-enum important_enum_t some_enum_key
	]
}
```

#### Adding struct member offsets 

```hjson
{
    name: structs-finder
    instructions: [
            # add hard-coded '0' into resultset
            add 0

            # add a first member at offset 0
            set-struct-member struct_t member_at_0 'unsigned int'

            # advance offset by 4
            offset 4            

            # add a second member
            set-struct-member struct_t member_at_4 'const char *'

            # goto function printf
            locate printf

            # iterate its function lines 
            function-lines

            # look for the specific mov opcode (MOV R8, ???)
            verify-operand mov --op0 8
            
            # extract the offset
            operand 1

            # define this offset into the struct
            set-struct-member struct_t member_at_r8_offset 'const char *'
	]
}
```

#### Finding several functions in a row

```hjson
{
    name: cool_functions
    instructions: [
            # find string
            find-str 'init_stuff' --null-terminated

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

            # store resultset in 'BLs'
            store BLs

            # set first bl to malloc function
            single 0
            goto-ref --code 
            set-name malloc
            set-type 'void *malloc(unsigned int size)'

            # go back to the results from 4 commands ago 
            # (the sort results)
            load BLs

            # rename next symbol :)
            single 1
            goto-ref --code
            set-name free
            set-type 'void free(void *block)'
	]
}
```

#### Conditional branches

```hjson
{
    name: set_opcode_const
    instructions: [
        # goto printf function
        locate printf

        # goto 'case_opcode_bl' if current opcode is bl
        if 'verify-operand bl' case_opcode_bl

            # make: #define is_bl (0)
            clear
            add 0
            set-const is_bl
    
            # finish script by jumping to end
            b end

        # mark as 'case_opcode_bl' label
        label case_opcode_bl

            # make: #define is_bl (1)
            clear
            add 1
            set-const is_bl

        # mark script end
        label end
    ]
}
```

#### Python script to find a list of symbols

```python
from fa.commands.find_str import find_str
from fa.commands.set_name import set_name
from fa import context

def run(interpreter):
    # throw an exception if not running within ida context
    context.verify_ida('script-name')

    # locate the global string
    set_name(find_str('hello world', null_terminated=True),
             'g_hello_world', interpreter)
```

#### Python script to automate SIG files interpreter

```python
TEMPLATE = '''
find-str '{unique_string}'
xref
function-start
unique
set-name '{function_name}'
'''

def run(interpreter):
    for function_name in ['func1', 'func2', 'func3']:
        instructions = TEMPLATE.format(unique_string=function_name, 
                                       function_name=function_name).split('\n')
        
        interpreter.find_from_instructions_list(instructions)
```

#### Python script to dynamically add structs

```python
from fa.commands.set_type import set_type
from fa import fa_types

TEMPLATE = '''
find-str '{unique_string}'
xref
'''

def run(interpreter):
    fa_types.add_const('CONST7', 7)
    fa_types.add_const('CONST8', 8)

    foo_e = fa_types.FaEnum('foo_e')
    foo_e.add_value('val2', 2)
    foo_e.add_value('val1', 1)
    foo_e.update_idb()

    special_struct_t = fa_types.FaStruct('special_struct_t')
    special_struct_t.add_field('member1', 'const char *')
    special_struct_t.add_field('member2', 'const char *', offset=0x20)
    special_struct_t.update_idb()

    for function_name in ['unique_magic1', 'unique_magic2']:
        instructions = TEMPLATE.format(unique_string=function_name, 
                                       function_name=function_name).split('\n')
        
        results = interpreter.find_from_instructions_list(instructions)
        for ea in results:
            # the set_type can receive either a string, FaStruct
            # or FaEnum :-)
            set_type(ea, special_struct_t)
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

Please first install the package as follows:

Clone the repository and install locally:

```sh
# clone
git clone git@github.com:doronz88/fa.git
cd fa

# install
python -m pip install -e .
```

#### IDA

Within IDA Python run:

```python
from fa import ida_plugin
ida_plugin.install()
```

You should get a nice prompt inside the output window welcoming you
into using FA. Also, a quick usage guide will also be printed so you 
don't have to memorize everything.

Also, an additional `FA Toolbar` will be added with quick functions that
are also available under the newly created `FA` menu.

![FA Menu](https://github.com/doronz88/fa/raw/master/fa/res/screenshots/menu.png "FA Menu")

A QuickStart Tip:

`Ctrl+6` to select your project, then `Ctrl+7` to find all its defined symbols.


You can also run IDA in script mode just to extract symbols using:

```sh
ida -S"fa/ida_plugin.py <signatures-root> --project-name <project-name> --symbols-file=/tmp/symbols.txt" foo.idb
```


#### ELF

In order to use FA on a RAW ELF file, simply use the following command-line:

```sh
python elf_loader.py <elf-file> <signatures_root> <project>
```

### Available commands

See [commands.md](commands.md)

