# FA

## What is it?

FA stands for Firmware Analysis.
FA allows one to easily perform code exploration, symbol finding and 
other functionality with ease.

## Requirements

In your IDA's python directory, install:
* [keystone](http://www.keystone-engine.org/download/)
* capstone (`pip install capstone`)


## How its used?

Before using, one must understand the terminology for: 
Projects, SIG files and loaders. 

### Projects

The project is kind of a namespace for different signatures.
For example, either: linux, linux_x86, linux_arm etc... are good 
project names that can be specified if you are working on either 
platforms. 

By dividing the signatures into such projects, Windows symbols for 
example won't be searched for Linux projects, which will result 
in a better directory organization layout, better performance and
less rate for false-positives. 

### SIG format

The SIG format is a core feature of FA regarding symbol searching.

The format is JSON based and used to describe the algorithms used for 
different symbols.
The algorithms is preformed are very linear, performed line by line, 
whereas each line can either extend or reduce the possible search
results.

Each line behaves like a shell command-line that gets the 
previous results as the input and outputs the next results
to the next line.

SIG syntax:
```json
{
    "type": "<function/global/number>",
    "name": "name",
    "instructions" : [
        "command1",
        "command2"
    ]
}
``` 

Available commands:

* `find-bytes --or '<bytes>'`
    * Searches for the specified bytes given as an hex string.
    * For example: 
        * `find-bytes --or '00 01 02 03'`
* `keystone-find-opcodes --or [--bele] <arch> <mode> '<opcodes>'`
    * Searches for opcodes using keystone engine.
    * `bele` flags used to indicate the mode is extracted 
    implicit.
    * For example: 
        * `keystone-find-opcodes --or KS_ARCH_PPC KS_MODE_BIG_ENDIAN|KS_MODE_PPC32 addi %r1, %r1, 4; addi %r1, %r1, 8;`
* `keystone-verify-opcodes [--bele] <arch> <mode> '<opcodes>'`
    * Reduces the search results to only those matching 
    PPC32 opcodes, seperated by `;`.
    * `bele` flags used to indicate the mode is extracted 
    implicit.
    * For example: 
        * `keystone-verify-opcodes [--bele] KS_ARCH_PPC KS_MODE_BIG_ENDIAN|KS_MODE_PPC32 'addi %r1, %r1, 4; addi %r1, %r1, 8;'`    
* `offset <offset>`
    * Adds a constant offset to the search results.
    * For example: `offset 8`, `offset -8`, `offset 0x10`,...
* `add-offset-range <start> <end> <skip>`
    * Adds a range of offsets to the search.
    * For example: 
        * `add-offset-range 0 10 2` will add all offsets in range: `(0, 10, 2)`
* `verify-bytes [--until step] '<bytes>'`
    * Verifies the search results up until now match a const 
    expression given as hex string.
    * For example: 
        * `verify-bytes '11 22 33 44'`
* `xrefs-to [--and/or] [--until step] <--bytes bytes/--name name>`
    * Searches for function references to given expression.
     Equivalent to IDA's `Alt+B`.
    * For example: 
        `xrefs-to --or --bytes '"11 22" 00'`
* `unique`
    * Verifies the number of search results == 1.
* `aligned <immediate>`
    * Verifies the results align a specific value.
    * For example: 
        * `aligned 4`
* `single`
    * Pops only a single result
* `function-start`
    * Goto function's start
* `sort`
    * Sorts the search results from lower to upper.
* `print`
    * Prints the results so far
* `trace`
    * Starts a pdb trace

You might be wondering for what reason is the `add` and/or `verify` 
commands. Their purpose is to remove false-positives and verify 
a given result. 

For example, you can test the following:

```
find-bytes --or '11 22 33 44'
add 20
verify-bytes 'aa bb cc dd'
add -20
```

This will locate all places of `11 22 33 44`, whereas at offset `20`
from them, there exists `aa bb cc dd`. Finally, the cursor will point
back to `11 22 33 44` by reducing the `-20` from the search cursor. 


### Aliases

Each command and mnemonic can be aliases using the file 
found in `fa/commands/alias`.

Syntax for each line is as follows: `alias_command = command`
For example:
```
ppc32-verify = keystone-verify-opcodes --bele KS_ARCH_PPC KS_MODE_PPC32
```

### Loaders

#### IDA

Go to: `File->Script File... (ALT+F7)` and select `ida_loader.py`.

You should get a nice prompt inside the output window welcoming you
into using FA. Also, a quick usage guide will also be printed so you 
don't have to memorize everything.

