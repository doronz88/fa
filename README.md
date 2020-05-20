# FA

## What is it?

FA stands for Firmware Analysis.
FA allows one to easily perform code exploration, symbol finding and 
other functionality with ease.

## Requirements

Supported IDA 7.x.

In your IDA's python directory, install:
* [keystone](http://www.keystone-engine.org/download/)
* capstone (`pip install capstone`)
* click (`pip install click`)
* hjson (`pip install hjson`)

For Testing:
* pytest
* idalink

## How its used?

Before using, one must understand the terminology for: 
Projects, SIG files and Loaders. 

### Projects

The project is kind of a namespace for different signatures.
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

The SIG format is a core feature of FA regarding symbol searching.

The format is Hjson based and is used to describe the algorithms for 
different symbols.
The algorithms are preformed *very linearly*, line by line, 
whereas each line can either extend or reduce the possible search
results.

Each line behaves like a shell command-line that gets the 
previous results as the input and outputs the next results
to the next line.

SIG syntax (single):
```hjson
{
    "type": "<function/global/number>",
    "name": "name",
    "instructions" : [
        # Available commands are listed below
        "command1",
        "command2"
    ]
}
```
 
### Available commands

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

keystone-engine module not installed
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

keystone-engine module not installed
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

#### max-xrefs
```
usage: max-xrefs [-h]

get the result with most xrefs pointing at it

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

#### name-literal
```
usage: name-literal [-h]

convert into a literal

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
usage: single [-h]

reduces the result list into a singleton

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
  --bytes BYTES     parameter as bytesv
```

### Examples

#### Finding a global struct

```hjson
{
    "type": "global",
    "name": "g_awsome_global",
    "instructions": [
            "find-bytes --or '11 22 33 44'",
            "offset 20",
            "verify-bytes 'aa bb cc dd'",
            "offset -20",
            "set-name g_awsome_global"
	]
}
```

This will locate all places of `11 22 33 44`, whereas at offset `20`
from them, there exists `aa bb cc dd`. Finally, the cursor will point
back to `11 22 33 44` by reducing the `-20` from the search cursor - 
then we can name it. 


#### Find function by reference to string

```hjson
{
    "type": "function",
    "name": "free",
    "instructions": [
            "find-str --or 'free' --null-terminated",
            "xref",
            "function-start",
            "max-xrefs",
            "set-type 'void free(void *block)'"
	]
}
```

This will search for the string `free`, then goto to its xref, then to the 
function-prolog, then reduce the search results to the one with the most references 
to it. Finally, it will set its signature.


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

You can also run IDA in script mode just to extract symbols using:

```sh
ida -S"ida_loader.py <project-name> --symbols-file=/tmp/symbols.txt" foo.idb
```

