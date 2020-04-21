# FA

## What is it?

FA stands for Firmware Analysis.
FA allows one to easily perform code exploration, symbol finding and 
other functionality with ease.

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

The format describes the algorithms used for different symbols.
The algorithms is preformed is very linear, performed line by line, 
whereas each line can either extend or reduce the possible search
results.

Syntax for each line is as follows:
```
command/manner{manner_args} args
``` 

Available commands:
* `find-bytes`
    * Searches for the specified bytes given as an hex string.
    * For example: `00 01 02 03`
* `powerpc-find-opcodes`
    * Searches for PPC32 opcodes, seperated by `;`.
    * For example: `addi %r1, %r1, 4; addi %r1, %r1, 8;`
* `powerpc-verify-opcodes`
    * Reduces the search results to only those matching 
    PPC32 opcodes, seperated by `;`.
    * For example: `addi %r1, %r1, 4; addi %r1, %r1, 8;`    
* `add`
    * Adds a constant offset to the search results.
    * For example: `8`, `-8`, `0x10`,...
* `add-range`
    * Adds a range of offsets to the search.
    * For example: `0 10 2` will add all offsets in range: `(0, 10, 2)`
* `verify-bytes`
    * Verifies the search results up until now match a const 
    expression given as hex string.
    * For example: `11 22 33 44`
* `xrefs-to`
    * Searches for function references to given expression.
     Equivalent to IDA's `Alt+B`.
    * Supported manners: `and`, `or`. 
    * For example: `"11 22" 00`
* `unique`
    * Verifies the number of search results == 1.
* `aligned`
    * Verifies the results align a specific value.
    * For example: `4`

You might be wondering for what reason is the `add` and/or `verify` 
commands. Their purpose is to remove false-positives and verify 
a given result. 

For example, you can test the following:

```
find-bytes 11 22 33 44
add 20
verify aa bb cc dd
add -20
```

This will locate all places of `11 22 33 44`, whereas at offset `20`
from them, there exists `aa bb cc dd`. Finally, the cursor will point
back to `11 22 33 44` by reducing the `-20` from the search cursor. 

#### Manners

The manners can be specified to change the "*manner*" in the command
will run. For example: `xrefs-to/or` will perform a union,
whereas `xrefs-to/and` will perform an intersection. Not all manners 
require additional arguments, but those can be given in curly braces
(`{}`).

Available manners (`[]` means optional):

* `and`
    * Reduces the results to only those matching
* `or`
    * Extends the results to every matching

### Loaders

#### IDA

Go to: `File->Script File... (ALT+F7)` and select `ida_loader.py`.

You should get a nice prompt inside the output window welcoming you
into using FA. Also, a quick usage guide will also be printed so you 
don't have to memorize everything.

 