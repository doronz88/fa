from argparse import RawTextHelpFormatter
from fa import utils, context

try:
    import ida_typeinf
except ImportError:
    pass

DESCRIPTION = '''get function's argument assignment address

EXAMPLE:
    0x00000000: ldr r0, =dest
    0x00000004: ldr r1, =src
    0x00000008: mov r2, #4
    0x0000000c: bl memcpy

    results = [0x0c]
    -> argument 2
    results = [8]  # address of 3rd argument
'''


def get_parser():
    p = utils.ArgumentParserNoExit('argument',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('arg', help='argument number')
    return p


@context.ida_context
def argument(addresses, arg):
    for address in addresses:
        args = ida_typeinf.get_arg_addrs(address)
        if args is None:
            continue
        try:
            yield args[arg]
        except KeyError:
            continue


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(argument(addresses, eval(args.arg)))
