from argparse import RawTextHelpFormatter
from fa import utils, context

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''goto symbol by name

EXAMPLE:
    0x00000000: main:
    0x00000000:     mov r0, r1
    0x00000004: foo:
    0x00000004:     bx lr

    results = [0, 4]
    -> locate foo
    result = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('locate',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('name')
    return p


@context.ida_context
def locate(name):
    return idc.get_name_ea_simple(name)


def run(segments, args, addresses, interpreter=None, **kwargs):
    address = locate(args.name)
    return [address] if address != idc.BADADDR else []
