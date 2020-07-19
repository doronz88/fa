from argparse import RawTextHelpFormatter
from fa import utils, context

try:
    import idautils
except ImportError:
    pass

DESCRIPTION = '''goto reference

EXAMPLE:
    0x00000000: ldr r0, =0x12345678

    results = [0]
    -> goto-ref --data
    results = [0x12345678]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('goto-ref',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('--code', action='store_true',
                   default=False, help='include code references')
    p.add_argument('--data', action='store_true',
                   default=False, help='include data references')
    return p


@context.ida_context
def goto_ref(addresses, code=False, data=False):
    for address in addresses:
        refs = []
        if code:
            refs += list(idautils.CodeRefsFrom(address, 0))
        if data:
            refs += list(idautils.DataRefsFrom(address))

        if len(refs) == 0:
            continue

        for ref in refs:
            if address + 4 != ref:
                yield ref


def goto_ref_unique(addresses, code=False, data=False):
    for address in goto_ref(addresses, code=code, data=data):
        yield address


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(goto_ref_unique(addresses,
                                code=args.code,
                                data=args.data))
