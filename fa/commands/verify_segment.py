from argparse import RawTextHelpFormatter

try:
    import idc
except ImportError:
    pass

from fa import utils, context

DESCRIPTION = '''reduce the result-set to those in the given segment name

EXAMPLE:
    .text:0x00000000 01 02 03 04
    .text:0x00000004 30 31 32 33

    .data:0x00000200 01 02 03 04
    .data:0x00000204 30 31 32 33

    results = [0, 0x200]
    -> verify-segment .data
    results = [0x200]
'''


@context.ida_context
def verify_segment(addresses, segment_name):
    for ea in addresses:
        if segment_name == idc.get_segm_name(ea):
            yield ea


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('name', help='segment name')

    p.prog = 'verify-segment'
    p.description = DESCRIPTION
    p.formatter_class = RawTextHelpFormatter
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(verify_segment(addresses, args.name))
