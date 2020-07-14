from argparse import RawTextHelpFormatter

try:
    import idc
except ImportError:
    pass

from fa import utils, context

DESCRIPTION = '''add comment for given addresses

EXAMPLE:
    0x00000200: 01 02 03 04
    0x00000204: 30 31 32 33

    results = [0x200]
    -> make-comment 'bla bla'
    results = [0x200]

    0x00000200: 01 02 03 04 ; bla bla
    0x00000204: 30 31 32 33
'''


@context.ida_context
def make_comment(addresses, comment):
    for ea in addresses:
        idc.set_cmt(ea, comment, 0)
        yield ea


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('comment', help='comment string')

    p.prog = 'make-comment'
    p.description = DESCRIPTION
    p.formatter_class = RawTextHelpFormatter
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(make_comment(addresses, args.comment))
