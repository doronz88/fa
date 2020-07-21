from argparse import RawTextHelpFormatter

from fa import utils, context

DESCRIPTION = '''expands the result-set with the occurrences of the given bytes
expression in "ida bytes syntax"

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08

    results = []
    -> find-bytes-ida '01 02 03 04'
    result = [0]

    -> find-bytes-ida '05 06 ?? 08'
    results = [0, 4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('find-bytes-ida',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('expression')
    return p


@context.ida_context
def find_bytes_ida(expression, segments=None):
    for address in utils.ida_find_all(expression):
        yield address


def run(segments, args, addresses, interpreter=None, **kwargs):
    return addresses + list(find_bytes_ida(args.expression))
