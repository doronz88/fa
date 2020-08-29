from argparse import RawTextHelpFormatter
from fa import utils


DESCRIPTION = '''adds a python-range to resultset

EXAMPLE:
    result = [0, 0x200]
    -> add-offset-range 0 4 8
    result = [0, 4, 8, 0x200, 0x204, 0x208]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('add-offset-range',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('start')
    p.add_argument('end')
    p.add_argument('step')
    return p


def add_offset_range(addresses, start, end, step):
    for ea in addresses:
        for i in range(start, end, step):
            yield ea + i


def run(segments, args, addresses, interpreter=None, **kwargs):
    gen = add_offset_range(addresses, eval(args.start), eval(args.end),
                           eval(args.step))
    return list(gen)
