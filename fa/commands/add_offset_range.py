from collections import OrderedDict

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('start', type=int)
    p.add_argument('end', type=int)
    p.add_argument('step', type=int)
    return p


def run(segments, args, addresses, **kwargs):
    retval = []

    for ea in addresses:
        for i in range(args.start, args.end, args.skip):
            retval.append(ea + i)

    return list(OrderedDict.fromkeys(retval))
