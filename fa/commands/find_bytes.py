from collections import OrderedDict
import binascii

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('--or', action='store_true')
    p.add_argument('--and', action='store_true')
    p.add_argument('hex_str')
    return p


@utils.yield_unique
def find_bytes(hex_str, segments=None):
    needle = bytearray(binascii.unhexlify(''.join(hex_str.split(' '))))
    return utils.find_raw(needle, segments=segments)


def run(segments, args, addresses, **kwargs):
    results = list(find_bytes(args.hex_str, segments=segments))

    retval = set(addresses)
    if getattr(args, 'or'):
        retval.update(results)
    elif getattr(args, 'and'):
        raise ValueError("Use 'verify-bytes' instead of 'find-bytes --and!")
    else:
        raise ValueError("must specify or manner")

    return list(OrderedDict.fromkeys(retval))
