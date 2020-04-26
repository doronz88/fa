from collections import OrderedDict
import binascii

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('--or', action='store_true')
    p.add_argument('--and', action='store_true')
    p.add_argument('hex_str')
    return p


def run(segments, args, addresses, **kwargs):
    needle = bytearray(binascii.unhexlify(''.join(args.hex_str.split(' '))))
    results = utils.find_raw(segments, needle)

    retval = set(addresses)
    if getattr(args, 'or'):
        retval.update(results)
    elif getattr(args, 'and'):
        raise ValueError("Use 'verify-bytes' instead of 'find-bytes --and!")
    else:
        raise ValueError("must specify or manner")

    return list(OrderedDict.fromkeys(retval))
