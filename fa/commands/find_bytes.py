import binascii

from fa.commands import utils


def run(segments, manners, addresses, args, **kwargs):
    needle = bytearray(binascii.unhexlify(''.join(args.split(' '))))
    results = utils.find_raw(segments, needle)

    retval = set(addresses)
    if 'or' in manners.keys():
        retval.update(results)
    elif 'and' in manners.keys():
        retval.intersection_update(results)
    else:
        raise ValueError("must specify either or/and manner")

    return list(retval)

