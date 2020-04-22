import binascii

from fa.commands import utils


def run(segments, manner, manner_args, addresses, args, **kwargs):
    needle = bytearray(binascii.unhexlify(''.join(args.split(' '))))
    results = utils.find_raw(segments, needle)

    retval = set(addresses)
    if manner == 'or':
        retval.update(results)
    elif manner == 'and':
        retval.intersection_update(results)
    else:
        raise ValueError("unsupported manner")

    return list(retval)

