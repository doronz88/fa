import binascii

from fa.commands import utils


def run(segments, manner, manner_args, addresses, args, **kwargs):
    needle = bytearray(binascii.unhexlify(''.join(args.split(' '))))
    return utils.find_raw(segments, needle)

