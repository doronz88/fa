import binascii

from fa.commands import utils


def run(segments, manners, addresses, args, **kwargs):
    magic = binascii.unhexlify(''.join(args.split(' ')))
    return [ea for ea in addresses if utils.read_memory(segments, ea, len(magic)) == magic]
