import binascii

from fa.commands import utils


def run(segments, manner, manner_args, current_ea, args, **kwargs):
    magic = binascii.unhexlify(''.join(args.split(' ')))
    if utils.read_memory(segments, current_ea, len(magic)) == magic:
        return [current_ea]
    else:
        return []
